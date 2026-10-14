"""Update workflows must work without either original development CSV."""
import contextlib
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from build import APPS, audit_types, build, inventory, write
from review_updates import review
from validate import validate

class UpdateTests(unittest.TestCase):
    def setUp(self):
        (ROOT/'private').mkdir(exist_ok=True)
        self.temp=tempfile.TemporaryDirectory(dir=ROOT/'private')
        self.base=Path(self.temp.name)
        self.inputs=self.base/'inputs'
        for app in APPS:
            write(self.inputs/app/'default/app.conf',f'[package]\nid = {app}\n[launcher]\nversion = 1.0.0\n')
        self.search='`linux_auditd` type=SYSCALL | stats count min(_time) as firstTime max(_time) as lastTime by host'
        write(self.inputs/'DA-ESS-ContentUpdate/default/macros.conf','[linux_auditd]\ndefinition = index=linux sourcetype=auditd\n')
        write(self.inputs/'DA-ESS-ContentUpdate/default/savedsearches.conf','[Keep]\nsearch = '+self.search+'\n[Remove]\nsearch = '+self.search+'\n')
        write(self.inputs/'SplunkEnterpriseSecuritySuite/default/savedsearches.conf','[Unchanged ES]\nsearch = '+self.search+'\n')

    def tearDown(self):
        self.temp.cleanup()

    def run_build(self,output,**kwargs):
        with contextlib.redirect_stdout(io.StringIO()):build(self.inputs,output,**kwargs)

    def test_build_without_csv_retains_schema_and_reports_unverified_samples(self):
        output=self.base/'build';self.run_build(output)
        self.assertFalse(list(self.inputs.glob('*.csv')))
        summary=json.loads((output/'reports/inventory_summary.json').read_text())
        self.assertEqual(summary['sample_records'],0)
        self.assertIn('not run',summary['sample_validation'])
        expected={r['type'] for r in json.loads((ROOT/'config/auditd_catalog.json').read_text())['types']}
        actual={r['type'] for r in json.loads((output/'reports/type_inventory.json').read_text())}
        self.assertTrue(expected<=actual)
        manifest=json.loads((output/'reports/input_manifest.json').read_text())
        self.assertTrue(all('/' in r['path'] for r in manifest))
        result=validate(output)
        self.assertEqual(result['failed'],0)
        self.assertTrue(any(c['check']=='optional sample validation' and c['status'].startswith('not run') for c in result['checks']))

    def test_escu_only_detects_added_removed_modified_rules_and_macro_changes(self):
        output=self.base/'build';self.run_build(output)
        updates=self.base/'updates'
        app=updates/'DA-ESS-ContentUpdate'
        shutil.copytree(self.inputs/'DA-ESS-ContentUpdate',app)
        write(app/'default/savedsearches.conf','[Keep]\nsearch = '+self.search.replace('SYSCALL','NEW_UPDATE_TYPE')+'\n[New]\nsearch = `wrapper` | stats max(_time) as lastTime by host\n')
        write(app/'default/macros.conf','[linux_auditd]\ndefinition = index=linux sourcetype=auditd\n[wrapper]\ndefinition = `linux_auditd` type=MACRO_ONLY_TYPE\n')
        result=review(output,updates)
        self.assertEqual(result['supplied_apps'],['DA-ESS-ContentUpdate'])
        self.assertEqual(len(result['rules']['added']),1)
        self.assertEqual(len(result['rules']['removed']),1)
        self.assertEqual(len(result['rules']['changed']),1)
        self.assertIn('MACRO_ONLY_TYPE',result['new_types_requiring_review'])
        self.assertIn('NEW_UPDATE_TYPE',result['new_types_requiring_review'])
        self.assertTrue(any(r['key']=='definition' for r in result['configuration']['added']))
        self.assertTrue(all(not p.startswith('SplunkEnterpriseSecuritySuite/') for p in result['files']['removed']))

    def test_ta_only_update_discovers_new_predicates_without_rule_apps(self):
        output=self.base/'build';self.run_build(output)
        updates=self.base/'updates'
        shutil.copytree(self.inputs/'Splunk_TA_nix',updates/'Splunk_TA_nix')
        write(updates/'Splunk_TA_nix/default/eventtypes.conf','[new_audit]\nsearch = sourcetype=auditd type=NEW_TA_TYPE\n')
        result=review(output,updates)
        self.assertIn('NEW_TA_TYPE',result['new_types_requiring_review'])
        self.assertEqual(result['rules'],{'added':[],'removed':[],'changed':[]})

    def test_previous_schema_retained_and_diff_written_automatically(self):
        first=self.base/'first';self.run_build(first)
        modelpath=first/'apps/SA_index_exile_auditd/default/data/models/Linux_Auditd.json'
        model=json.loads(modelpath.read_text())
        obj=next(o for o in model['objects'] if o['objectName']=='SYSCALL')
        obj['fields'].append({'fieldName':'previous_custom_field','type':'string'})
        modelpath.write_text(json.dumps(model))
        second=self.base/'second';self.run_build(second,previous=first)
        current=json.loads((second/'apps/SA_index_exile_auditd/default/data/models/Linux_Auditd.json').read_text())
        self.assertIn('previous_custom_field',{f['fieldName'] for o in current['objects'] for f in o['fields']})
        self.assertTrue((second/'reports/update_diff.json').is_file())

    def test_csvs_are_opt_in_and_never_approval_dependencies(self):
        write(self.inputs/'all_auditd_types.csv','malformed unused development file')
        write(self.inputs/'auditd-types-sample_based_on_esu.csv','malformed unused development file')
        self.assertEqual(inventory(self.inputs)[-1]['sample_records'],0)
        sample=self.base/'optional-example.csv'
        write(sample,'_raw\n"type=OPTIONAL_TYPE msg=audit(1700000000:1): op=test"\n')
        output=self.base/'build';self.run_build(output,samples_path=sample)
        self.assertEqual(json.loads((output/'reports/inventory_summary.json').read_text())['sample_records'],1)
        self.assertFalse(any(r['path'].endswith('optional-example.csv') for r in json.loads((output/'reports/input_manifest.json').read_text())))

    def test_literal_type_discovery_rejects_wildcards(self):
        self.assertEqual(audit_types('type=USER_* OR type IN ("NEW_TYPE", "USER_*", "UNKNOWN[1333]")'),{'NEW_TYPE','UNKNOWN[1333]'})

    def test_missing_app_is_not_silently_built_as_empty(self):
        incomplete=self.base/'incomplete';incomplete.mkdir()
        with self.assertRaises(ValueError):build(incomplete,self.base/'output')

if __name__=='__main__':unittest.main()
