"""Local tests exercise emitted regex/config; they are not a Splunk SPL emulator."""
import csv
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from build import conf, direct_candidate, split_pipes, generate_model, generate_ta, HEADER, digest, tree_digest, field_names
from approve_rules import approve

def extract(raw, transforms):
    fields={}
    for name, settings in transforms.items():
        if not name.startswith('ix_auditd_'):
            continue
        m=re.search(settings['REGEX'],raw)
        if not m:
            continue
        if 'FORMAT' in settings:
            key,value=settings['FORMAT'].split('::',1)
            # Search-time FORMAT substitutes a single capture, not concatenation.
            capture=re.fullmatch(r'\$(\d+)',value)
            if capture:
                value=m[int(capture[1])] or ''
            if value:
                fields.setdefault(key,value)
        else:
            for k,v in m.groupdict().items():
                if v is not None:
                    fields.setdefault(k,v)
    return fields

class PipelineTests(unittest.TestCase):
    def test_search_time_format_does_not_concatenate(self):
        settings={'ix_auditd_legacy':{'REGEX':r'uid=(\w+)', 'FORMAT':'uid::$1$2$3'}}
        self.assertEqual(extract('uid=root',settings)['uid'],'$1$2$3')
        settings['ix_auditd_legacy']['FORMAT']='uid::$1'
        self.assertEqual(extract('uid=root',settings)['uid'],'root')

    def test_generated_fields_use_named_captures(self):
        for name,settings in self.transforms.items():
            if name.startswith('ix_auditd_field_'):
                self.assertNotIn('FORMAT',settings,name)
                self.assertEqual(len(re.compile(settings['REGEX']).groupindex),1,name)

    def test_quoted_bare_empty_and_literal_dollar_values(self):
        for value,expected in [('root','root'), ('"test user"','test user'),
                               ("'test user'",'test user'), ('""',''), ("''",''),
                               ('"$HOME"','$HOME'), ('"$1$2$3"','$1$2$3')]:
            raw=f'type=USER_AUTH msg=audit(1700000000:1): acct={value} uid=0'
            self.assertEqual(extract(raw,self.transforms)['acct'],expected)
        self.assertNotIn('acct',extract('type=USER_AUTH msg=audit(1700000000:1): uid=0',self.transforms))

    @classmethod
    def setUpClass(cls):
        cls.build=ROOT/'build'
        cls.ta=cls.build/'apps/Splunk_TA_nix'
        cls.transforms=conf(cls.ta/'default/transforms.conf')
        cls.model=json.loads((cls.build/'apps/SA_index_exile_auditd/default/data/models/Linux_Auditd.json').read_text())

    def test_real_corpus_headers_and_classification(self):
        source=ROOT.parent/'artifacts/all_auditd_types.csv'
        if not source.exists():
            self.skipTest('Private source corpus is not present in this checkout')
        with source.open(encoding='utf-8-sig',newline='') as f:
            rows=list(csv.DictReader(f))
        known={o['displayName'] for o in self.model['objects']}
        for row in rows:
            actual=extract(row['_raw'],self.transforms)
            self.assertEqual(actual.get('audit_type'),row['type'],row['type'])
            self.assertTrue(actual.get('audit_id'),row['type'])
            self.assertTrue(actual.get('audit_event_key'),row['type'])
            self.assertIn(re.sub(r'[^A-Za-z0-9_]','_',row['type']).strip('_'),known)
        self.assertGreater(len(rows),0)

    def test_nested_auth_exact_values(self):
        raw="type=USER_AUTH msg=audit(1700000000.123:42): pid=22 uid=0 auid=1001 ses=7 msg='op=PAM:authentication acct=\"test user\" exe=\"/usr/bin/su\" hostname=? addr=2001:db8::1 terminal=pts/2 res=failed'"
        f=extract(raw,self.transforms)
        for k,v in {'audit_type':'USER_AUTH','audit_id':'42','audit_event_key':'1700000000.123:42','pid':'22','acct':'test user','addr':'2001:db8::1','res':'failed','op':'PAM:authentication'}.items():
            self.assertEqual(f[k],v)

    def test_real_corpus_modeled_raw_field_coverage(self):
        source=ROOT.parent/'artifacts/all_auditd_types.csv'
        if not source.exists():self.skipTest('Private source corpus is unavailable')
        modeled={f['fieldName'] for o in self.model['objects'] for f in o['fields']}
        with source.open(encoding='utf-8-sig',newline='') as f:
            for row in csv.DictReader(f):
                extracted=extract(row['_raw'],self.transforms)
                expected=(field_names(row['_raw']) & modeled)-{'proctitle'}
                self.assertFalse(expected-set(extracted),row['type']+': missing '+','.join(sorted(expected-set(extracted))))

    def test_interpreted_and_epoch_headers(self):
        for timestamp in ['1700000000.123','10/13/2026 14:35:32.657']:
            for sep in [': ', ' : ', '  ']:
                for newline in ['', '\n', '\r\n']:
                    raw=f'type=DAEMON_CONFIG msg=audit({timestamp}:3861){sep}op=reconfigure state=changed'+newline
                    f=extract(raw,self.transforms)
                    self.assertEqual(f['audit_type'],'DAEMON_CONFIG')
                    self.assertEqual(f['audit_id'],'3861')

    def test_hyphen_and_underscore_field_names(self):
        f=extract('type=CONFIG_CHANGE msg=audit(1700000000:9): old-enabled=1 new-enabled=0 old-log_passwd=0 new-log_passwd=1',self.transforms)
        self.assertEqual(f['old_enabled'],'1'); self.assertEqual(f['new_enabled'],'0')
        self.assertEqual(f['old_log_passwd'],'0'); self.assertEqual(f['new_log_passwd'],'1')
        f=extract('type=USER_ROLE_CHANGE msg=audit(1700000000:9): default-context=test_context selected-context=new_context',self.transforms)
        self.assertEqual(f['default_context'],'test_context'); self.assertEqual(f['selected_context'],'new_context')

    def test_unknown_anomalous_and_future_types(self):
        for typ in ['UNKNOWN[1333]','SYSCSYSCALL','FUTURE_TYPE']:
            f=extract(f'type={typ} msg=audit(1700000000.0:1): op=test',self.transforms)
            self.assertEqual(f['audit_type'],typ)
            self.assertEqual(f['type'],typ)

    def test_negative_headers(self):
        for raw in ['type=SERVICE_STOP unit=auditd', 'ordinary systemd message', 'type=SYSCALL msg=audit(broken)', 'type= msg=audit(1700000000:1):']:
            self.assertNotIn('audit_type',extract(raw,self.transforms))

    def test_proctitle_unquoted_full_text(self):
        raw='type=PROCTITLE msg=audit(1700000000.0:1): proctitle=/usr/bin/example --flag a b '
        self.assertEqual(extract(raw,self.transforms)['ix_proctitle_raw'],'/usr/bin/example --flag a b')
        props=conf(self.ta/'default/props.conf')['auditd']
        self.assertIn('"%00","%20"',props['EVAL-proctitle'])
        self.assertNotIn('replace(ix_proctitle_raw,"00"',props['EVAL-proctitle'])

    def test_execve_order_quote_and_fragment_handling(self):
        raw='type=EXECVE msg=audit(1700000000.0:1): argc=12 a0="echo" a1="deadbeef" a2=6869 a3="" a10="ten" a11="eleven"'
        f=extract(raw,self.transforms)
        self.assertEqual(f['ix_arg1'],'"deadbeef"')
        self.assertEqual(f['ix_arg2'],'6869')
        self.assertEqual(f['ix_arg3'],'""')
        props=conf(self.ta/'default/props.conf')['auditd']['EVAL-execve_command']
        tail=props[props.index('mvjoin(mvappend('):]
        self.assertLess(tail.index('ix_arg2,'),tail.index('ix_arg10,'))
        self.assertIn('tonumber(argc)<=64',props)
        self.assertIn('tonumber(argc)<=4 OR isnotnull(ix_arg4)',props)
        fragment=extract('type=EXECVE msg=audit(1700000000.0:1): argc=1 a0_len=20 a0[0]="abc"',self.transforms)
        self.assertNotIn('ix_arg0',fragment)

    def test_model_and_references(self):
        objects=self.model['objects']; names={o['objectName'] for o in objects}
        self.assertEqual(len(names),len(objects))
        self.assertEqual(objects[0]['parentName'],'BaseEvent')
        for o in objects[1:]:
            self.assertIn(o['parentName'],names)
        allfields={f['fieldName'] for o in objects for f in o['fields']}
        self.assertFalse(allfields & {'_raw','password','data','msg'})
        self.assertIn('audit_event_key',allfields)
        props=conf(self.ta/'default/props.conf')['auditd']
        for ref in props['REPORT-ix_auditd'].split(', '):
            self.assertIn(ref,self.transforms)
        events=conf(self.ta/'default/eventtypes.conf'); tags=conf(self.ta/'default/tags.conf')
        for key,settings in tags.items():
            if key.startswith('eventtype=ix_auditd'):
                self.assertIn(key.split('=',1)[1],events)
                self.assertTrue(all(v=='enabled' for v in settings.values()))

    def test_direct_conversion_preserves_predicate_strings(self):
        s='`linux_auditd` proctitle="*of=*" OR proctitle="*if=/dev/zero*" | rename host as dest | stats count min(_time) as firstTime max(_time) as lastTime BY proctitle dest | `filter`'
        q,reason=direct_candidate(s,'Linux_Auditd','index=linux')
        self.assertIsNotNone(q,reason)
        self.assertIn('Auditd.proctitle="*of=*" OR Auditd.proctitle="*if=/dev/zero*"',q)
        self.assertIn('BY Auditd.proctitle Auditd.host',q)
        self.assertTrue(q.endswith('`filter`'))
        self.assertNotIn('summariesonly=true',q)
        self.assertNotIn('fillnull_value',q)

    def test_unsupported_conversions_fail_closed(self):
        searches=[
            '`linux_auditd` | rex "x=(?<x>.*)" | stats count by x',
            'type=SYSCALL | join host [search `sysmon`]',
            '`linux_auditd` | stats count by host | search dest="$dest$"',
            '`linux_auditd` UID=daemon | stats count min(_time) as firstTime max(_time) as lastTime by host',
            '`linux_auditd` raw_keyword | stats count min(_time) as firstTime max(_time) as lastTime by host',
            '`linux_auditd` type>SYSCALL | stats count min(_time) as firstTime max(_time) as lastTime by host',
        ]
        for s in searches:
            self.assertIsNone(direct_candidate(s,'Linux_Auditd','index=linux')[0])

    def test_pipe_split_preserves_regex_and_subsearch(self):
        s='`linux_auditd` | rex "a|b" | join x [search y | stats count]'
        self.assertEqual(len(split_pipes(s)),3)

    def test_no_live_or_scheduled_rule_changes(self):
        self.assertFalse(list(self.build.glob('**/local/*')))
        self.assertFalse((self.build/'apps/SA_index_exile_auditd/default/savedsearches.conf').exists())
        self.assertEqual(conf(self.build/'apps/SA_index_exile_auditd/default/datamodels.conf')['Linux_Auditd']['acceleration'],'false')

    def test_approval_rejects_unapproved_or_stale(self):
        private=ROOT/'private'; private.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=private) as d:
            d=Path(d); p=d/'approval.json'
            p.write_text('{}')
            with self.assertRaises(ValueError):
                approve(self.build,ROOT.parent/'artifacts',p,d/'patches')
            self.assertFalse((d/'patches').exists())

    def test_approval_creates_only_search_patch_and_rejects_drift(self):
        # Entire fixture is synthetic. It never approves a real detection.
        private=ROOT/'private'; private.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=private) as temp:
            d=Path(temp); b=d/'build'; inputs=d/'inputs'
            source='`linux_auditd` | stats max(_time) as lastTime by host'
            candidate='| tstats max(_time) as lastTime FROM datamodel=Linux_Auditd.Auditd BY Auditd.host'
            model=b/'apps/SA_index_exile_auditd/default/data/models/Linux_Auditd.json'
            model.parent.mkdir(parents=True); model.write_text('{}')
            ta=b/'apps/Splunk_TA_nix'; ta.mkdir(); (ta/'test.txt').write_text('synthetic')
            src=inputs/'TestApp/default/savedsearches.conf'; src.parent.mkdir(parents=True)
            src.write_text('[Synthetic]\nsearch = '+source+'\naction.risk = 1\n')
            (b/'reports').mkdir(); (b/'candidates').mkdir()
            (b/'candidates/test.spl').write_text(candidate+'\n')
            record={'id':'test','app':'TestApp','title':'Synthetic','status':'pending_human_review','search_sha256':digest(source),'candidate_sha256':digest(candidate)}
            (b/'reports/rule_inventory.json').write_text(json.dumps([record]))
            (b/'reports/input_manifest.json').write_text(json.dumps([
                {'path':'TestApp/default/savedsearches.conf','sha256':digest(src.read_bytes())},
                {'path':'all_auditd_types.csv','sha256':'unavailable-development-evidence'},
                {'path':'auditd-types-sample_based_on_esu.csv','sha256':'unavailable-development-evidence'}]))
            evidence={k:'synthetic' for k in ['server_version','app_context','earliest','latest','raw_result_signature','candidate_result_signature','evidence_reference']}
            evidence['equivalent']=True
            approval={'reviewer':'synthetic test only','approved_at':'synthetic test only','model_sha256':digest(model.read_bytes()),'ta_sha256':tree_digest(ta),'rules':[{'id':'test','approved':True,'source_sha256':digest(source),'candidate_sha256':digest(candidate),'validation':evidence}]}
            af=d/'approval.json'; af.write_text(json.dumps(approval))
            self.assertEqual(approve(b,inputs,af,d/'patches'),1)
            patch=(d/'patches/TestApp/local/savedsearches.conf.patch').read_text()
            self.assertIn('[Synthetic]',patch); self.assertIn('search = ',patch)
            self.assertNotIn('action.risk',patch)
            self.assertIn('action.risk = 1',src.read_text())
            (ta/'test.txt').write_text('changed')
            with self.assertRaises(ValueError):approve(b,inputs,af,d/'changed-patches')
            (ta/'test.txt').write_text('synthetic')
            src.write_text(src.read_text()+'description = changed dependency\n')
            with self.assertRaises(ValueError):approve(b,inputs,af,d/'changed-patches')

    def test_preserves_unrelated_vendor_files(self):
        baseline=ROOT.parent/'artifacts/Splunk_TA_nix'
        if not baseline.exists():self.skipTest('Private baseline is not available')
        changed={'INDEX_EXILE_BUILD.txt','default/app.conf','default/props.conf','default/transforms.conf','default/eventtypes.conf','default/tags.conf'}
        for p in self.ta.rglob('*'):
            if p.is_file() and p.relative_to(self.ta).as_posix() not in changed:
                self.assertEqual(p.read_bytes(),(baseline/p.relative_to(self.ta)).read_bytes(),p.name)

if __name__=='__main__':
    unittest.main()
