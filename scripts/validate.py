#!/usr/bin/env python3
"""Validate generated references, corpus coverage and packaging without Splunk."""
import argparse
import json
import re
import tarfile
from pathlib import Path
from build import conf, digest, jsave, tree_digest

def validate(root):
    checks=[]
    def check(name, condition):
        checks.append({'check':name,'status':'passed' if condition else 'failed'})
    modelpath=root/'apps/SA_index_exile_auditd/default/data/models/Linux_Auditd.json'
    model=json.loads(modelpath.read_text())
    objects=model['objects']; names=[o['objectName'] for o in objects]
    check('unique dataset identifiers',len(names)==len(set(names)))
    check('root BaseEvent',objects[0]['parentName']=='BaseEvent')
    check('all children inherit Auditd',all(o['parentName']=='Auditd' for o in objects[1:]))
    ta=root/'apps/Splunk_TA_nix'
    props=conf(ta/'default/props.conf')['auditd']; transforms=conf(ta/'default/transforms.conf')
    check('all REPORT references resolve',all(x.strip() in transforms for x in props['REPORT-ix_auditd'].split(',')))
    field_transforms=[v for k,v in transforms.items() if k.startswith('ix_auditd_field_')]
    check('audit fields use direct named captures without FORMAT',bool(field_transforms) and all(
        'FORMAT' not in v and len(re.compile(v['REGEX']).groupindex)==1 for v in field_transforms))
    check('no local environment files',not any(p.is_file() and ('local' in p.relative_to(root/'apps').parts or p.name=='local.meta') for p in (root/'apps').rglob('*')))
    check('no raw or secret model fields',not any(f['fieldName'] in {'_raw','password','data'} for o in objects for f in o['fields']))
    summary=json.loads((root/'reports/inventory_summary.json').read_text())
    if summary['sample_records']:
        check('all supplied sample headers accounted for',not summary['anomalies'])
    else:
        checks.append({'check':'optional sample validation','status':'not run; samples not supplied'})
    if summary['mapped_csv_rules']:
        check('all mapped CSV titles accounted for',not summary['csv_only_titles'])
    else:
        checks.append({'check':'optional rule/type mapping comparison','status':'not run; mapping not supplied'})
    rules=json.loads((root/'reports/rule_inventory.json').read_text())
    check('all rules have explicit disposition',all(r['status'] in {'pending_human_review','manual_conversion_required'} for r in rules))
    check('candidate hashes match inventory',all(digest((root/'candidates'/(r['id']+'.spl')).read_text().rstrip('\n'))==r['candidate_sha256'] for r in rules if r['candidate_sha256']))
    check('no scheduled rules shipped in model app',not (root/'apps/SA_index_exile_auditd/default/savedsearches.conf').exists())
    check('acceleration disabled',conf(root/'apps/SA_index_exile_auditd/default/datamodels.conf')['Linux_Auditd']['acceleration']=='false')
    contract=json.loads((root/'reports/build_contract.json').read_text())
    check('model contract hash',contract['model_sha256']==digest(modelpath.read_bytes()))
    check('TA contract hash',contract['ta_sha256']==tree_digest(ta))
    for entry in json.loads((root/'reports/packages.json').read_text()):
        p=root/'dist'/entry['file']
        if not p.exists():
            checks.append({'check':'archive '+entry['file'],'status':'not run; recreate with scripts/package.py'})
            continue
        check('archive checksum '+entry['file'],digest(p.read_bytes())==entry['sha256'])
        ok=True
        with tarfile.open(p) as tf:
            members=tf.getmembers()
            actual=set()
            for m in members:
                path=Path(m.name)
                if path.is_absolute() or '..' in path.parts or not m.isfile():
                    ok=False; continue
                local=root/'apps'/path
                actual.add(path.as_posix())
                if not local.is_file() or tf.extractfile(m).read()!=local.read_bytes():ok=False
            appname=entry['file'].removesuffix('.tgz')
            expected={p.relative_to(root/'apps').as_posix() for p in (root/'apps'/appname).rglob('*') if p.is_file()}
            ok=ok and expected==actual
        check('safe archive matches complete app tree '+entry['file'],ok)
    report={'scope':'offline configuration and archive checks; not Splunk execution','checks':checks,
            'passed':sum(c['status']=='passed' for c in checks),'failed':sum(c['status']=='failed' for c in checks),
            'runtime':'not executed; no live evidence collected','appinspect':'not run','performance':'unverified'}
    jsave(root/'reports/validation.json',report)
    return report

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('--build',type=Path,required=True)
    a=p.parse_args(); result=validate(a.build)
    print(json.dumps(result,indent=2))
    raise SystemExit(bool(result['failed']))
