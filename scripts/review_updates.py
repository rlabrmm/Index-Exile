#!/usr/bin/env python3
"""Discover changes in complete updated app directories without CSVs or all other apps."""
import argparse
import json
from pathlib import Path
from build import APPS, CORE, EXTRA, audit_types, config_inventory, inventory, jsave, source_manifest
from compare_updates import delta

def review(baseline, updates):
    supplied=[app for app in APPS if (updates/app).is_dir()]
    if not supplied:
        raise ValueError('No recognized app directory; safely unpack packages under their app IDs first.')
    for app in supplied:
        marker='app.conf' if app=='Splunk_TA_nix' else 'savedsearches.conf'
        if not (updates/app/'default'/marker).is_file():
            raise ValueError(f'{app}: provide the complete extracted app, not isolated replacement files.')
    reports=baseline/'reports'
    old_files={r['path']:r for r in json.loads((reports/'input_manifest.json').read_text()) if r['path'].split('/')[0] in supplied}
    new_files={r['path']:r for r in source_manifest(updates)}
    old_rules={r['id']:r for r in json.loads((reports/'rule_inventory.json').read_text()) if r['app'] in supplied}
    _,_,_,rules,types,summary=inventory(updates)
    new_rules={r['id']:r for r in rules}
    rule_changes=delta({k:v['search_sha256'] for k,v in old_rules.items()},{k:v['search_sha256'] for k,v in new_rules.items()})
    old_config_path=reports/'source_config_inventory.json'
    new_config={r['id']:r for r in config_inventory(updates)}
    if old_config_path.exists():
        old_config={r['id']:r for r in json.loads(old_config_path.read_text()) if r['app'] in supplied}
        changes=delta(old_config,new_config)
        config_changes={kind:[(new_config if kind!='removed' else old_config)[k] for k in ids] for kind,ids in changes.items()}
    else:
        config_changes={'status':'baseline lacks setting hashes; changed files and rule hashes are still compared'}
    previous_types={r['type'] for r in json.loads((reports/'type_inventory.json').read_text())}
    return {'scope':'Only supplied complete applications are compared; omitted applications remain unchanged.',
        'supplied_apps':supplied,'unchanged_apps_not_supplied':[a for a in APPS if a not in supplied],
        'files':delta(old_files,new_files),'rules':rule_changes,
        'rule_details':{kind:[{'id':rid,'app':(old_rules if kind=='removed' else new_rules)[rid]['app'],
            'title':(old_rules if kind=='removed' else new_rules)[rid]['title']} for rid in ids] for kind,ids in rule_changes.items()},
        'configuration':config_changes,'new_types_requiring_review':sorted(types-previous_types),
        'types_referenced_by_update':sorted(types),'dataset_retirement':'Never inferred from missing samples or an omitted application.',
        'sample_validation':summary['sample_validation'],
        'approval':'Review configuration/macro changes even when rule text is unchanged; obtain fresh approval before replacing searches.'}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--baseline',type=Path,required=True)
    p.add_argument('--updates',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args(); result=review(a.baseline,a.updates); jsave(a.output,result)
    print('Reviewed '+', '.join(result['supplied_apps'])+'; no CSV required and no live changes made.')
