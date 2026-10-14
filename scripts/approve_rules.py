#!/usr/bin/env python3
"""Generate search-only local patches after explicit hash-bound human approval."""
import argparse
import json
from pathlib import Path
from build import digest, effective, write, tree_digest

def approve(build_dir, inputs, approval_file, output):
    inventory = {r['id']:r for r in json.loads((build_dir/'reports/rule_inventory.json').read_text())}
    approval = json.loads(approval_file.read_text(encoding='utf-8'))
    if not approval.get('reviewer') or not approval.get('approved_at'):
        raise ValueError('Named human reviewer and approval timestamp are required.')
    model = build_dir/'apps/SA_index_exile_auditd/default/data/models/Linux_Auditd.json'
    if approval.get('model_sha256') != digest(model.read_bytes()):
        raise ValueError('Model changed or approval is not bound to this model.')
    if approval.get('ta_sha256') != tree_digest(build_dir/'apps/Splunk_TA_nix'):
        raise ValueError('TA changed or approval is not bound to this TA.')
    # App/macro/config drift invalidates review; optional development evidence is not required.
    manifest=json.loads((build_dir/'reports/input_manifest.json').read_text())
    if not manifest:
        raise ValueError('Missing input provenance')
    for entry in manifest:
        rel=Path(entry['path'])
        # Backward compatibility with initial development manifests that listed CSV exports.
        if len(rel.parts)==1 and rel.name in {'all_auditd_types.csv','auditd-types-sample_based_on_esu.csv'}:
            continue
        if rel.is_absolute() or '..' in rel.parts:
            raise ValueError('Unsafe input manifest path')
        current=inputs/rel
        if not current.is_file() or digest(current.read_bytes())!=entry['sha256']:
            raise ValueError('Input/dependency changed; rebuild and obtain fresh approval.')
    patches = {}
    approved_ids = set()
    for a in approval.get('rules', []):
        if a.get('approved') is not True:
            continue
        rid = a['id']
        if rid in approved_ids:
            raise ValueError('Duplicate approval ID')
        approved_ids.add(rid)
        r = inventory[rid]
        if r['status'] != 'pending_human_review':
            raise ValueError('Manual conversion has no validated generated candidate.')
        candidate = (build_dir/'candidates'/(rid+'.spl')).read_text().rstrip('\n')
        source = effective(inputs/r['app'], 'savedsearches.conf')[r['title']]['search']
        for label, actual in [('source',digest(source)), ('candidate',digest(candidate))]:
            recorded = r['search_sha256'] if label=='source' else r['candidate_sha256']
            if a.get(label+'_sha256') != actual or actual != recorded:
                raise ValueError(f'{label} changed; a fresh review is required.')
        evidence = a.get('validation', {})
        required = ['server_version','app_context','earliest','latest','raw_result_signature','candidate_result_signature','evidence_reference']
        if any(not evidence.get(k) for k in required) or evidence.get('equivalent') is not True:
            raise ValueError('Equivalent runtime result evidence is required before creating a replacement patch.')
        if evidence['raw_result_signature'] != evidence['candidate_result_signature']:
            raise ValueError('Result signatures differ.')
        # Existing risk/notable/schedule settings stay in their original app.
        line = candidate.replace('\n', ' ')
        patches.setdefault(r['app'], []).append(f'[{r["title"]}]\nsearch = {line}\n')
    if not approved_ids:
        raise ValueError('No explicitly approved rules; no patches were generated.')
    if output.exists() and any(output.iterdir()):
        raise ValueError('Choose an empty patch output directory.')
    for app, stanzas in patches.items():
        write(output/app/'local/savedsearches.conf.patch', '# Human-reviewed search-only merge patch. Do not overwrite existing local configuration.\n\n'+'\n'.join(stanzas))
    return len(approved_ids)

if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build',type=Path,required=True)
    p.add_argument('--inputs',type=Path,required=True)
    p.add_argument('--approval',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    print(f'Generated patches for {approve(a.build,a.inputs,a.approval,a.output)} approved rules; nothing deployed.')
