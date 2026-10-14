#!/usr/bin/env python3
"""Compare sanitized inventories from two offline builds; never carry approvals forward."""
import argparse
import json
from pathlib import Path
from build import jsave

def delta(before,after):
    return {'added':sorted(after.keys()-before.keys()),'removed':sorted(before.keys()-after.keys()),
            'changed':sorted(k for k in before.keys()&after.keys() if before[k]!=after[k])}

def compare(old,new):
    def load(base, name, key):
        return {r[key]:r for r in json.loads((base/'reports'/name).read_text())}
    result={}
    for filename,key in [('rule_inventory.json','id'),('type_inventory.json','type'),('input_manifest.json','path'),('field_inventory.json','dataset')]:
        before,after=load(old,filename,key),load(new,filename,key)
        if filename=='rule_inventory.json':
            keys=['app','title','search_sha256','candidate_sha256','status','disabled','schedule','earliest','latest']
            if all('dependency_context_sha256' in r for r in before.values()):keys.append('dependency_context_sha256')
            before={k:{f:v.get(f) for f in keys} for k,v in before.items()}
            after={k:{f:v.get(f) for f in keys} for k,v in after.items()}
        elif filename=='type_inventory.json':
            # Optional sample absence is an evidence change, not a dataset deletion.
            before={k:v['dataset'] for k,v in before.items()};after={k:v['dataset'] for k,v in after.items()}
        elif filename=='input_manifest.json':
            before={k:v for k,v in before.items() if '/' in k}
            after={k:v for k,v in after.items() if '/' in k}
        result[filename]=delta(before,after)
    filename='source_config_inventory.json'
    if (old/'reports'/filename).exists() and (new/'reports'/filename).exists():
        result[filename]=delta(load(old,filename,'id'),load(new,filename,'id'))
    else:
        result[filename]={'status':'prior configuration detail unavailable; use file hashes and rule changes'}
    result['approvals']='All approvals must be revalidated against current source, candidate, model and runtime evidence.'
    return result

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--old',type=Path,required=True); p.add_argument('--new',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args(); jsave(a.output,compare(a.old,a.new))
