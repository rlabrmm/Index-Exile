#!/usr/bin/env python3
"""Recreate installable packages from committed app trees without private inputs."""
import argparse
from pathlib import Path
from build import package, jsave

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build',type=Path,default=Path(__file__).resolve().parents[1]/'build')
    args=parser.parse_args()
    packages=[package(args.build/'apps'/name,args.build/'dist'/(name+'.tgz')) for name in ['Splunk_TA_nix','SA_index_exile_auditd']]
    jsave(args.build/'reports/packages.json',packages)
    print('Rebuilt and byte-verified two local packages; nothing deployed.')
