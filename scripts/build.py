#!/usr/bin/env python3
"""Reproducible, offline auditd model/TA builder. Never deploys or enables rules."""
from __future__ import annotations
import argparse
import csv
import gzip
import hashlib
import io
import json
import re
import shutil
import tarfile
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HEADER = r'(?:^|\s)type=(?P<audit_type>[A-Z][A-Z0-9_]*(?:\[\d+\])?)\s+msg=audit\((?P<audit_event_id>[^)\r\n]+):(?P<audit_id>\d+)\)(?:\s*:)?(?=\s|$)'
CORE = set('type audit_type audit_id audit_event_id node host source sourcetype dest comm exe syscall arch uid auid euid gid egid suid sgid fsuid fsgid pid ppid ses success exit key argc proctitle execve_command name nametype cwd op res unit acct addr hostname terminal tty subj user a0 a1 a2 a3'.split())
EXTRA = set('item items inode dev mode rdev ouid ogid obj cap_fp cap_fi cap_fe cap_fver cap_frootid grantors direction kind fp spid laddr lport rport cipher ksize suid fam saddr fd0 fd1 oauid ocomm opid oses capability permissive scontext tcontext tclass nargs id old_pa old_pe old_pi old_pp pa pe pi pp fe fi frootid fver qbytes code compat ip sig state major minor fd flags entries family table old new oflag resolve old_prom prom old_enabled new_enabled old_log_passwd new_log_passwd default_context selected_context'.split())
NUMERIC = set('argc pid ppid item items spid opid fd0 fd1 lport rport ksize nargs qbytes sig major minor entries'.split())
EXCLUDED = set('_raw password data msg punct eventtype tag parser splunk_server splunk_server_group'.split())
BUILTIN = {'_time', 'host', 'source', 'sourcetype'}
APPS = ('Splunk_TA_nix', 'DA-ESS-ContentUpdate', 'SplunkEnterpriseSecuritySuite')

def digest(data):
    return hashlib.sha256(data if isinstance(data, bytes) else data.encode()).hexdigest()

def tree_digest(directory):
    """Bind review to exact relative paths and bytes, independent of timestamps."""
    entries=[p.relative_to(directory).as_posix()+'\0'+digest(p.read_bytes()) for p in sorted(directory.rglob('*')) if p.is_file()]
    return digest('\n'.join(entries))

def write(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding='utf-8', newline='\n')

def jsave(path, obj):
    write(path, json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + '\n')

def conf(path):
    """Parse stanzas and continued assignments without interpolation."""
    result, stanza, pending = {}, None, ''
    if not Path(path).exists():
        return result
    for line in Path(path).read_text(encoding='utf-8-sig').splitlines():
        if pending:
            line = pending + line.lstrip()
        if line.rstrip().endswith('\\'):
            pending = line.rstrip()[:-1] + ' '
            continue
        pending = ''
        s = line.strip()
        if not s or s.startswith(('#', ';')):
            continue
        if s.startswith('[') and s.endswith(']'):
            stanza = s[1:-1]
            result.setdefault(stanza, {})
        elif '=' in s and stanza is not None:
            k, v = s.split('=', 1)
            result[stanza][k.strip()] = v.strip()
    if pending:
        raise ValueError(f'Unterminated continuation in {path.name}')
    return result

def effective(app, name):
    out = conf(app / 'default' / name)
    for k, v in conf(app / 'local' / name).items():
        out.setdefault(k, {}).update(v)
    return out

def csv_rows(path):
    csv.field_size_limit(20_000_000)
    with Path(path).open(encoding='utf-8-sig', newline='') as f:
        return list(csv.DictReader(f))

def field_names(raw):
    # Only allowlisted audit fields survive this discovery step.
    return {x.replace('-', '_') for x in re.findall(r'(?<![\w-])([A-Za-z][\w-]*)=', raw)}

def dataset_name(t):
    return re.sub(r'[^A-Za-z0-9_]', '_', t).strip('_')

def split_pipes(s):
    """Split only unquoted, top-level pipes; preserve regexes and subsearches."""
    parts, start, quote, escape, depth = [], 0, None, False, 0
    for i, c in enumerate(s):
        if escape:
            escape = False
            continue
        if c == '\\':
            escape = True
            continue
        if quote:
            if c == quote:
                quote = None
        elif c in '\"\'`':
            quote = c
        elif c == '[':
            depth += 1
        elif c == ']':
            depth -= 1
        elif c == '|' and depth == 0:
            parts.append(s[start:i].strip())
            start = i + 1
    if quote or depth:
        raise ValueError('Unbalanced SPL quotes/subsearches')
    return parts + [s[start:].strip()]

def outside_strings(s, fn):
    return ''.join(x if x.startswith('"') else fn(x) for x in re.split(r'("(?:\\.|[^"\\])*")', s))

def predicate_fields(s):
    """Validate the complete supported search predicate, rejecting free raw terms."""
    tokens=re.findall(r'"(?:\\.|[^"\\])*"|!=|=|[(),]|[^\s(),=!<>]+',s)
    compact=''.join(tokens)
    if compact!=re.sub(r'\s+','',outside_strings(s,lambda x:x)):
        # Whitespace inside quoted values must be retained in the comparison.
        expected=outside_strings(s,lambda x:re.sub(r'\s+','',x))
        if compact!=expected:
            raise ValueError('Unsupported predicate token')
    pos,fields=0,set()
    def atom():
        nonlocal pos
        if pos<len(tokens) and tokens[pos].upper()=='NOT':
            pos+=1; atom(); return
        if pos<len(tokens) and tokens[pos]=='(':
            pos+=1; expr()
            if pos>=len(tokens) or tokens[pos]!=')': raise ValueError('Unbalanced predicate')
            pos+=1; return
        if pos>=len(tokens) or not re.fullmatch(r'[A-Za-z_]\w*',tokens[pos]):
            raise ValueError('Expected a field comparison; raw terms are unsupported')
        fields.add(tokens[pos]); pos+=1
        if pos>=len(tokens): raise ValueError('Missing comparison')
        op=tokens[pos].upper(); pos+=1
        if op=='IN':
            if pos>=len(tokens) or tokens[pos]!='(': raise ValueError('Invalid IN list')
            pos+=1; value()
            while pos<len(tokens) and tokens[pos]==',':
                pos+=1; value()
            if pos>=len(tokens) or tokens[pos]!=')': raise ValueError('Invalid IN list')
            pos+=1
        elif op in {'=','!='}: value()
        else: raise ValueError('Unsupported comparison')
    def value():
        nonlocal pos
        if pos>=len(tokens) or tokens[pos] in {'(',')',',','=','!='} or tokens[pos].upper() in {'AND','OR','NOT'} or any(c in tokens[pos] for c in '`[]|'):
            raise ValueError('Unsupported predicate value')
        pos+=1
    def expr():
        nonlocal pos
        atom()
        while pos<len(tokens) and tokens[pos]!=')':
            if tokens[pos].upper() in {'AND','OR'}: pos+=1
            atom()
    if tokens:
        expr()
    if pos!=len(tokens): raise ValueError('Trailing predicate syntax')
    return fields

def direct_candidate(search, model, scope):
    """Fail closed: only source-filter + rename + standard stats + unchanged tail."""
    try:
        parts = split_pipes(search)
    except ValueError as e:
        return None, str(e)
    if not parts[0].startswith('`linux_auditd`'):
        return None, 'Source is not exclusively the linux_auditd macro; cross-source/manual review required.'
    pred = parts[0][len('`linux_auditd`'):].strip()
    if '`' in pred or '$' in search:
        return None, 'Parameterized search or additional source macro requires explicit review.'
    aliases, ix = {}, 1
    while ix < len(parts) and parts[ix].lower().startswith('rename '):
        m = re.fullmatch(r'rename\s+(\w+)\s+as\s+(\w+)', parts[ix], re.I)
        if not m:
            return None, 'Unsupported rename expression.'
        aliases[m[2]] = aliases.get(m[1], m[1])
        ix += 1
    if ix >= len(parts):
        return None, 'Missing supported aggregation.'
    m = re.fullmatch(r'stats\s+(count\s+min\(_time\)\s+as\s+firstTime\s+max\(_time\)\s+as\s+lastTime|max\(_time\)\s+as\s+lastTime)\s+by\s+([\w\s,]+)', parts[ix], re.I)
    if not m:
        return None, 'Pre-aggregation eval/rex/bin, joins, correlation, or unsupported aggregation requires manual conversion.'
    groups = [x for x in re.split(r'[\s,]+', m[2].strip()) if x]
    try:
        fields = predicate_fields(pred)
    except ValueError as e:
        return None, str(e)
    if not fields <= CORE | {'index'} or not {aliases.get(g, g) for g in groups} <= CORE:
        return None, 'Unknown or case-sensitive field requires extraction review: ' + ', '.join(sorted(fields - CORE - {'index'}))
    # Detect free-text search terms after removing literals, field comparisons and operators.
    stripped = re.sub(r'"(?:\\.|[^"\\])*"', 'VALUE', pred)
    if re.search(r'(?<![\w])(?:TERM|CASE)\s*\(', stripped):
        return None, 'Raw term matching cannot be translated to model fields.'
    def qualify(x):
        return re.sub(r'\b([A-Za-z_]\w*)(?=\s*(?:=|!=|\bIN\s*\())', lambda a: a[1] if a[1] == 'index' else 'Auditd.' + a[1], x)
    qualified = outside_strings(pred, qualify)
    aggs = m[1]
    by = ' '.join('Auditd.' + aliases.get(g, g) for g in groups)
    query = f'| tstats summariesonly=false allow_old_summaries=false {aggs} FROM datamodel={model}.Auditd WHERE ({scope})'
    if pred:
        query += f' AND ({qualified})'
    query += ' BY ' + by
    query += '\n| rename ' + ' '.join(f'Auditd.{aliases.get(g, g)} AS {g}' for g in groups)
    if parts[ix+1:]:
        query += '\n| ' + '\n| '.join(parts[ix+1:])
    return query, 'Candidate only: requires paired runtime result equivalence and human approval.'

def audit_types(search):
    result=set(re.findall(r'(?<!\w)(?:audit_type|type)\s*={1,2}\s*"?([A-Z][A-Z_0-9]*(?:\[\d+\])?)(?=["\s),|]|$)',search))
    for values in re.findall(r'\b(?:audit_type|type)\s+IN\s*\(([^)]+)\)',search,re.I):
        result.update(v.strip().strip('"') for v in values.split(',') if re.fullmatch(r'[A-Z][A-Z_0-9]*(?:\[\d+\])?',v.strip().strip('"')))
    return result

def macro_context(search, macrosets):
    """Trace dependency definitions without executing SPL or assuming macro visibility."""
    text=[search]; seen=set(); pending=re.findall(r'`([\w]+)(?:\([^`]*\))?`',search)
    while pending:
        name=pending.pop()
        if name in seen:continue
        seen.add(name)
        for macros in macrosets.values():
            for key,settings in macros.items():
                if key==name or key.startswith(name+'('):
                    definition=settings.get('definition','')
                    text.append(definition)
                    pending.extend(re.findall(r'`([\w]+)(?:\([^`]*\))?`',definition))
    return '\n'.join(text), sorted(seen)

def config_inventory(inputs):
    """Keep setting hashes rather than potentially confidential configuration values."""
    records=[]
    relevant={(r['app'],r['title']) for r in inventory(inputs)[3]}
    for app in APPS:
        for p in sorted((inputs/app).rglob('*.conf')):
            if not p.is_file():continue
            rel_parts=p.relative_to(inputs/app).parts
            if 'local' in rel_parts or p.name=='local.meta':continue
            if app!='Splunk_TA_nix' and p.name not in {'app.conf','savedsearches.conf','macros.conf','props.conf','transforms.conf','eventtypes.conf','tags.conf','datamodels.conf'}:
                continue  # Other content still has whole-file change detection through the manifest.
            rel=p.relative_to(inputs).as_posix()
            for stanza,settings in conf(p).items():
                if p.name=='savedsearches.conf' and (app,stanza) not in relevant:continue
                for key,value in settings.items():
                    if re.search(r'password|passwd|secret|token|authorization|credential',key,re.I):
                        continue  # Do not publish low-entropy credential hashes.
                    records.append({'id':digest(rel+'\n'+stanza+'\n'+key),'app':app,'file':rel,
                                    'stanza':stanza,'key':key,'value_sha256':digest(value)})
    return records

def source_manifest(inputs):
    result=[]
    for app in APPS:
        for p in sorted((inputs/app).rglob('*')):
            if not p.is_file():continue
            rel=p.relative_to(inputs/app)
            if 'local' in rel.parts or p.name=='local.meta':continue
            result.append({'path':(Path(app)/rel).as_posix(),'sha256':digest(p.read_bytes())})
    return result

def inventory(inputs, samples_path=None, type_map_path=None):
    # Development evidence is opt-in; filenames in the input directory are not prerequisites.
    samples = csv_rows(samples_path) if samples_path else []
    mapped = csv_rows(type_map_path) if type_map_path else []
    types, raw_fields, anomalies = Counter(), defaultdict(set), []
    for row in samples:
        raw = row.get('_raw', '')
        m = re.search(HEADER, raw)
        if not m:
            anomalies.append('Sample without supported audit header')
            continue
        t = m['audit_type']
        types[t] += 1
        raw_fields[t].update(field_names(raw))
        if row.get('type') and t != row['type']:
            anomalies.append(f'Raw/exported type mismatch for {t}')
    rules, counts = [], {}
    apps = ['DA-ESS-ContentUpdate', 'SplunkEnterpriseSecuritySuite']
    macrosets = {app: effective(inputs/app, 'macros.conf') for app in apps}
    mapped_titles = {r['title']: r for r in mapped}
    for app in apps:
        searches = effective(inputs/app, 'savedsearches.conf')
        counts[app] = len(searches)
        for title, settings in searches.items():
            s = settings.get('search', '')
            context,dependencies=macro_context(s,macrosets)
            if not s or not (re.search(r'auditd|linux_audit|\btype\s*=\s*(?:SYSCALL|EXECVE|PROCTITLE)', context, re.I) or title in mapped_titles):
                continue
            # Ignore only descriptions: selection is based on executable search, not labels.
            mapped_row = mapped_titles.get(title)
            explicit = audit_types(context)
            hints = set(re.findall(r'[A-Z][A-Z_0-9]+', mapped_row['type_used'])) if mapped_row else set()
            inferred = ({'PROCTITLE'} if 'proctitle' in context else set()) | ({'EXECVE'} if 'execve_command' in context else set())
            missing = []
            for dep in dependencies:
                if not any(dep in macrosets[a] or any(k.startswith(dep+'(') for k in macrosets[a]) for a in apps):
                    missing.append(dep)
            rules.append({'id': digest(app+'\n'+title)[:16], 'app': app, 'title': title,
                          'search': s, 'search_sha256': digest(s), 'explicit_types': sorted(explicit),
                          'dependency_context_sha256':digest(context),
                          'hint_types': sorted(hints | inferred), 'macro_dependencies': dependencies,
                          'missing_macros': missing, 'csv_present': mapped_row is not None,
                          'csv_search_matches': re.sub(r'\s+', ' ', s).strip() == re.sub(r'\s+', ' ', mapped_row['search']).strip() if mapped_row else None,
                          'disabled': settings.get('disabled', 'inherited'),
                          'schedule': settings.get('cron_schedule', 'inherited'),
                          'earliest': settings.get('dispatch.earliest_time', 'inherited'),
                          'latest': settings.get('dispatch.latest_time', 'inherited')})
    # Keep CSV-only rules visible, never assume the CSV is authoritative over installed app exports.
    present = {r['title'] for r in rules}
    missing_titles = sorted(set(mapped_titles) - present)
    alltypes = set(types)
    for r in rules:
        alltypes.update(r['explicit_types'])
        alltypes.update(r['hint_types'])
    # TA eventtype predicates are additional evidence, not proof of raw field extraction.
    ta_types=set()
    for settings in effective(inputs/'Splunk_TA_nix','eventtypes.conf').values():
        s=settings.get('search','')
        if re.search(r'auditd|linux_audit',s,re.I):ta_types.update(audit_types(s))
    alltypes.update(ta_types)
    return samples, types, raw_fields, rules, alltypes, {'sample_records':len(samples),'mapped_csv_rules':len(mapped),'source_stanzas':counts,'csv_only_titles':missing_titles,'anomalies':anomalies,
        'sample_validation':'supplied_optional_evidence' if samples_path else 'not run; optional samples not supplied',
        'type_map_validation':'supplied_optional_evidence' if type_map_path else 'not run; optional mapping not supplied',
        'ta_predicate_types':sorted(ta_types)}

def field(f):
    return {'fieldName': f, 'displayName': f, 'type': 'number' if f in NUMERIC else 'string',
            'fieldSearch': '', 'required': False, 'multivalue': False, 'hidden': False,
            'comment': {'description': 'Audit record field; absent values remain absent. IDs and mixed name/numeric values remain strings.'}}

def object_def(name, parent, constraint, fields):
    return {'objectName': name, 'displayName': name, 'parentName': parent,
            'fields': [field(f) for f in sorted(fields)], 'calculations': [],
            'constraints': [{'search':constraint}], 'children': []}

def generate_model(policy, types, raw_fields):
    allowed = CORE | EXTRA
    extras = policy.get('additional_fields', {})
    for t, fields in extras.items():
        if set(fields) & EXCLUDED or any(not re.fullmatch(r'[A-Za-z_]\w*', f) for f in fields):
            raise ValueError('Unsafe additional model field')
        allowed.update(fields)
    objects = [object_def('Auditd','BaseEvent','(`ix_auditd_indexes`) sourcetype=auditd tag=ix_auditd',CORE - BUILTIN)]
    # Host/source/sourcetype are inherited BaseEvent fields; do not redeclare them.
    for t in sorted(types):
        name = dataset_name(t)
        children_fields = ((raw_fields.get(t,set()) & allowed) | set(extras.get(t,[]))) - CORE - BUILTIN
        objects.append(object_def(name,'Auditd',f'audit_type="{t}" tag=ix_auditd_{name.lower()}',children_fields))
    types_spl = ', '.join('"'+t+'"' for t in sorted(types))
    objects.append(object_def('Unmapped','Auditd',f'NOT audit_type IN ({types_spl})',[]))
    return {'modelName':policy['model'],'displayName':'Linux Auditd','description':'Linux auditd records; type-specific datasets. No implicit cross-record merge.','editable':True,'objects':objects}

def transform(name, regex, fmt=None):
    s = f'[{name}]\nREGEX = {regex}\n'
    if fmt:
        s += f'FORMAT = {fmt}\n'
    return s + 'MV_ADD = false\n\n'

def generate_ta(policy, model):
    allfields = set().union(*(set(f['fieldName'] for f in o['fields']) for o in model['objects']))
    transforms = transform('ix_auditd_header', HEADER)
    reports = ['ix_auditd_header']
    # The raw timestamp plus serial is stronger than serial alone for correlation.
    transforms += transform('ix_auditd_event_key', r'(?:^|\s)type=[A-Z][A-Z0-9_]*(?:\[\d+\])?\s+msg=audit\((?P<audit_event_key>[^)\r\n]+)\)(?:\s*:)?(?=\s|$)')
    reports += ['ix_auditd_event_key']
    rawfields = allfields - {'audit_type','audit_id','audit_event_id','audit_event_key','dest','execve_command','proctitle'} - BUILTIN
    rawfields |= {'argc'} | {f'a{i}' for i in range(policy['max_execve_args'])}
    for f in sorted(rawfields):
        rawkey = re.escape(f).replace('_','[-_]')
        # Boundaries support nested msg='key=value ...' without capturing the wrapper.
        # Search-time FORMAT cannot concatenate $1$2$3. Each quoting form
        # extracts the field directly through one named capture instead.
        for suffix, value in (
            ('double', rf'"(?P<{f}>[^"\r\n]*)"'),
            ('single', rf"'(?P<{f}>[^'\r\n]*)'"),
            ('bare', rf'''(?P<{f}>[^\s'"\r\n]+)'''),
        ):
            regex = r'''(?:^|[\s'])''' + rawkey + '=' + value
            name = 'ix_auditd_field_' + f + '_' + suffix
            transforms += transform(name, regex)
            reports.append(name)
    transforms += transform('ix_auditd_proctitle', r'(?:^|\s)proctitle=(?P<ix_proctitle_raw>[^\r\n]+?)\s*$')
    reports += ['ix_auditd_proctitle']
    for i in range(policy['max_execve_args']):
        name = 'ix_auditd_arg_' + str(i)
        # Retain quotes internally so a quoted all-hex argument stays literal text.
        transforms += transform(name, rf'(?:^|\s)a{i}=(?P<ix_arg{i}>"[^"\r\n]*"|[^\s\r\n]+)')
        reports.append(name)
    props = '[auditd]\n# Search-time only. Parsing, timestamps and collection remain unchanged.\n'
    props += '# Bounded audit field extraction; review other consumers before replacing automatic KV extraction.\nKV_MODE = none\n'
    props += 'REPORT-ix_auditd = ' + ', '.join(reports) + '\n'
    props += 'EVAL-dest = host\n'
    # No calculated field depends on another calculated field.
    native = 'match(audit_event_id,"^[0-9]+(?:[.][0-9]+)?$")'
    props += f'EVAL-proctitle = if(isnotnull(ix_proctitle_raw),if({native} AND match(ix_proctitle_raw,"^(?:[0-9A-Fa-f]{{2}})+$"),urldecode(replace(replace(ix_proctitle_raw,"([0-9A-Fa-f]{{2}})","%\\\\1"),"%00","%20")),replace(ix_proctitle_raw,"^\\\"|\\\"$","")),proctitle)\n'
    args = []
    for i in range(policy['max_execve_args']):
        v = f'ix_arg{i}'
        args.append(f'if({native} AND match({v},"^(?:[0-9A-Fa-f]{{2}})+$"),urldecode(replace({v},"([0-9A-Fa-f]{{2}})","%\\\\1")),replace({v},"^\\\"|\\\"$",""))')
    # Avoid silently emitting a truncated command or treating fragmented args as complete.
    complete = ' AND '.join(f'(tonumber(argc)<={i} OR isnotnull(ix_arg{i}))' for i in range(policy['max_execve_args']))
    props += f'EVAL-execve_command = if(isnotnull(execve_command),execve_command,if(audit_type="EXECVE" AND tonumber(argc)>0 AND tonumber(argc)<={policy["max_execve_args"]} AND {complete},mvjoin(mvappend(' + ','.join(args) + ')," "),null()))\n'
    events = '[ix_auditd]\nsearch = sourcetype=auditd audit_type=* audit_event_key=*\n\n'
    tags = '[eventtype=ix_auditd]\nix_auditd = enabled\n\n'
    for o in model['objects'][1:]:
        if o['objectName'] == 'Unmapped':
            continue
        name = 'ix_auditd_' + o['objectName'].lower()
        # The literal type value comes from the constrained model object.
        type_filter = o['constraints'][0]['search'].split(' tag=')[0]
        events += f'[{name}]\nsearch = sourcetype=auditd audit_event_key=* {type_filter}\n\n'
        tags += f'[eventtype={name}]\n{name} = enabled\n\n'
    return {'props.conf':props,'transforms.conf':transforms,'eventtypes.conf':events,'tags.conf':tags}

def package(directory, target):
    target.parent.mkdir(parents=True,exist_ok=True)
    with target.open('wb') as dest, gzip.GzipFile(filename='',mode='wb',fileobj=dest,mtime=0) as gz, tarfile.open(fileobj=gz,mode='w') as tar:
        for p in sorted(directory.rglob('*')):
            if not p.is_file():
                continue
            data=p.read_bytes()
            info=tarfile.TarInfo(directory.name+'/'+p.relative_to(directory).as_posix())
            info.size=len(data); info.mtime=0; info.mode=0o755 if p.suffix=='.sh' else 0o644
            tar.addfile(info,io.BytesIO(data))
    with tarfile.open(target) as tar:
        for member in tar.getmembers():
            rel=Path(member.name).relative_to(directory.name)
            assert not rel.is_absolute() and '..' not in rel.parts
            assert tar.extractfile(member).read() == (directory/rel).read_bytes()
    return {'file':target.name,'sha256':digest(target.read_bytes())}

def build(inputs, output, *, previous=None, samples_path=None, type_map_path=None):
    if output.exists() and any(output.iterdir()):
        raise ValueError('Choose a fresh output directory. Existing builds are immutable review baselines.')
    policy=json.loads((ROOT/'config/model_policy.json').read_text())
    if policy['model']!='Linux_Auditd' or policy['root']!='Auditd' or policy['sourcetypes']!=['auditd']:
        raise ValueError('Model identity and sourcetype changes require an explicit generator migration.')
    if not re.fullmatch(r'index=[A-Za-z0-9_*:-]+',policy['index_constraint']):
        raise ValueError('Index constraint must be one reviewed index selector.')
    if not isinstance(policy['max_execve_args'],int) or not 1<=policy['max_execve_args']<=128:
        raise ValueError('max_execve_args must be between 1 and 128.')
    for app in APPS:
        required='app.conf' if app=='Splunk_TA_nix' else 'savedsearches.conf'
        if not (inputs/app/'default'/required).is_file():
            raise ValueError(f'Missing application source: {app}/default/{required}. Use review_updates.py for a partial application update.')
    samples,counts,raw_fields,rules,types,summary=inventory(inputs,samples_path,type_map_path)
    catalog=json.loads((ROOT/'config/auditd_catalog.json').read_text())['types']
    retained={r['type']:set(r['fields']) for r in catalog}
    if previous:
        prior_types=json.loads((previous/'reports/type_inventory.json').read_text())
        prior_model=json.loads((previous/'apps/SA_index_exile_auditd/default/data/models/Linux_Auditd.json').read_text())
        prior_fields={o['objectName']:{f['fieldName'] for f in o['fields']} for o in prior_model['objects']}
        for item in prior_types:
            retained.setdefault(item['type'],set()).update(prior_fields[item['dataset']])
    current_types=set(types)
    types.update(retained)
    model_fields={t:set(raw_fields.get(t,[])) | retained.get(t,set()) for t in types}
    for t,fields in retained.items():
        policy['additional_fields'].setdefault(t,[])
        policy['additional_fields'][t]=sorted(set(policy['additional_fields'][t]) | fields)
    types.update(policy['additional_types'])
    if any(not re.fullmatch(r'[A-Z][A-Z0-9_]*(?:\[\d+\])?',t) for t in types):
        raise ValueError('Invalid audit type')
    if len({dataset_name(t) for t in types})!=len(types):
        raise ValueError('Dataset name collision')
    model=generate_model(policy,types,model_fields)
    # Correlation keys are explicitly modeled; no raw payload is persisted.
    model['objects'][0]['fields'].append(field('audit_event_key'))
    ta=generate_ta(policy,model)
    app=output/'apps/SA_index_exile_auditd'
    jsave(app/'default/data/models/Linux_Auditd.json',model)
    write(app/'default/app.conf',f'[install]\nis_configured = 1\n[ui]\nis_visible = 0\n[launcher]\nauthor = Index Exile\nversion = {policy["version"]}\ndescription = Linux auditd data model\n[package]\nid = SA_index_exile_auditd\n')
    write(app/'default/datamodels.conf','[Linux_Auditd]\nacceleration = false\nacceleration.earliest_time = -7d\n')
    write(app/'default/macros.conf',f'[ix_auditd_indexes]\ndefinition = {policy["index_constraint"]}\niseval = 0\n')
    write(app/'metadata/default.meta','[]\naccess = read : [ * ], write : [ admin ]\nexport = system\n')
    baseline=inputs/'Splunk_TA_nix'
    patched=output/'apps/Splunk_TA_nix'
    # Rebuild in a new/clean output tree. Never merge stale files into a release.
    if patched.exists():
        raise ValueError('Output TA exists; use a fresh --output directory to prevent stale-file packaging.')
    for src in sorted(baseline.rglob('*')):
        rel=src.relative_to(baseline)
        if src.is_symlink():
            raise ValueError('Symlinks are not allowed in TA inputs')
        if not src.is_file() or 'local' in rel.parts or src.name in {'local.meta','splunkbase.manifest'} or '__pycache__' in rel.parts:
            continue
        dest=patched/rel
        dest.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(src,dest)
    for name,addition in ta.items():
        p=patched/'default'/name
        prior=p.read_text(encoding='utf-8-sig') if p.exists() else ''
        added=conf_text(addition)
        existing=conf(p)
        # Existing stanza names require a reviewed merge on updates, not duplicate stanzas.
        if set(existing)&set(added):
            raise ValueError(f'Existing stanza collision in {name}: review upstream changes before rebuilding')
        write(p,prior.rstrip()+'\n\n# Index Exile auditd extension\n'+addition)
        write(output/'ta-overlay/Splunk_TA_nix/default'/name,addition)
    appconf=patched/'default/app.conf'
    text=appconf.read_text(encoding='utf-8-sig')
    text=re.sub(r'(?m)^install_source_checksum\s*=.*\n?', '', text)
    write(appconf,text)
    write(patched/'INDEX_EXILE_BUILD.txt',f'Index Exile extension {policy["version"]}\nBase vendor version retained; this is a locally modified build.\nExcluded: local/, metadata/local.meta and vendor package checksum manifest.\nNo collector or ingestion behavior changed.\n')
    safe_rules=[]
    for r in rules:
        macro=effective(inputs/r['app'],'macros.conf').get('linux_auditd',{})
        # Model scope must not broaden the source macro; only simple scopes are convertible.
        scope=macro.get('definition')
        if scope is None:
            scope=effective(inputs/'DA-ESS-ContentUpdate','macros.conf').get('linux_auditd',{}).get('definition','')
        sm=re.fullmatch(r'index=([\w*:-]+)\s+sourcetype="?auditd"?',scope)
        candidate,note=direct_candidate(r['search'],policy['model'],'index='+sm[1]) if sm else (None,'Source macro is not a simple reviewed auditd scope.')
        if sm and policy['index_constraint'] not in {'index=*','index='+sm[1]}:
            candidate=None; note='Model index scope may exclude source-macro events; align scope and rebuild.'
        if r['missing_macros']:
            candidate=None; note='Missing macro dependencies: '+', '.join(r['missing_macros'])
        rec={k:v for k,v in r.items() if k!='search'}
        rec.update({'status':'pending_human_review' if candidate else 'manual_conversion_required','reason':note,
                    'candidate_sha256':digest(candidate) if candidate else None})
        if candidate:
            write(output/'candidates'/(r['id']+'.spl'),candidate+'\n')
        safe_rules.append(rec)
    jsave(output/'reports/rule_inventory.json',safe_rules)
    summary.update({'observed_types':len(counts),'model_type_datasets':len(types),'root_and_unmapped':2,
                    'selected_rules':len(rules),'candidate_count':sum(r['status']=='pending_human_review' for r in safe_rules),
                    'manual_rule_count':sum(r['status']=='manual_conversion_required' for r in safe_rules),
                    'live_validation':'not executed; no live evidence collected', 'server_release':'unknown'})
    jsave(output/'reports/inventory_summary.json',summary)
    jsave(output/'reports/type_inventory.json',[{'type':t,'dataset':dataset_name(t),'sample_count':counts.get(t,0),
       'evidence':'observed_raw' if t in counts else ('source_predicate_unvalidated' if t in current_types else 'retained_catalog_unvalidated_current_input'),
       'retained_fields':sorted(retained.get(t,[])),
       'raw_field_names':sorted(raw_fields.get(t,[])),
       'rule_ids':[r['id'] for r in rules if t in r['explicit_types'] or t in r['hint_types']],
       'anomaly':t in {'SYSCSYSCALL','UNKNOWN[1333]'}} for t in sorted(types)])
    jsave(output/'reports/field_inventory.json',[{'dataset':o['objectName'],'fields':o['fields']} for o in model['objects']])
    jsave(output/'reports/input_manifest.json',source_manifest(inputs))
    jsave(output/'reports/source_config_inventory.json',config_inventory(inputs))
    # Evidence hashes do not create runtime/approval dependencies on development files.
    jsave(output/'reports/optional_evidence.json',[{'kind':kind,'sha256':digest(p.read_bytes())}
          for kind,p in [('samples',samples_path),('type_mapping',type_map_path)] if p])
    jsave(output/'reports/packages.json',[package(p,output/'dist'/(p.name+'.tgz')) for p in [patched,app]])
    jsave(output/'reports/build_contract.json',{'model_sha256':digest((app/'default/data/models/Linux_Auditd.json').read_bytes()),'ta_sha256':tree_digest(patched)})
    if previous:
        from compare_updates import compare
        jsave(output/'reports/update_diff.json',compare(previous,output))
    print(json.dumps(summary,indent=2))

def conf_text(text):
    return set(re.findall(r'(?m)^\[([^\r\n]+)\]',text))

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--inputs',type=Path,default=ROOT.parent/'artifacts')
    p.add_argument('--output',type=Path,default=ROOT/'build')
    p.add_argument('--previous-build',type=Path,help='Retain prior schema and automatically report changes')
    p.add_argument('--samples',type=Path,help='Optional development CSV containing _raw; never required')
    p.add_argument('--type-map',type=Path,help='Optional development rule/type mapping CSV; never required')
    args=p.parse_args()
    build(args.inputs.resolve(),args.output.resolve(),previous=args.previous_build,
          samples_path=args.samples,type_map_path=args.type_map)

if __name__=='__main__':
    main()
