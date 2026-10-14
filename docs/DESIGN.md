# Design and evidence

## Scope and evidence

The original CSVs were development-only evidence and are not update prerequisites. Current builds derive requirements from application searches, referenced macros and TA predicates, retaining `config/auditd_catalog.json` and the prior accepted model. Optional samples/mappings are read only through explicit flags. Their absence is recorded as unverified sample evidence and does not shrink the schema. Application manifests bind approvals to actual software/configuration; optional development files are not runtime dependencies. Initial sample observations below are historical; the current build report records which optional evidence was actually supplied.

The supplied CSV contains 60 searches and the sample export contains 39 records. Read `_raw` through a CSV parser; exported enriched columns are observations of another extraction pipeline, not proof of this TA's behavior. The source baseline is Splunk_TA_nix 9.0.0 and ESCU 6.8.0. Full per-file hashes and source app identities are in `build/reports/input_manifest.json`.

The builder reads executable `search` assignments from both ES applications, with `local` over `default` precedence. It inventories all relevant search bodies and compares the CSV's names and search text against them. Descriptions and drilldown labels do not become executable rules. Macro dependencies and CSV discrepancies are recorded per rule; source app settings take precedence over the CSV.

Three architecture options were considered: a record model with type children (selected), a search-time transaction model, and a separate pre-correlated summary index. The record model fits the actual samples and supports direct aggregations without inventing cross-record fields. The other options add correlation and operational costs and require separate retention, restart and event-boundary decisions.

## Data model contract

`Linux_Auditd.Auditd` is a BaseEvent root with constraints:

```spl
(`ix_auditd_indexes`) sourcetype=auditd tag=ix_auditd
```

The macro defaults to `index=linux`, matching the supplied `linux_auditd` macro and sample metadata. This is a configurable population decision, not a universal Linux index convention. Type children inherit the root and constrain both the exact `audit_type` and their own eventtype tag. The Unmapped child catches valid audit headers with types not yet named in the policy.

Names come from literal raw types, explicit rule predicates and documented CSV hints. Hints such as PROCTITLE inferred from a field do not automatically narrow a converted rule. `UNKNOWN[1333]` maps to the valid object identifier `UNKNOWN_1333` while preserving the literal filter. `SYSCSYSCALL` remains a distinct anomalous observed type. No claim is made that it is a standard kernel record type.

Four types required by searches but absent from the sample corpus are retained as rule-only, unvalidated datasets: ADD_USER, DAEMON_ABORT, DAEMON_END and DAEMON_START. The detailed inventory distinguishes them from observed types. DAEMON_CONFIG supports the observed header without a colon after `audit(...)`.

The model is an auditd record model, not a replacement CIM Endpoint model. SYSCALL, EXECVE, PATH, CWD and PROCTITLE records remain separate events. No process GUID, attacker address or guaranteed process-level identity is invented.

## Field selection

| Field group | Reason | Treatment |
| --- | --- | --- |
| type, audit_type | Original filters and dataset membership | Exact strings, including anomalies |
| audit_id, audit_event_id, audit_event_key | PATH/CWD correlation and collision review | Serial, timestamp text, and complete timestamp:serial respectively; group with host |
| host/source/sourcetype/_time | Event scope and aggregation | Inherit Splunk BaseEvent fields |
| comm/exe/syscall/arch, uid/auid/euid/gid and session IDs | Executable and privilege predicates | Mixed numeric/name values remain strings |
| pid/ppid/argc | Grouping and argument assembly | Numeric model fields; no guessed IDs |
| proctitle/execve_command | Command-based detections | Search-time normalization, high cardinality |
| name/nametype/cwd/a0-a3/key | File, syscall and correlation predicates | Raw record-local values |
| unit/op/res/acct/addr/terminal/subj | Service and account activity | Preserve original meaning; no fabricated action or user |
| Type-local capabilities/socket/SELinux/BPF/IPC fields | Observed forensic context | Added only to applicable children; allowlisted |
| _raw/password/TTY data/arbitrary environment fields | Not needed for the selected aggregations | Excluded from the model |

Missing fields stay missing. `res=failed` and `success=no` remain separate source concepts. Uppercase `UID`, `AUID` and `SYSCALL` are not silently aliased to lowercase fields; rules using them require review of actual enriched/raw semantics. `build/reports/field_inventory.json` is the complete emitted field list.

## TA decisions

The supplied TA defines a broad `auditd` eventtype, but no dedicated `[auditd]` extraction stanza. The extension keeps vendor tags intact and adds only `ix_auditd` and type-specific tags. Existing `linux_audit` behavior remains untouched; that sourcetype is not admitted to this model without new evidence.

The extension uses search-time REPORT extractions and calculated command fields. `KV_MODE=none` bounds extraction to the reviewed audit fields. This intentionally changes ad-hoc automatic KV discovery for `auditd`; review other auditd consumers before deployment. Other sourcetypes retain their baseline settings. Existing local/source/host overrides may change effective behavior and must be checked with btool.

PROCTITLE retains the full interpreted command or decodes even-length hex bytes. All 39 supplied headers use interpreted date/time text. Hex decoding is therefore restricted to native numeric-epoch audit headers; interpreted numeric/hex-looking text remains text. Validate that encoding/profile convention for each new collector before rollout. Hex NUL separators are replaced at byte boundaries. EXECVE reconstructs args in numeric order from a0 through a63, preserving the distinction between quoted text and unquoted hex. Only complete records with argc within the configured limit produce a derived command. Split/fragmented arguments, cross-record EXECVE fragments and larger argument lists require additional normalization; never silently truncate them. Command reconstruction does not recover shell quoting or prove parity with an existing external `execve_command` extractor.

The raw corpus contains one sample per type, which is insufficient to prove distribution-wide extraction or null/multivalue behavior. All model fields are single-valued per record; existing event merging or external multivalue extractions must block rollout until reconciled.

## Rule conversion

The converter accepts a narrow grammar: `linux_auditd` base filter, simple rename commands, standard count/min/max aggregation or last-event max, then an unchanged tail. It preserves quoted string values and boolean grouping, qualifies model fields, maps `host as dest` through the original host field, and retains filter/time-formatting macros. It uses the root dataset to avoid adding an inferred type restriction.

Candidates use `summariesonly=false allow_old_summaries=false`. No global fillnull is added because it changes group inclusion. Model field types, nulls, multivalue behavior, time limits, role access and macro context still require paired validation. Unknown grammar, raw rex, bucket/bin changes, arbitrary eval, joins and unresolved parameters are held for manual conversion. A candidate is not an approval or a measured performance result.

PATH/CWD searches currently group by host plus serial. Replacing that with a timestamp:serial key may reduce cross-reboot collisions but changes original semantics and needs explicit approval. Sparse PATH and CWD fields must not be put together into a tstats BY list: null suppression can drop the very records needed for correlation.

## Acceleration decision

Acceleration is disabled in the delivered app. The declared seven-day range is a proposed default only. Before enablement, establish exact server release/topology, retention, summary coverage, acceptable delay, storage, scheduler capacity and paired correctness. Measure query cost together with summary-build/backfill cost; no indexer CPU reduction is claimed here.

The object owner, change approver, platform owner and affected detection consumers are not inferred from the supplied login. Assign them during deployment review. No active server health or capacity evidence was collected.

## Documentation baseline

Official reference URLs and exact version scope are listed in `SOURCES.md`. Enterprise 9.4 is the documentation baseline only; it is not evidence of the test server's version. Runtime eligibility and configuration support must be checked against that actual release before activation.
