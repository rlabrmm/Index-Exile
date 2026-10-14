# Validation and performance acceptance

## Local checks

Run these from the repository root:

```console
python -m unittest discover -s tests -v
python scripts/validate.py --build build
python scripts/package.py --build build
```

Tests load the emitted TA regex/config rather than only testing the builder's input templates. Real-corpus tests read the private source locally and store no raw values. A fresh checkout without that corpus reports those tests as skipped. Synthetic fixtures use reserved example addresses and fabricated identities. Python regex checks and a limited local extractor do not implement Splunk's PCRE, EVAL, automatic field ordering or SPL engine.

## Runtime prerequisites

Record exact release, topology, owning app, owner/approver, role/search permissions, fixed interval, source population, retention and expected extraction. Compare source/host/sourcetype overrides using the release-appropriate btool procedure. Check props, transforms, eventtypes, tags, macros and model visibility from the actual detection app.

Use the installed Splunk Search skill. It requires an existing authenticated splunkctl target and does not configure credentials. If unavailable, label runtime `not executed; no live evidence collected`. Its exact-search confirmation boundary must be satisfied before submitting live searches.

## Bounded checks after installation

Use the same fixed epoch interval for every comparison. The relative examples below are starting templates and must be bound to that interval before comparing signatures.

1. Compare the raw auditd population with tagged records, preserving failed headers:

```spl
index=linux sourcetype=auditd earliest=-15m latest=now
| eval has_header=if(isnotnull(audit_type) AND isnotnull(audit_event_key),1,0)
| stats count sum(has_header) AS classified BY type
```

2. Compare root and children with the raw result under identical permissions:

```spl
| tstats summariesonly=false allow_old_summaries=false count
  FROM datamodel=Linux_Auditd.Auditd
  WHERE earliest=-15m latest=now
  BY Auditd.audit_type
```

Repeat each intended child using `WHERE nodename=Auditd.TYPE`. Test Unmapped with a controlled, approved test source; do not inject fabricated events into production merely for a check. Verify the broad root tag and exactly one type-child tag per supported single record.

3. Inspect field completeness per type with a bounded stats query, including audit_event_key, command fields and required grouping keys. Specifically test decoded/interpreted PROCTITLE, numeric argument order, missing/fragmented EXECVE arguments, unknown labels, nested msg fields, absent colon DAEMON_CONFIG, negative non-audit messages and null group keys. Do not export raw command lines into the repository.

4. For every candidate, execute original and candidate with the same source filters, fixed time window, app/macro context and role. Canonicalize rows by field name, scalar type and sorted multivalue contents, retaining duplicates/counts. Compare complete outputs, not only total row counts. Compare pre-format numeric times as well as final output fields used by risk/notable actions.

5. Only after acceleration is enabled through a reviewed change, compare mixed and summary-only runs for the same interval. Record summary range, actual covered buckets, lag, age, size, errors, build/backfill progress and source continuity. An enabled flag or nominal 100% status alone is insufficient evidence of complete current data.

## Performance envelope

After correctness passes, record multiple comparable runs for original and converted searches, accounting for warm/cold cache, concurrency and scheduler conditions. Capture elapsed time, scanned/read work, search/indexer CPU, memory and storage where available. Include continuous summarization and backfill cost; a faster individual query may increase total indexer work.

Acceptance requires unchanged detection results and a workload-level improvement acceptable to the named owner. Set thresholds from the environment's baseline, not an invented generic percentage. Preserve original rules until the approver accepts the results. Stop on missing results, stale summaries, excessive lag, scheduler pressure or storage growth, and use the documented rollback.

## Initial execution status

No server authentication, search, install, btool, AppInspect, acceleration enablement, restart or detection change was performed. Live verification was unavailable because splunkctl was absent. Actual performance and source/summary equivalence are unverified; local test outcomes are recorded in the validation report and memory log.
