---
name: maintain-linux-auditd-ta
description: Build or update this repository's Linux auditd TA and type-based data model from application updates and retained schema knowledge, with optional samples. Use for new audit types, extraction/tag fixes and TA or content updates; no automatic deployment or rule activation.
---

# Maintain the Linux Auditd TA and model

Use the repository containing `scripts/build.py`, `config/model_policy.json` and `docs/UPDATES.md`. Resolve paths relative to that root. Read `README.md`, `docs/DESIGN.md`, and the previous accepted build reports before changing artifacts. Record each update in the review output and the project's change record.

## Inputs and baseline

Accept any supplied complete updated TA or ES/ESCU application, even if the other applications and all development CSV exports are unavailable. First run `python scripts/review_updates.py --baseline BASELINE --updates UPDATES --output REPORT.json`. Compare only supplied applications; do not interpret omitted apps as deleted. Safely inspect and unpack archives into their app-ID directories before using the tool. Isolated replacement files are not complete app snapshots and require a scoped manual comparison instead.

Neither `auditd-types-sample_based_on_esu.csv` nor `all_auditd_types.csv` is a prerequisite. They were development evidence only. Use `config/auditd_catalog.json` and the previous accepted model as retained schema knowledge. Discover current requirements from search text, referenced macros and TA predicates/configuration. Optional sanitized samples and mapping data can be passed explicitly using `--samples` and `--type-map`. Their absence must not delete known datasets/fields or block change discovery; label sample validation not run. Never store credentials or source logs in tracked files.

Inspect repository state and source hashes. Read all applicable default/local TA settings, metadata, source/host precedence, referenced transforms/lookups, collectors, manifests and licenses. Review the supplied TA-Builder specification when available as implementation guidance; do not use its generic CIM mapping table as evidence for auditd semantics.

Use Python's CSV reader and `_raw` as the extraction input. Profile every supplied record, including multiline and malformed records. Exported fields can reveal discrepancies but do not validate the proposed extractor. Keep observed, rule-only and anomalous types separate. Preserve UNKNOWN numeric labels and misspelled source labels until a human-approved normalization is supported by evidence.

## Build and review

1. Read executable searches and referenced macro definitions from available applications. Compare changed search hashes, settings, macro definitions and extraction/tag configuration with baseline reports. Compare an optional mapping only when supplied. Derive record types from source predicates and field evidence; do not turn an inferred hint into a narrowing detection condition.
2. Maintain the record-level `Linux_Auditd.Auditd` contract and stable dataset identifiers. Select detection-relevant fields and bounded type-local fields. Exclude raw logs, secret-bearing arbitrary fields and TTY data. Document cardinality and missing-field consequences.
3. Update the policy/generator, including extraction tests. Preserve unrelated vendor behavior and app identity. Search-time calculated fields must not depend on execution order among EVAL assignments. Do not merge PATH/CWD/EXECVE records implicitly.
4. To rebuild complete packages, combine updated applications with the unchanged source applications in an untracked snapshot and run `python scripts/build.py --inputs INPUTS --previous-build BASELINE --output OUTPUT`. No CSV is required. If unchanged source packages are unavailable, finish the partial update review and identify only the missing application sources needed for packaging. A stanza collision requires a reviewed generator merge; never force duplicate stanza append or delete deployment-local configuration.
5. Compare inventories with `scripts/compare_updates.py`. Review added/removed types, field changes, macro changes, input hashes and stale detection dependencies. Keep the prior build available for rollback.
6. Run `python -m unittest discover -s tests -v` against the accepted build location, and `python scripts/validate.py --build OUTPUT`. Repackage and reopen archives; compare bytes and hashes. Keep local behavior checks separate from Splunk execution and AppInspect.
7. Follow `docs/INSTALL.md` and `docs/VALIDATION.md` for a proposed deployment. Use installed Splunk skills for live interaction. If splunkctl is required but absent, stop only the live path and state that no live evidence was collected; never bypass that skill with direct REST or credential scripts.

## Outputs and stop conditions

Deliver complete app trees, model JSON, patch overlay, packages, input/type/field inventories, validation results, manual dataset instructions and a precise changed-file list. Retain vendor attribution. Keep acceleration disabled until release/topology, extraction correctness, scope, capacity and summary completeness are established.

Stop dependent deployment on failed parsing/classification, unexpected type overlap, missing required fields, stale summaries or regression. Finish independent local work and explain missing evidence. An enabled model is not proof of completeness or better performance.

Do not install, restart, change permissions, enable acceleration or replace detection searches as a side effect of building artifacts. Obtain the appropriate explicit authorization immediately before live mutation. Route conversion work to `../convert-linux-auditd-rules/SKILL.md`. Commit locally only when requested, after reviewing the exact staged files for confidential data.
