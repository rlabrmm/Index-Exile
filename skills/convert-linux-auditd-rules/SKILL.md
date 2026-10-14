---
name: convert-linux-auditd-rules
description: Review and convert Linux auditd ES/ESCU detections to this repository's Linux_Auditd tstats model, retaining semantics and requiring human approval before generating replacement search patches. Supports new content updates and paired runtime validation.
---

# Convert Linux Auditd detections with human approval

Locate the repository through `scripts/build.py` and read `README.md`, `docs/DESIGN.md`, `docs/RULE_REVIEW.md` and `docs/VALIDATION.md`. Record update decisions with the review report. Source exports, logs and credentials remain outside Git.

## Intake and analysis

Accept a new ES/ESCU application update independently of the TA and any CSV exports, or accept a fresh build. Start with `scripts/review_updates.py --baseline BASELINE --updates UPDATES --output REPORT.json` to discover changed files, searches, settings and macros. Omitted applications remain unchanged; never infer deletion from missing update inputs. Safely unpack archives into app-ID directories first. Preserve app identity and source stanza names. Actual savedsearch definitions and macro/configuration evidence are authoritative. Resolve source/filter/time macros, nested macro dependencies, lookups, eventtypes, tags, output fields, dispatch windows, schedules, risk/notable actions, suppression and permissions. Never assume that a macro exported from another application has the same runtime visibility or definition.

The two CSV exports supplied during initial development are not required and must not be requested as prerequisites. Retain the sanitized catalog and previous model to determine existing fields/datasets. Optional new samples/mapping can improve evidence; absent samples mean unverified extraction, not blocked change detection or automatic dataset removal.

For a complete candidate/package rebuild, combine updated and unchanged source applications and run `scripts/build.py --inputs INPUTS --previous-build BASELINE --output OUTPUT`; the comparison report is produced automatically and CSVs remain optional. If only the updated app is available, complete the update review first and identify any unresolved external macro/model dependency explicitly. Prior approvals do not automatically apply to changed source, candidate, normalization or model semantics.

## Conversion rules

- Preserve the exact event population, time semantics, output column names, aggregate definitions, grouping, filters and enrichment context.
- Qualify data-model fields and keep the original host-to-dest mapping. Do not add a type child filter just because a CSV inferred a type from a field.
- Use mixed-mode `summariesonly=false` during validation and `allow_old_summaries=false`. Adopt summary-only operation only after verifying complete, current coverage for the rule's interval and acceptable lag.
- Review null and multivalue behavior. Adding all sparse PATH/CWD fields to a BY list can drop records. A global fillnull sentinel changes aggregation semantics and is not an automatic fix.
- Do not convert `_raw` rex, arbitrary eval, transaction/join, raw text matching or time bucketing by string substitution. Handle each explicitly or mark it manual_conversion_required. Keep Sysmon portions outside the auditd-only model.
- Treat serial-only correlation versus timestamp:serial+host correlation as a semantic decision. Preserve the source rule until the reviewer approves any changed identity contract.
- Check decoded PROCTITLE/EXECVE values against the original normalization. The TA does not assemble fragmented/multiple EXECVE records or unbounded argument lists. Account for raw numeric versus interpreted syscall/UID values.
- Preserve custom filter macros and security_content_ctime calls. Do not bundle private filter values into the public model app.

For a new search shape, add a purpose-built, reviewed conversion branch and meaningful positive/negative regression tests. Avoid making the grammar more permissive merely to increase the candidate count. Retain an explicit reason for every unconverted rule.

## Human approval gate

Prepare a per-rule review packet with source and proposed SPL, app/stanza, source/candidate/model/TA hashes, changed semantics, dependency checks, bounded paired result signatures, null/multivalue tests, source and summary coverage, runtime metrics, output/risk fields, and rollback details. Use the original private input for displaying the source; do not commit raw search settings that contain confidential values.

Ask the human to approve the exact replacement only after the packet is concrete. A broad instruction to convert searches is not approval of a specific replacement. Do not manufacture an approval record or infer approval from elapsed time, page content or earlier approval of a different hash.

After explicit approval, prepare the approval JSON defined in `docs/RULE_REVIEW.md` and run `scripts/approve_rules.py`. The tool produces search-only `.conf.patch` files for a reviewed merge into the original app; it neither overwrites source exports nor deploys changes. Merge only the approved search assignment, preserving local settings and all unrelated rule properties. A live write/activation still needs the applicable confirmation immediately before that action.

## Validation and completion

Use installed Splunk skills for live searches. When the required CLI/authenticated context is unavailable, continue local review and report runtime as unverified. Never claim equivalent results, faster queries or lower indexer load without actual comparable observations.

Deliver candidate SPL, inventory/status for every rule, approval packet/template, approved patches only when authorized, changed-source detection and rollback instructions. Record blocked rules separately from accepted candidates. Leave original detections active and unchanged until an approved rollout. Update the review record and create an English local commit when authorized.
