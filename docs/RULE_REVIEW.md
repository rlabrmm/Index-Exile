# Rule conversion review and approval

`build/reports/rule_inventory.json` maps IDs to app, original title, source hash, candidate hash, status, macro dependencies and CSV agreement. Candidate SPL is in `build/candidates/<id>.spl`. Search source remains in the private input application; it is not duplicated into the output package.

The current converter deliberately handles only direct aggregation and the last-event monitor. Every other source shape has an explicit reason for manual work. A missing candidate does not mean the rule should be disabled.

## Manual conversion cases

| Shape | Required treatment |
| --- | --- |
| PATH/CWD correlation | Aggregate separately or use sparse-field-safe values aggregations by host+reviewed event key; preserve path reconstruction and event multiplicity. Validate absent CWD, relative/absolute names, multiple PATH records and serial reuse. |
| chmod `_raw` rex and `$dest$` | Extract needed fields before acceleration with exact raw semantics, or retain the raw search. Resolve whether the parameterized search is a drilldown or scheduled detection. |
| Copy Fail pre-aggregation eval | Review setuid/indicator calculation and required name/exe fields. Ensure the SYSCALL record really contains the needed context. |
| Possible Setuid eval | Preserve ID representation and inequality/null semantics; model necessary source fields before aggregation. |
| Network discovery bucket/bin | Preserve the source time rounding and aggregation grain. Moving the bin into tstats BY may change grouping. |
| Dirty Frag joins | Convert each eligible auditd branch independently; preserve join limits, session keys, timing and multiplicity. |
| Suspicious Namespace/Sysmon | Only the auditd branch belongs in this model. Retain and validate the external Sysmon branch. |
| Uppercase UID/AUID/SYSCALL | Determine whether these are enriched fields, source mistakes or intentional names. Do not case-normalize silently. |
| Last-event monitor | Existing logic sees only hosts with events in the searched interval. It does not detect a host absent from the entire interval. Fixing that requires a separate expected-host inventory and approval. |

## Approval record

An example structure follows. Placeholder values are not approval. Keep actual approval evidence in the designated controlled location; commit only sanitized reviewer identifiers/evidence references if appropriate.

```json
{
  "reviewer": "HUMAN_REVIEWER",
  "approved_at": "ISO_8601_TIMESTAMP",
  "model_sha256": "SHA256_OF_CURRENT_MODEL_JSON",
  "ta_sha256": "SHA256_TREE_FROM_BUILD_CONTRACT",
  "rules": [
    {
      "id": "RULE_ID_FROM_INVENTORY",
      "approved": true,
      "source_sha256": "SOURCE_SEARCH_HASH",
      "candidate_sha256": "CANDIDATE_SEARCH_HASH",
      "validation": {
        "server_version": "ACTUAL_RELEASE",
        "app_context": "ORIGINAL_RULE_APP",
        "earliest": "FIXED_EPOCH_START",
        "latest": "FIXED_EPOCH_END",
        "raw_result_signature": "CANONICAL_RESULT_HASH",
        "candidate_result_signature": "SAME_CANONICAL_RESULT_HASH",
        "equivalent": true,
        "evidence_reference": "CONTROLLED_REVIEW_PACKET_REFERENCE"
      }
    }
  ]
}
```

The model and TA tree hashes are recorded in `build/reports/build_contract.json`. The review packet must additionally capture effective extraction state, macro definitions/visibility, relevant dispatch/action settings, and summary coverage. The approval utility checks source, candidate, model and TA hashes and the declared result signatures; it does not verify a human identity or independently execute Splunk. The skill operator must verify the approval is genuinely from the user and that the external evidence has not changed.

```console
python scripts/approve_rules.py --build build --inputs private-inputs --approval private/approval.json --output private/approved-patches
```

The script refuses absent/negative approval, stale source/candidate/model hashes, changed application inputs, absent equivalence evidence or differing result signatures. Development CSVs are not approval prerequisites, including when processing the original development manifest. It produces only approved search assignments, preserving every other savedsearch property. Review and merge a patch; do not replace an entire existing local savedsearches.conf with it. No approved patches were produced as part of this initial build.
