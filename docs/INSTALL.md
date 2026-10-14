# Installation and rollback

These steps are an operator runbook, not a record of completed deployment. No credentials are required in any repository file.

1. Record the actual Splunk Enterprise version, topology, owner, app context and intended indexes. Confirm that events are individual audit records and that this is the `auditd` sourcetype.
2. Back up the installed TA and relevant local/metadata overrides. Compare `build/ta-overlay` against effective `[auditd]` props and all `ix_auditd*` knowledge objects. Inspect source/host-level extraction overrides and external command normalization. Stop on collisions.
3. Recreate packages with `python scripts/package.py --build build`; compare SHA256 with `build/reports/packages.json`. Archives have one app root and exclude local settings.
4. Update the existing `Splunk_TA_nix` with the reviewed package. Preserve its deployment-managed `local` settings. Do not install a second renamed copy alongside it, and do not overwrite or remove existing local files merely to win precedence.
5. Install `SA_index_exile_auditd` on the search head or via the supported search-head cluster deployment path. Deploy the TA's search knowledge on the search tier so it is available in the distributed search knowledge bundle. This extension has no new collector, index-time parser or forwarding changes; it does not require a UF input change. Use the platform's supported deployment mechanism for your topology, not direct edits on managed cluster members.
6. Set the `ix_auditd_indexes` macro in the model app's local configuration to the intended index scope. Verify read permissions in the app from which detections run. Metadata exports the model globally; review the read roles for your environment.
7. Reload/restart using the procedure appropriate to the actual Splunk release and deployment tier. Run btool and the validation searches before considering acceleration.
8. After correctness and capacity review, enable acceleration in local datamodels.conf with a reviewed summary range. Wait for actual coverage, not merely an enabled status. Compare raw, mixed and summary-only results before choosing summary-only production queries.
9. Keep all original detections unchanged until the rule-conversion skill produces explicit human-reviewed patches. Merge each approved search assignment into its original application's local savedsearches configuration; retain schedules, dispatch windows, risk/notable actions, permissions and filter macros.

## Importing just the JSON

In the supported Data Model management UI, upload `Linux_Auditd.json` from `build/apps/SA_index_exile_auditd/default/data/models/`. Use the same model name and owning app. JSON import alone is not enough: install the extraction/tag knowledge, define `ix_auditd_indexes`, and set model permissions. Use either the packaged model app or a reviewed import into an existing app; avoid duplicate models with the same name in competing app contexts.

Example tstats query after installation:

```spl
| tstats summariesonly=false allow_old_summaries=false count
  FROM datamodel=Linux_Auditd.Auditd
  WHERE nodename=Auditd.SYSCALL earliest=-15m latest=now
  BY Auditd.audit_type Auditd.host
```

This query is provided for execution after deployment and has not been run here.

## Rollback

Restore the backed-up TA through the same deployment mechanism and revert only the new model app and approved local search changes. Restore previous macro/index scope and permissions. Keep source audit data intact. If model/extraction semantics changed after summaries were built, treat those summaries as stale and follow the exact release's supported summary retirement/rebuild procedure; do not force `allow_old_summaries=true`. Stop rollout on mismatched results, missing child populations, extraction errors, scheduler pressure or unexpected storage growth.
