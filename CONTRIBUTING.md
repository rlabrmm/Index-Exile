# Contributing

Keep changes reproducible and scoped to Linux auditd.

Before proposing an update:

1. Read `docs/DESIGN.md` and the relevant maintenance skill under `skills/`.
2. Preserve the source applications and previous accepted build for comparison. Development CSV exports are optional and must not become prerequisites.
3. Record any input or schema change in the sanitized update report. Never commit raw events, credentials, deployment exports, private addresses or local settings.
4. Keep original ES searches unchanged until a specific tstats candidate has human approval and equivalent runtime results.
5. Include the reason and rollback path for changes to dataset identity, field meaning, extraction behavior or application scope.

Before opening a pull request, review staged files and license notices. Run the documented offline checks when you change code, configuration or the model. Report live Splunk and AppInspect checks as unverified unless they were actually performed.

Use English for project files, reports and commit messages. Do not push credentials or private test environment details in examples.
