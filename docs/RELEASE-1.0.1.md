# Auditd extraction fix: extension 1.0.1

The supplied search export showed literal `$1$2$3` in fields such as `uid`, `pid`, `exe`, `syscall`, and `argc`, while audit header fields and tags were populated. The generated field transforms used `FORMAT = field::$1$2$3`. Search-time FORMAT does not support concatenating capture values. Header and internal argument transforms already used named captures, explaining the difference.

Each allowlisted raw field now uses separate named-capture transforms for double-quoted, single-quoted, and unquoted values. Quotes are excluded from field values. The bounded field list, header extraction, tags, command EVALs, and unrelated vendor files remain unchanged. The extension version is 1.0.1; the upstream TA version remains its vendor version.

The old local test helper incorrectly concatenated captures, hiding the defect. It now substitutes only a single capture reference. Regression tests reject FORMAT on generated raw-field transforms and cover quoted, unquoted, empty, absent, nested, normalized-name, and literal-dollar values. Five tests fail against the previous generated TA; all pass against the corrected build.

## Packages and deployment verification

Recreate packages with `python scripts/package.py --build build`. The complete TA is `build/dist/Splunk_TA_nix.tgz`; the companion model is `build/dist/SA_index_exile_auditd.tgz`. Install the TA update through the existing deployment process described in INSTALL.md. Do not install the overlay as another app. Verify effective configuration for overrides and run a fresh search after the updated search-time configuration is loaded.

Compare `uid`, `pid`, `exe`, `syscall`, `argc`, and argument fields directly with `_raw`; check tags and EXECVE command assembly. Existing exported CSV values do not change when configuration changes. If acceleration was enabled externally, validate or rebuild affected summaries through the deployment owner before relying on them. This repository leaves acceleration disabled.

Validation is offline only. No Splunk search, deployment, btool or AppInspect execution is claimed. The private sample export stays outside Git; only aggregate comparison counts are recorded in `reports/auditd_extraction_regression.json`.

Reference: Splunk Enterprise transforms.conf specification, FORMAT search-time extraction and named capturing groups. Public documentation retrieval was unavailable during this run; the failure diagnosis is also directly supported by the supplied CSV and generated configuration.

The regenerated release inventory also removes 160 legacy hashes of local input settings. Portable default source settings are unchanged.
