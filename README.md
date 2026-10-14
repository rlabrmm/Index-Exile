# Index Exile: Linux Auditd

Portable, record-oriented Splunk data model, locally extended Linux TA, and reusable maintenance skills. All rule conversions are review candidates. No detection has been replaced or enabled, and acceleration is initially disabled.

## Deliverables

- `build/apps/Splunk_TA_nix`: complete modified TA, retaining the vendor identity and unrelated behavior. `local/` and local metadata are excluded.
- `build/apps/SA_index_exile_auditd`: model app, index macro, metadata and disabled acceleration configuration.
- `build/apps/SA_index_exile_auditd/default/data/models/Linux_Auditd.json`: importable data model JSON.
- `build/ta-overlay`: exact auditd additions for reviewing the TA changes.
- `build/dist`: installable TGZ packages, generated locally and excluded from Git. Recreate them from the committed app trees.
- `build/reports`: application hashes, type/field/rule inventories, hashed configuration settings, candidate disposition, automatic update comparison and package checksums. No raw sample payloads or configuration values.
- `build/candidates`: proposed tstats SPL, identified through `rule_inventory.json`.
- `skills/maintain-linux-auditd-ta/SKILL.md`: TA/model maintenance agent.
- `skills/convert-linux-auditd-rules/SKILL.md`: rule conversion and human approval agent.
- `docs`: design, installation, manual dataset addition, updates and validation procedures.

The committed baseline contains no app `local/` directories, local metadata, raw events, source application exports, or package archives. Its manifests exclude local application settings.

## Use

Read `docs/INSTALL.md` before installation. Install the extended TA as an update to the existing `Splunk_TA_nix`, and the model app separately on the appropriate search tier. Do not install the overlay as a second TA. Configure the index macro for the intended auditd indexes.

Python 3.10+ and its standard library are sufficient for build, tests and packaging:

```console
python scripts/package.py --build build
python -m unittest discover -s tests -v
python scripts/validate.py --build build
```

A full rebuild uses the source application directories. Neither development CSV is required:

```console
python scripts/build.py --inputs private-inputs --previous-build build --output build-next
```

For a full package rebuild, the input directory contains `Splunk_TA_nix`, `DA-ESS-ContentUpdate` and `SplunkEnterpriseSecuritySuite`. Use new output directories; builds are immutable review baselines. The builder retains the sanitized type/field catalog and the previous model, discovers types from current searches, referenced macros and TA predicates, and automatically writes `reports/update_diff.json` when `--previous-build` is supplied.

If only one application update is available, compare that complete extracted application directly:

```console
python scripts/review_updates.py --baseline build --updates private-updates --output private/update-review.json
```

`private-updates` may contain only `Splunk_TA_nix`, only `DA-ESS-ContentUpdate`, or any subset of the three source apps. Omitted applications are treated as unchanged. The review identifies file, rule, macro and configuration-setting changes without either CSV. Safely unpack downloaded archives into app directories first. A full rebuild later needs unchanged application sources as well; change discovery does not.

`auditd-types-sample_based_on_esu.csv` and `all_auditd_types.csv` were initial development evidence only. Optional new evidence can be supplied explicitly through `--type-map PATH` and `--samples PATH`; there is no fixed filename requirement. Without samples, extraction/runtime validation is marked not run, never falsely passed. `config/auditd_catalog.json` retains only non-sensitive type names and field names, so historical schema knowledge remains portable.

## Validation boundary

Local regex/configuration tests are separate from Splunk execution. The supplied server release, topology, effective configuration, acceleration coverage and performance remain unverified. `splunkctl` was unavailable, so the installed Splunk Search skill's live path could not execute. No authentication or deployment was attempted. See `docs/VALIDATION.md` for the exact acceptance procedure.

Source vendor files retain their existing notices and license terms under `build/apps/Splunk_TA_nix`. The repository's existing `LICENSE` does not replace those notices. Supplied samples, deployment settings, credentials, source ES exports and local execution logs are not committed. Review third-party licensing before public redistribution.

## License and upstream components

Project documentation and original automation use the repository license. `build/apps/Splunk_TA_nix` preserves the upstream add-on license notices and third-party attributions. The project license does not replace those terms. See [THIRD_PARTY.md](docs/THIRD_PARTY.md) before redistribution.
