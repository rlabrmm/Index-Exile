# Official reference baseline

Retrieved during the project on 2026-10-13. The target server release is unknown. These Enterprise 9.4 references guide draft syntax and local design; they do not certify server compatibility or runtime behavior.

- tstats: supported aggregations, dataset/nodename addressing, null BY fields, and summary-only behavior.
  `https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/9.4/search-commands/tstats`
- props.conf: search-time REPORT, EVAL and KV_MODE semantics.
  `https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.4/configuration-file-reference/9.4.1-configuration-file-reference/props.conf`
- transforms.conf: named extraction groups, FORMAT and MV_ADD behavior. With MV_ADD=false an already-present field is not replaced; effective prior extractions matter.
  `https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.4/configuration-file-reference/9.4.1-configuration-file-reference/transforms.conf`
- datamodels.conf: acceleration settings and range configuration.
  `https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.4/configuration-file-reference/9.4.1-configuration-file-reference/datamodels.conf`
- Splunk-maintained CIM JSON example: structural reference for BaseEvent, child parentName, fields, calculations and constraints. This project does not import CIM normalization or claim CIM certification.
  `https://raw.githubusercontent.com/splunk/addonfactory-splunk_sa_cim/master/default/data/models/Change_Analysis.json`

Match each version-dependent deployment decision to the actual installed release before rollout. Public documentation is separate from local evidence in `build/reports`.
