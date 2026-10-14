# Add a child dataset manually

Prefer changing the policy and rebuilding so future TA/ESCU updates preserve the addition.

1. Obtain a sanitized raw audit record and a concrete detection/forensic use case. Confirm the literal type from `_raw`, not a guessed field name or CSV tag. Note absent samples if the type is rule-only.
2. Add the literal type to `additional_types` in `config/model_policy.json`. The builder also discovers types from supplied samples and executable rules. Preserve existing names to avoid breaking consumers.
3. If needed, add an allowlisted field list under `additional_fields`, keyed by the literal type. Review field meaning, numeric versus string representation, cardinality and secret exposure. The current policy adds new fields as strings; adjust the generator's numeric list only with evidence. The builder generates a bounded key-value extraction for new fields; non-key-value or encoded structures need a reviewed extractor and regression fixture.
4. Build into a fresh output directory, compare inventories, run validation and inspect the added eventtype, tag and model constraint. Add positive, negative, missing-field and malformed examples. A new type should match the root plus its own child, not another type child or Unmapped.
5. Review summary compatibility and deployment effects; deploy the TA and model together. Check effective extraction and model populations before rebuilding/enabling acceleration. Revalidate consumers.

Example policy additions:

```json
{
  "additional_types": ["NEW_AUDIT_TYPE"],
  "additional_fields": {"NEW_AUDIT_TYPE": ["new_field"]}
}
```

The example is a placeholder, not a claimed Linux audit record type.

## Direct configuration procedure

If you must edit manually, add these coordinated objects, then carry the same change back into the policy/generator:

```ini
# eventtypes.conf
[ix_auditd_new_audit_type]
search = sourcetype=auditd audit_event_key=* audit_type="NEW_AUDIT_TYPE"

# tags.conf
[eventtype=ix_auditd_new_audit_type]
ix_auditd_new_audit_type = enabled
```

Add an object to the JSON `objects` array:

```json
{
  "objectName": "NEW_AUDIT_TYPE",
  "displayName": "NEW_AUDIT_TYPE",
  "parentName": "Auditd",
  "fields": [],
  "calculations": [],
  "constraints": [{"search": "audit_type=\"NEW_AUDIT_TYPE\" tag=ix_auditd_new_audit_type"}],
  "children": []
}
```

Inheritance supplies the root fields; do not redeclare them. Remove the new literal from Unmapped membership by adding it to that object's NOT-IN list. For a new field, add a field definition and a tested REPORT extraction; a model field declaration alone does not extract data. Legal object names use letters/digits/underscores, while the constraint retains the exact literal type. Check for sanitized-name collisions such as punctuation variants.

After import, verify the new child with `nodename=Auditd.NEW_AUDIT_TYPE`, and compare its raw, data-model and tstats counts over the same bounded interval and permissions. Record the actual result and update the memory log.
