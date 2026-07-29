package secureit.authz

import rego.v1

base_input := {
  "identity": {
    "subject": "operator@example.test",
    "scopes": {"secureit:ssh:action"},
    "environments": {"dev", "test"}
  },
  "required_scope": "secureit:ssh:action",
  "target": {"environment": "test", "lifecycle_state": "managed"},
  "target_count": 1,
  "action": {"risk": "read", "max_targets": 20},
  "manifest_hash": "sha256:demo",
  "approval": {},
  "audit_available": true
}

test_allows_read_in_test if allow with input as base_input

test_denies_missing_scope if not allow with input as object.union(base_input, {
  "identity": object.union(base_input.identity, {"scopes": set()})
})

test_denies_quarantined if not allow with input as object.union(base_input, {
  "target": {"environment": "test", "lifecycle_state": "quarantined"}
})

test_denies_when_audit_is_down if not allow with input as object.union(base_input, {
  "audit_available": false
})

test_denies_excessive_fanout if not allow with input as object.union(base_input, {
  "target_count": 21
})

test_denies_self_approval_in_prod if not allow with input as object.union(base_input, {
  "identity": object.union(base_input.identity, {"environments": {"prod"}}),
  "target": {"environment": "prod", "lifecycle_state": "managed"},
  "action": {"risk": "high", "max_targets": 20},
  "approval": {
    "manifest_hash": "sha256:demo",
    "approver_subject": "operator@example.test",
    "decision": "approved"
  }
})
