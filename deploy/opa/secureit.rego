package secureit.authz

import rego.v1

default allow := false

blocked_state if input.target.lifecycle_state in {"quarantined", "retired", "pending"}

scope_allowed if input.required_scope in input.identity.scopes

environment_allowed if input.target.environment in input.identity.environments

fanout_allowed if input.target_count <= input.action.max_targets

read_action_allowed if {
  input.action.risk == "read"
  input.target.environment in {"dev", "test"}
}

approval_satisfied if {
  input.target.environment in {"staging", "prod"}
  input.approval.manifest_hash == input.manifest_hash
  input.approval.approver_subject != input.identity.subject
  input.approval.decision == "approved"
}

allow if {
  input.audit_available
  scope_allowed
  environment_allowed
  fanout_allowed
  not blocked_state
  read_action_allowed
}

allow if {
  input.audit_available
  scope_allowed
  environment_allowed
  fanout_allowed
  not blocked_state
  approval_satisfied
}

decision := {
  "allow": allow,
  "requires_approval": input.target.environment in {"staging", "prod"},
  "max_targets": input.action.max_targets,
  "policy_version": "secureit-demo-v1"
}
