begin;

create schema if not exists inventory;
create schema if not exists control_plane;
create schema if not exists private_access;
create schema if not exists audit;
create schema if not exists agent_api;

do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'secureit_agent_catalog') then
    create role secureit_agent_catalog nologin;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'secureit_control_plane') then
    create role secureit_control_plane nologin;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'secureit_credential_broker') then
    create role secureit_credential_broker nologin;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'secureit_auditor') then
    create role secureit_auditor nologin;
  end if;
end
$$;

create table inventory.access_profiles (
  id uuid primary key,
  name text not null unique check (length(name) between 1 and 128),
  connection_mode text not null check (connection_mode in ('local_agent', 'ssh_cert', 'cloud_api')),
  allowed_environments text[] not null,
  max_ttl_seconds integer not null check (max_ttl_seconds between 30 and 3600),
  privilege_level text not null check (privilege_level in ('readonly', 'operator', 'privileged')),
  enabled boolean not null default true,
  created_at timestamptz not null default now(),
  check (allowed_environments <@ array['dev', 'test', 'staging', 'prod']::text[])
);

create table inventory.servers (
  id uuid primary key,
  name text not null unique check (length(name) between 2 and 254),
  environment text not null check (environment in ('dev', 'test', 'staging', 'prod')),
  owner text not null check (length(owner) between 1 and 128),
  criticality text not null check (criticality in ('low', 'medium', 'high', 'critical')),
  lifecycle_state text not null default 'pending'
    check (lifecycle_state in ('pending', 'managed', 'quarantined', 'retired')),
  connection_mode text not null check (connection_mode in ('local_agent', 'ssh_cert', 'cloud_api')),
  access_profile_id uuid not null references inventory.access_profiles(id),
  labels jsonb not null default '{}'::jsonb check (jsonb_typeof(labels) = 'object'),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  last_seen_at timestamptz
);

create table inventory.management_endpoints (
  id uuid primary key,
  server_id uuid not null references inventory.servers(id) on delete restrict,
  protocol text not null check (protocol in ('https', 'ssh', 'mtls', 'cloud_api')),
  address text not null check (length(address) between 1 and 253),
  port integer not null check (port between 1 and 65535),
  network_zone text not null check (length(network_zone) between 1 and 64),
  expected_identity text not null check (length(expected_identity) between 16 and 1024),
  unique (server_id, protocol, address, port)
);

create table private_access.access_bindings (
  id uuid primary key,
  server_id uuid not null references inventory.servers(id) on delete restrict,
  mechanism text not null
    check (mechanism in ('workload_mtls', 'ssh_ca', 'cloud_sts', 'legacy_secret')),
  remote_principal text not null,
  secret_backend text not null,
  credential_ref text not null,
  max_ttl_seconds integer not null check (max_ttl_seconds between 30 and 3600),
  enabled boolean not null default true,
  rotated_at timestamptz,
  created_at timestamptz not null default now(),
  unique (server_id, mechanism, remote_principal)
);

comment on table private_access.access_bindings is
  'Contiene referencias opacas; está prohibido almacenar valores de credenciales.';

create table control_plane.action_definitions (
  action_id text not null,
  version integer not null check (version > 0),
  description text not null,
  risk text not null check (risk in ('read', 'low', 'high', 'critical')),
  executor text not null,
  parameter_schema jsonb not null,
  artifact_digest text not null check (artifact_digest ~ '^sha256:[a-f0-9]{64}$'),
  max_targets integer not null check (max_targets between 1 and 100),
  max_stdout_bytes integer not null check (max_stdout_bytes between 0 and 65536),
  max_stderr_bytes integer not null check (max_stderr_bytes between 0 and 16384),
  enabled boolean not null default true,
  primary key (action_id, version)
);

create table control_plane.execution_requests (
  id uuid primary key,
  idempotency_key uuid not null,
  requester_subject text not null,
  action_id text not null,
  action_version integer not null,
  normalized_parameters jsonb not null,
  resolved_target_ids uuid[] not null check (cardinality(resolved_target_ids) between 1 and 100),
  manifest_hash text not null unique check (manifest_hash ~ '^sha256:[a-f0-9]{64}$'),
  policy_hash text not null check (policy_hash ~ '^sha256:[a-f0-9]{64}$'),
  risk text not null check (risk in ('read', 'low', 'high', 'critical')),
  status text not null check (status in (
    'awaiting_approval', 'queued', 'running', 'completed', 'failed', 'cancelled', 'expired'
  )),
  expires_at timestamptz not null,
  created_at timestamptz not null default now(),
  foreign key (action_id, action_version)
    references control_plane.action_definitions(action_id, version),
  unique (requester_subject, idempotency_key)
);

create table control_plane.approvals (
  id uuid primary key,
  execution_request_id uuid not null references control_plane.execution_requests(id) on delete restrict,
  manifest_hash text not null,
  approver_subject text not null,
  decision text not null check (decision in ('approved', 'denied')),
  expires_at timestamptz not null,
  created_at timestamptz not null default now(),
  unique (execution_request_id, approver_subject)
);

create table control_plane.jobs (
  id uuid primary key,
  execution_request_id uuid not null unique references control_plane.execution_requests(id) on delete restrict,
  status text not null check (status in ('queued', 'running', 'completed', 'failed', 'cancelled', 'expired')),
  lease_owner text,
  lease_expires_at timestamptz,
  attempts integer not null default 0 check (attempts between 0 and 10),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index jobs_claimable_idx on control_plane.jobs (created_at)
  where status = 'queued';

create table control_plane.job_results (
  job_id uuid not null references control_plane.jobs(id) on delete restrict,
  server_id uuid not null references inventory.servers(id) on delete restrict,
  status text not null,
  exit_code integer,
  stdout_excerpt text check (octet_length(stdout_excerpt) <= 65536),
  stderr_excerpt text check (octet_length(stderr_excerpt) <= 16384),
  truncated boolean not null default false,
  secret_detected boolean not null default false,
  created_at timestamptz not null default now(),
  primary key (job_id, server_id),
  check (not secret_detected or (stdout_excerpt is null and stderr_excerpt is null))
);

create table control_plane.credential_rotation_jobs (
  id uuid primary key,
  requester_subject text not null,
  idempotency_key uuid not null,
  target_ids uuid[] not null check (cardinality(target_ids) between 1 and 20),
  access_profile_id uuid not null references inventory.access_profiles(id),
  previous_version_id text,
  next_version_id text,
  status text not null check (status in ('awaiting_approval', 'queued', 'running', 'completed', 'failed')),
  verified_at timestamptz,
  sanitized_error_code text,
  created_at timestamptz not null default now(),
  unique (requester_subject, idempotency_key)
);

create table audit.events (
  sequence bigint generated always as identity primary key,
  event_id uuid not null unique,
  occurred_at timestamptz not null default now(),
  subject text not null,
  operation text not null,
  outcome text not null check (outcome in ('allowed', 'denied')),
  object_ids uuid[] not null default '{}',
  reason_code text not null,
  request_id uuid,
  previous_hash text,
  event_hash text not null check (event_hash ~ '^sha256:[a-f0-9]{64}$')
);

create function audit.reject_mutation() returns trigger
language plpgsql
as $$
begin
  raise exception 'audit events are append-only';
end
$$;

create trigger audit_events_append_only
before update or delete on audit.events
for each row execute function audit.reject_mutation();

create view agent_api.servers as
select id as server_id, name, environment, criticality,
       lifecycle_state as state, connection_mode, labels
from inventory.servers;

revoke all on schema inventory, control_plane, private_access, audit, agent_api from public;
revoke all on all tables in schema inventory, control_plane, private_access, audit from public;

grant usage on schema agent_api to secureit_agent_catalog;
grant select on agent_api.servers to secureit_agent_catalog;

grant usage on schema inventory, control_plane, audit to secureit_control_plane;
grant select, insert, update on inventory.servers, inventory.management_endpoints to secureit_control_plane;
grant select on inventory.access_profiles, control_plane.action_definitions to secureit_control_plane;
grant select, insert, update on control_plane.execution_requests, control_plane.jobs,
  control_plane.job_results, control_plane.credential_rotation_jobs to secureit_control_plane;
grant insert on audit.events to secureit_control_plane;

grant usage on schema private_access, inventory to secureit_credential_broker;
grant select on private_access.access_bindings, inventory.servers to secureit_credential_broker;

grant usage on schema audit to secureit_auditor;
grant select on audit.events to secureit_auditor;

commit;
