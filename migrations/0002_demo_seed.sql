begin;

insert into inventory.access_profiles
  (id, name, connection_mode, allowed_environments, max_ttl_seconds, privilege_level)
values
  ('10000000-0000-4000-8000-000000000001', 'linux-readonly-local-agent', 'local_agent', array['dev','test'], 300, 'readonly'),
  ('10000000-0000-4000-8000-000000000002', 'linux-readonly-ssh-ca', 'ssh_cert', array['dev','test','staging'], 300, 'readonly');

insert into inventory.servers
  (id, name, environment, owner, criticality, lifecycle_state, connection_mode, access_profile_id, labels)
values
  ('20000000-0000-4000-8000-000000000001', 'web-test-01.example', 'test', 'platform-demo', 'low', 'managed', 'local_agent', '10000000-0000-4000-8000-000000000001', '{"role":"web","region":"example-west"}'),
  ('20000000-0000-4000-8000-000000000002', 'db-dev-01.example', 'dev', 'data-demo', 'medium', 'managed', 'ssh_cert', '10000000-0000-4000-8000-000000000002', '{"role":"database","region":"example-east"}');

insert into inventory.management_endpoints
  (id, server_id, protocol, address, port, network_zone, expected_identity)
values
  ('30000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000001', 'https', '192.0.2.10', 443, 'documentation-only', 'SHA256:DEMO000000000000000000000000000000000000001'),
  ('30000000-0000-4000-8000-000000000002', '20000000-0000-4000-8000-000000000002', 'ssh', '198.51.100.20', 22, 'documentation-only', 'SHA256:DEMO000000000000000000000000000000000000002');

commit;
