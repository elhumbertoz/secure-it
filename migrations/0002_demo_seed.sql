begin;

insert into inventory.access_profiles
  (id, name, connection_mode, allowed_environments, max_ttl_seconds, privilege_level)
values
  ('10000000-0000-4000-8000-000000000001', 'linux-readonly-local-agent', 'local_agent', array['dev','test'], 300, 'readonly'),
  ('10000000-0000-4000-8000-000000000002', 'linux-readonly-ssh-ca', 'ssh_cert', array['dev','test','staging'], 300, 'readonly');

commit;
