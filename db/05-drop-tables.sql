-- for testing only
alter table orgs drop constraint org_owner_fkey;
drop table users;
drop table orgs;
drop table audit_log;

drop function update_org_metadata();
drop function org_audit_update_owner();
drop function org_audit_update_status();
drop function update_user_metadata();
drop function user_audit_update_digest();
drop function user_audit_update_display_name();
drop function user_audit_update_encryption_key_version();
drop function user_audit_update_password();
drop function user_audit_update_status();

