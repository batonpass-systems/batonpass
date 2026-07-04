-- for testing only
ALTER TABLE orgs DROP CONSTRAINT org_owner_fkey;
DROP TABLE users;
DROP TABLE orgs;
DROP TABLE audit_log;

DROP FUNCTION update_org_metadata();
DROP FUNCTION org_audit_update_owner();
DROP FUNCTION org_audit_update_status();
DROP FUNCTION update_user_metadata();
DROP FUNCTION user_audit_update_digest();
DROP FUNCTION user_audit_update_display_name();
DROP FUNCTION user_audit_update_encryption_key_version();
DROP FUNCTION user_audit_update_password();
DROP FUNCTION user_audit_update_status();

