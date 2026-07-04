-- for testing only
CREATE TABLE IF NOT EXISTS audit_log (
    audit_table TEXT NOT NULL,
    audit_id TEXT NOT NULL,
    audit_column TEXT NOT NULL,
    old_mtime BIGINT NOT NULL,
    new_mtime BIGINT NOT NULL,
    old_signature TEXT NOT NULL UNIQUE,
    new_signature TEXT NOT NULL UNIQUE,
    details TEXT NOT NULL, -- Stored as JSON string
    insert_order BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ctime BIGINT NOT NULL DEFAULT extract(epoch from now())::bigint
);

CREATE TABLE IF NOT EXISTS orgs (
    id TEXT UNIQUE NOT NULL DEFAULT gen_random_uuid()::text,
    insert_order BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name TEXT UNIQUE NOT NULL CHECK (name != ''),
    -- see FK constraint in ALTER at end
    owner TEXT NOT NULL,

    -- common model metadata
    ctime BIGINT NOT NULL DEFAULT extract(epoch from now())::bigint,
    mtime BIGINT NOT NULL DEFAULT extract(epoch from now())::bigint,
    -- `role` == 1 is constant `Role::NORMAL`.
    -- `role` == 2 is constant `Role::ADMIN`.
    -- `role` == 3 is constant `Role::TEST`.
    role INTEGER NOT NULL CHECK (role > 0 AND role < 4),
    schema_version INTEGER NOT NULL DEFAULT 0 CHECK (schema_version >= 0 AND schema_version <= 99999),
    signature TEXT UNIQUE NOT NULL DEFAULT gen_random_uuid()::text,
    -- `status` == 1 is constant `Status::UNCONFIRMED`.
    -- `status` == 2 is constant `Status::ACTIVE`.
    -- `status` == 3 is constant `Status::INACTIVE`.
    status INTEGER NOT NULL CHECK (status > 0 AND status < 4)
    -- FOREIGN KEY (owner) REFERENCES users(id) added below via ALTER TABLE,
    -- since users references orgs and must be created after orgs.
);

CREATE OR REPLACE FUNCTION update_org_metadata() RETURNS TRIGGER AS $$
BEGIN
    NEW.mtime := extract(epoch from now())::bigint;
    NEW.signature := gen_random_uuid()::text;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER update_org_metadata BEFORE UPDATE ON orgs
FOR EACH ROW
EXECUTE FUNCTION update_org_metadata();

CREATE OR REPLACE FUNCTION org_audit_update_owner() RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO audit_log (audit_table, audit_id, audit_column, old_mtime, new_mtime, old_signature, new_signature, details)
    VALUES ('orgs', OLD.id, 'owner', OLD.mtime, NEW.mtime, OLD.signature, NEW.signature,
            jsonb_build_object('old', OLD.owner, 'new', NEW.owner)::text);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER org_audit_update_owner AFTER UPDATE OF owner ON orgs
FOR EACH ROW
WHEN (OLD.owner IS DISTINCT FROM NEW.owner)
EXECUTE FUNCTION org_audit_update_owner();

CREATE OR REPLACE FUNCTION org_audit_update_status() RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO audit_log (audit_table, audit_id, audit_column, old_mtime, new_mtime, old_signature, new_signature, details)
    VALUES ('orgs', OLD.id, 'status', OLD.mtime, NEW.mtime, OLD.signature, NEW.signature,
            jsonb_build_object('old', OLD.status, 'new', NEW.status)::text);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER org_audit_update_status AFTER UPDATE OF status ON orgs
FOR EACH ROW
WHEN (OLD.status IS DISTINCT FROM NEW.status)
EXECUTE FUNCTION org_audit_update_status();

CREATE TABLE IF NOT EXISTS users (
    ed25519_public TEXT NOT NULL CHECK (ed25519_public != ''),
    ed25519_public_digest TEXT NOT NULL CHECK (ed25519_public_digest != ''),
    display_name TEXT NOT NULL CHECK (display_name != ''),
    display_name_digest TEXT NOT NULL CHECK (display_name_digest != ''),
    email TEXT NOT NULL CHECK (email != ''),
    email_digest TEXT NOT NULL CHECK (email_digest != ''),
    encryption_key_version TEXT NOT NULL CHECK (encryption_key_version != '00000000-0000-0000-0000-000000000000'),
    id TEXT UNIQUE NOT NULL DEFAULT gen_random_uuid()::text,
    insert_order BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- see FK constraint below
    org TEXT NOT NULL,
    password TEXT NOT NULL CHECK (password LIKE '$argon2%'),

    -- common model metadata
    ctime BIGINT NOT NULL DEFAULT extract(epoch from now())::bigint,
    mtime BIGINT NOT NULL DEFAULT extract(epoch from now())::bigint,
    -- `role` == 1 is constant `Role::NORMAL`.
    -- `role` == 2 is constant `Role::ADMIN`.
    -- `role` == 3 is constant `Role::TEST`.
    role INTEGER NOT NULL CHECK (role > 0 AND role < 4),
    schema_version INTEGER NOT NULL DEFAULT 0 CHECK (schema_version >= 0 AND schema_version <= 99999),
    signature TEXT UNIQUE NOT NULL DEFAULT gen_random_uuid()::text,
    -- `status` == 1 is constant `Status::UNCONFIRMED`.
    -- `status` == 2 is constant `Status::ACTIVE`.
    -- `status` == 3 is constant `Status::INACTIVE`.
    status INTEGER NOT NULL CHECK (status > 0 AND status < 4),
    FOREIGN KEY (org) REFERENCES orgs(id)
      ON DELETE CASCADE
      DEFERRABLE INITIALLY DEFERRED
);
CREATE UNIQUE INDEX IF NOT EXISTS user_email_digest_org ON users (email_digest, org);
CREATE UNIQUE INDEX IF NOT EXISTS user_ed25519_public_digest_org ON users (ed25519_public_digest, org);

CREATE OR REPLACE FUNCTION update_user_metadata() RETURNS TRIGGER AS $$
BEGIN
    NEW.mtime := extract(epoch from now())::bigint;
    NEW.signature := gen_random_uuid()::text;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER update_user_metadata BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION update_user_metadata();

CREATE OR REPLACE FUNCTION user_audit_update_digest() RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO audit_log (audit_table, audit_id, audit_column, old_mtime, new_mtime, old_signature, new_signature, details)
    VALUES ('users', OLD.id, 'ed25519_public_digest', OLD.mtime, NEW.mtime, OLD.signature, NEW.signature,
            jsonb_build_object('old', OLD.ed25519_public_digest, 'new', NEW.ed25519_public_digest)::text);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER user_audit_update_digest AFTER UPDATE OF ed25519_public_digest ON users
FOR EACH ROW
WHEN (OLD.ed25519_public_digest IS DISTINCT FROM NEW.ed25519_public_digest)
EXECUTE FUNCTION user_audit_update_digest();

CREATE OR REPLACE FUNCTION user_audit_update_display_name() RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO audit_log (audit_table, audit_id, audit_column, old_mtime, new_mtime, old_signature, new_signature, details)
    VALUES ('users', OLD.id, 'display_name_digest', OLD.mtime, NEW.mtime, OLD.signature, NEW.signature,
            jsonb_build_object('old', OLD.display_name_digest, 'new', NEW.display_name_digest)::text);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER user_audit_update_display_name AFTER UPDATE OF display_name_digest ON users
FOR EACH ROW
WHEN (OLD.display_name_digest IS DISTINCT FROM NEW.display_name_digest)
EXECUTE FUNCTION user_audit_update_display_name();

CREATE OR REPLACE FUNCTION user_audit_update_encryption_key_version() RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO audit_log (audit_table, audit_id, audit_column, old_mtime, new_mtime, old_signature, new_signature, details)
    VALUES ('users', OLD.id, 'encryption_key_version', OLD.mtime, NEW.mtime, OLD.signature, NEW.signature,
            jsonb_build_object('old', OLD.encryption_key_version, 'new', NEW.encryption_key_version)::text);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER user_audit_update_encryption_key_version AFTER UPDATE OF encryption_key_version ON users
FOR EACH ROW
WHEN (OLD.encryption_key_version IS DISTINCT FROM NEW.encryption_key_version)
EXECUTE FUNCTION user_audit_update_encryption_key_version();

CREATE OR REPLACE FUNCTION user_audit_update_password() RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO audit_log (audit_table, audit_id, audit_column, old_mtime, new_mtime, old_signature, new_signature, details)
    VALUES ('users', OLD.id, 'password', OLD.mtime, NEW.mtime, OLD.signature, NEW.signature,
            jsonb_build_object('old', OLD.password, 'new', NEW.password)::text);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER user_audit_update_password AFTER UPDATE OF password ON users
FOR EACH ROW
WHEN (OLD.password IS DISTINCT FROM NEW.password)
EXECUTE FUNCTION user_audit_update_password();

CREATE OR REPLACE FUNCTION user_audit_update_status() RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO audit_log (audit_table, audit_id, audit_column, old_mtime, new_mtime, old_signature, new_signature, details)
    VALUES ('users', OLD.id, 'status', OLD.mtime, NEW.mtime, OLD.signature, NEW.signature,
            jsonb_build_object('old', OLD.status, 'new', NEW.status)::text);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER user_audit_update_status AFTER UPDATE OF status ON users
FOR EACH ROW
WHEN (OLD.status IS DISTINCT FROM NEW.status)
EXECUTE FUNCTION user_audit_update_status();

ALTER TABLE orgs
  ADD CONSTRAINT org_owner_fkey FOREIGN KEY (owner) REFERENCES users(id)
    ON DELETE CASCADE
    DEFERRABLE INITIALLY DEFERRED;
