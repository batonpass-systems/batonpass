-- for testing only
CREATE USER batonpass PASSWORD 'batonpass';
CREATE ROLE batonpass_root WITH SUPERUSER CREATEDB CREATEROLE LOGIN ENCRYPTED PASSWORD 'batonpass_root';
