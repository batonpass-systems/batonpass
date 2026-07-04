-- for testing only
create user batonpass password 'batonpass';
create role batonpass_root with superuser createdb createrole login encrypted password 'batonpass_root';
