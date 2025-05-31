/* contrib/pg_tde/pg_tde--1.0-rc.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pg_tde" to load this file. \quit

-- Key Provider Management
CREATE FUNCTION pg_tde_add_database_key_provider(
    provider_type text,
    provider_name text,
    options json
)
    RETURNS VOID
    LANGUAGE c
    AS 'MODULE_PATHNAME';

CREATE FUNCTION pg_tde_add_database_key_provider_file(
    provider_name text,
    file_path text
)
    RETURNS VOID
    LANGUAGE sql
    BEGIN ATOMIC
        SELECT pg_tde_add_database_key_provider(
            provider_type => 'file',
            provider_name => provider_name,
            options => json_build_object('path', file_path)
        );
    END;

CREATE FUNCTION pg_tde_add_database_key_provider_file(
    provider_name text,
    file_path json
)
    RETURNS VOID
    LANGUAGE sql
    BEGIN ATOMIC
        SELECT pg_tde_add_database_key_provider(
            type => 'file',
            provider_name => provider_name,
            options => json_build_object('path', file_path)
        );
    END;

CREATE FUNCTION pg_tde_add_database_key_provider_vault_v2(
    provider_name text,
    vault_token text,
    vault_url text,
    vault_mount_path text,
    vault_ca_path text
)
    RETURNS VOID
    LANGUAGE sql
    BEGIN ATOMIC
        SELECT pg_tde_add_database_key_provider(
            provider_type => 'vault-v2',
            provider_name => provider_name,
            options => json_build_object(
                'url', coalesce(vault_url, ''),
                'token', coalesce(vault_token, ''),
                'mountPath', coalesce(vault_mount_path, ''),
                'caPath' coalesce(vault_ca_path, '')
            )
        );
    END;

CREATE FUNCTION pg_tde_add_database_key_provider_vault_v2(
    provider_name text,
    vault_token json,
    vault_url json,
    vault_mount_path json,
    vault_ca_path json
)
    RETURNS VOID
    LANGUAGE sql
    BEGIN ATOMIC
        SELECT pg_tde_add_database_key_provider(
            provider_type => 'vault-v2',
            provider_name => provider_name,
            options => json_build_object(
                'url', vault_url,
                'token', vault_token,
                'mountPath', vault_mount_path,
                'caPath', vault_ca_path));
    END;

CREATE FUNCTION pg_tde_add_database_key_provider_kmip(
    provider_name text,
    kmip_host text,
    kmip_port integer,
    kmip_ca_path text,
    kmip_cert_path text,
    kmip_key_path text
)
    RETURNS VOID
    LANGUAGE sql
    BEGIN ATOMIC
        SELECT pg_tde_add_database_key_provider(
            provider_type => 'kmip',
            provider_name => provider_name,
            options => json_build_object(
                'host', coalesce(kmip_host, ''),
                'port', kmip_port,
                'caPath', coalesce(kmip_ca_path, ''),
                'certPath', coalesce(kmip_cert_path, ''),
                'keyPath', coalesce(kmip_key_path, '')
            )
        );
    END;

CREATE FUNCTION pg_tde_add_database_key_provider_kmip(
    provider_name text,
    kmip_host json,
    kmip_port json,
    kmip_ca_path json,
    kmip_cert_path json,
    kmip_key_path json
)
    RETURNS VOID
    LANGUAGE sql
    BEGIN ATOMIC
        SELECT pg_tde_add_database_key_provider(
            provider_type => 'kmip',
            provider_name => provider_name,
            options => json_build_object(
                'host', kmip_host,
                'port', kmip_port,
                'caPath', kmip_ca_path,
                'certPath', kmip_cert_path,
                'keyPath', kmip_key_path
            )
        );
    END;

CREATE FUNCTION pg_tde_list_all_database_key_providers(
    OUT id integer,
    OUT provider_name text,
    OUT provider_type text,
    OUT options json
)
    RETURNS SETOF RECORD
    LANGUAGE c
    AS 'MODULE_PATHNAME';

CREATE FUNCTION pg_tde_list_all_global_key_providers(
    OUT id integer,
    OUT provider_name text,
    OUT provider_type text,
    OUT options json
)
    RETURNS SETOF RECORD
    LANGUAGE c
    AS 'MODULE_PATHNAME';

-- Global Tablespace Key Provider Management
CREATE FUNCTION pg_tde_add_global_key_provider(provider_type text, provider_name text, options json)
    RETURNS VOID
    LANGUAGE c
    AS 'MODULE_PATHNAME';

CREATE FUNCTION pg_tde_add_global_key_provider_file(provider_name text, file_path text)
    RETURNS VOID
    LANGUAGE sql
    BEGIN ATOMIC
        SELECT pg_tde_add_global_key_provider(
            provider_type => 'file',
            provider_name => provider_name,
            options => json_build_object('path', coalesce(file_path, ''))
        );
    END;

CREATE FUNCTION pg_tde_add_global_key_provider_file(provider_name text, file_path json)
    RETURNS VOID
    LANGUAGE sql
    BEGIN ATOMIC
        SELECT pg_tde_add_global_key_provider(
            provider_type => 'file',
            provider_name => provider_name,
            options => json_build_object('path', file_path)
        );
    END;

CREATE FUNCTION pg_tde_add_global_key_provider_vault_v2(
    provider_name text,
    vault_token text,
    vault_url text,
    vault_mount_path text,
    vault_ca_path text
)
    RETURNS VOID
    LANGUAGE sql
    BEGIN ATOMIC
        SELECT pg_tde_add_global_key_provider(
            provider_type => 'vault-v2',
            provider_name => provider_name,
            options => json_build_object(
                'url', coalesce(vault_url, ''),
                'token', coalesce(vault_token, ''),
                'mountPath', coalesce(vault_mount_path, ''),
                'caPath', coalesce(vault_ca_path, '')
            )
        );
    END;

CREATE FUNCTION pg_tde_add_global_key_provider_vault_v2(
    provider_name text,
    vault_token json,
    vault_url json,
    vault_mount_path json,
    vault_ca_path json
)
    RETURNS VOID
    LANGUAGE sql
    BEGIN ATOMIC
        SELECT pg_tde_add_global_key_provider(
            provider_type => 'vault-v2',
            provider_name => provider_name,
            options => json_build_object(
                'url', vault_url,
                'token', vault_token,
                'mountPath', vault_mount_path,
                'caPath', vault_ca_path
            )
        );
    END;

CREATE FUNCTION pg_tde_add_global_key_provider_kmip(
    provider_name text,
    kmip_host text,
    kmip_port integer,
    kmip_ca_path text,
    kmip_cert_path text,
    kmip_key_path text
)
    RETURNS VOID
    LANGUAGE sql
    BEGIN ATOMIC
        SELECT pg_tde_add_global_key_provider(
            provider_type => 'kmip',
            provider_name => provider_name,
            options => json_build_object(
                'host', coalesce(kmip_host, ''),
                'port', kmip_port,
                'caPath', coalesce(kmip_ca_path, ''),
                'certPath', coalesce(kmip_cert_path, ''),
                'keyPath', coalesce(kmip_key_path, '')
            )
        );
    END;

CREATE FUNCTION pg_tde_add_global_key_provider_kmip(
    provider_name text,
    kmip_host json,
    kmip_port json,
    kmip_ca_path json,
    kmip_cert_path json,
    kmip_key_path json
)
    RETURNS VOID
    LANGUAGE sql
    BEGIN ATOMIC
        SELECT pg_tde_add_global_key_provider(
            provider_type => 'kmip',
            provider_name => provider_name,
            options => json_build_object(
                'host', kmip_host,
                'port', kmip_port,
                'caPath', kmip_ca_path,
                'certPath', kmip_cert_path,
                'keyPath', kmip_key_path
            )
        );
    END;

-- Key Provider Management
CREATE FUNCTION pg_tde_change_database_key_provider(provider_type text, provider_name text, options json)
    RETURNS VOID
    LANGUAGE c
    AS 'MODULE_PATHNAME';

CREATE FUNCTION pg_tde_change_database_key_provider_file(provider_name text, file_path text)
    RETURNS VOID
    LANGUAGE sql
    BEGIN ATOMIC
         SELECT pg_tde_change_database_key_provider('file', provider_name,
                    json_build_object('path', coalesce(file_path, '')));
    END;

CREATE FUNCTION pg_tde_change_database_key_provider_file(provider_name text, file_path json)
RETURNS VOID
LANGUAGE sql
BEGIN ATOMIC
    -- json keys in the options must be matched to the keys in
    -- load_file_keyring_provider_options function.
    SELECT pg_tde_change_database_key_provider('file', provider_name,
                json_build_object('path', file_path));
END;

CREATE FUNCTION pg_tde_change_database_key_provider_vault_v2(provider_name text,
                                                    vault_token text,
                                                    vault_url text,
                                                    vault_mount_path text,
                                                    vault_ca_path text)
RETURNS VOID
LANGUAGE sql
BEGIN ATOMIC
    -- json keys in the options must be matched to the keys in
    -- load_vaultV2_keyring_provider_options function.
    SELECT pg_tde_change_database_key_provider('vault-v2', provider_name,
                            json_build_object('url', coalesce(vault_url, ''),
                            'token', coalesce(vault_token, ''),
                            'mountPath', coalesce(vault_mount_path, ''),
                            'caPath', coalesce(vault_ca_path, '')));
END;

CREATE FUNCTION pg_tde_change_database_key_provider_vault_v2(provider_name text,
                                                    vault_token json,
                                                    vault_url json,
                                                    vault_mount_path json,
                                                    vault_ca_path json)
RETURNS VOID
LANGUAGE sql
BEGIN ATOMIC
    -- json keys in the options must be matched to the keys in
    -- load_vaultV2_keyring_provider_options function.
    SELECT pg_tde_change_database_key_provider('vault-v2', provider_name,
                            json_build_object('url', vault_url,
                            'token', vault_token,
                            'mountPath', vault_mount_path,
                            'caPath', vault_ca_path));
END;

CREATE FUNCTION pg_tde_change_database_key_provider_kmip(provider_name text,
                                                kmip_host text,
                                                kmip_port integer,
                                                kmip_ca_path text,
                                                kmip_cert_path text,
                                                kmip_key_path text)
RETURNS VOID
LANGUAGE sql
BEGIN ATOMIC
    -- json keys in the options must be matched to the keys in
    -- load_kmip_keyring_provider_options function.
    SELECT pg_tde_change_database_key_provider('kmip', provider_name,
                            json_build_object('host', coalesce(kmip_host, ''),
                            'port', kmip_port,
                            'caPath', coalesce(kmip_ca_path, ''),
                            'certPath', coalesce(kmip_cert_path, ''),
                            'keyPath', coalesce(kmip_key_path, '')));
END;

CREATE FUNCTION pg_tde_change_database_key_provider_kmip(provider_name text,
                                                kmip_host json,
                                                kmip_port json,
                                                kmip_ca_path json,
                                                kmip_cert_path json,
                                                kmip_key_path json)
RETURNS VOID
LANGUAGE sql
BEGIN ATOMIC
    -- json keys in the options must be matched to the keys in
    -- load_kmip_keyring_provider_options function.
    SELECT pg_tde_change_database_key_provider('kmip', provider_name,
                            json_build_object('host', kmip_host,
                            'port', kmip_port,
                            'caPath', kmip_ca_path,
                            'certPath', kmip_cert_path,
                            'keyPath', kmip_key_path));
END;

-- Global Tablespace Key Provider Management
CREATE FUNCTION pg_tde_change_global_key_provider(provider_type text, provider_name text, options json)
RETURNS VOID
LANGUAGE c
AS 'MODULE_PATHNAME';

CREATE FUNCTION pg_tde_change_global_key_provider_file(provider_name text, file_path text)
RETURNS VOID
LANGUAGE sql
BEGIN ATOMIC
    -- json keys in the options must be matched to the keys in
    -- load_file_keyring_provider_options function.
    SELECT pg_tde_change_global_key_provider('file', provider_name,
                json_build_object('path', coalesce(file_path, '')));
END;

CREATE FUNCTION pg_tde_change_global_key_provider_file(provider_name text, file_path json)
RETURNS VOID
LANGUAGE sql
BEGIN ATOMIC
    -- json keys in the options must be matched to the keys in
    -- load_file_keyring_provider_options function.
    SELECT pg_tde_change_global_key_provider('file', provider_name,
                json_build_object('path', file_path));
END;

CREATE FUNCTION pg_tde_change_global_key_provider_vault_v2(provider_name text,
                                                           vault_token text,
                                                           vault_url text,
                                                           vault_mount_path text,
                                                           vault_ca_path text)
RETURNS VOID
LANGUAGE sql
BEGIN ATOMIC
    -- json keys in the options must be matched to the keys in
    -- load_vaultV2_keyring_provider_options function.
    SELECT pg_tde_change_global_key_provider('vault-v2', provider_name,
                            json_build_object('url', coalesce(vault_url, ''),
                            'token', coalesce(vault_token, ''),
                            'mountPath', coalesce(vault_mount_path, ''),
                            'caPath', coalesce(vault_ca_path, '')));
END;

CREATE FUNCTION pg_tde_change_global_key_provider_vault_v2(provider_name text,
                                                           vault_token json,
                                                           vault_url json,
                                                           vault_mount_path json,
                                                           vault_ca_path json)
RETURNS VOID
LANGUAGE sql
BEGIN ATOMIC
    -- json keys in the options must be matched to the keys in
    -- load_vaultV2_keyring_provider_options function.
    SELECT pg_tde_change_global_key_provider('vault-v2', provider_name,
                            json_build_object('url', vault_url,
                            'token', vault_token,
                            'mountPath', vault_mount_path,
                            'caPath', vault_ca_path));
END;

CREATE FUNCTION pg_tde_change_global_key_provider_kmip(provider_name text,
                                                       kmip_host text,
                                                       kmip_port integer,
                                                       kmip_ca_path text,
                                                       kmip_cert_path text,
                                                       kmip_key_path text)
RETURNS VOID
LANGUAGE sql
BEGIN ATOMIC
    -- json keys in the options must be matched to the keys in
    -- load_kmip_keyring_provider_options function.
    SELECT pg_tde_change_global_key_provider('kmip', provider_name,
                            json_build_object('host', coalesce(kmip_host, ''),
                            'port', kmip_port,
                            'caPath', coalesce(kmip_ca_path, ''),
                            'certPath', coalesce(kmip_cert_path, ''),
                            'keyPath', coalesce(kmip_key_path, '')));
END;

CREATE FUNCTION pg_tde_change_global_key_provider_kmip(provider_name text,
                                                       kmip_host json,
                                                       kmip_port json,
                                                       kmip_ca_path json,
                                                       kmip_cert_path json,
                                                       kmip_key_path json)
RETURNS VOID
LANGUAGE sql
BEGIN ATOMIC
    -- json keys in the options must be matched to the keys in
    -- load_kmip_keyring_provider_options function.
    SELECT pg_tde_change_global_key_provider('vault-v2', provider_name,
                            json_build_object('host', kmip_host,
                            'port', kmip_port,
                            'caPath', kmip_ca_path,
                            'certPath', kmip_cert_path,
                            'keyPath', kmip_key_path));
END;

CREATE FUNCTION pg_tde_is_encrypted(relation REGCLASS)
RETURNS BOOLEAN
STRICT
LANGUAGE c
AS 'MODULE_PATHNAME';

CREATE FUNCTION pg_tde_set_key_using_database_key_provider(key_name text, provider_name text DEFAULT NULL, ensure_new_key BOOLEAN DEFAULT FALSE)
RETURNS VOID
LANGUAGE c
AS 'MODULE_PATHNAME';

CREATE FUNCTION pg_tde_set_key_using_global_key_provider(key_name text, provider_name text DEFAULT NULL, ensure_new_key BOOLEAN DEFAULT FALSE)
RETURNS VOID
LANGUAGE c
AS 'MODULE_PATHNAME';

CREATE FUNCTION pg_tde_set_server_key_using_global_key_provider(key_name text, provider_name text DEFAULT NULL, ensure_new_key BOOLEAN DEFAULT FALSE)
RETURNS VOID
LANGUAGE c
AS 'MODULE_PATHNAME';

CREATE FUNCTION pg_tde_set_default_key_using_global_key_provider(key_name text, provider_name text DEFAULT NULL, ensure_new_key BOOLEAN DEFAULT FALSE)
RETURNS VOID
AS 'MODULE_PATHNAME'
LANGUAGE c;

CREATE FUNCTION pg_tde_verify_key()
RETURNS VOID
LANGUAGE c
AS 'MODULE_PATHNAME';

CREATE FUNCTION pg_tde_verify_server_key()
RETURNS VOID
LANGUAGE c
AS 'MODULE_PATHNAME';

CREATE FUNCTION pg_tde_verify_default_key()
RETURNS VOID
LANGUAGE c
AS 'MODULE_PATHNAME';

CREATE FUNCTION pg_tde_key_info()
RETURNS TABLE ( key_name text,
                key_provider_name text,
                key_provider_id integer,
                key_creation_time timestamptz)
LANGUAGE c
AS 'MODULE_PATHNAME';

CREATE FUNCTION pg_tde_server_key_info()
RETURNS TABLE ( key_name text,
                key_provider_name text,
                key_provider_id integer,
                key_creation_time timestamptz)
LANGUAGE c
AS 'MODULE_PATHNAME';

CREATE FUNCTION pg_tde_default_key_info()
RETURNS TABLE ( key_name text,
                key_provider_name text,
                key_provider_id integer,
                key_creation_time timestamptz)
LANGUAGE c
AS 'MODULE_PATHNAME';

CREATE FUNCTION pg_tde_delete_global_key_provider(provider_name text)
RETURNS VOID
LANGUAGE c
AS 'MODULE_PATHNAME';

CREATE FUNCTION pg_tde_delete_database_key_provider(provider_name text)
RETURNS VOID
LANGUAGE c
AS 'MODULE_PATHNAME';

CREATE FUNCTION pg_tde_version()
    RETURNS text
    LANGUAGE c
    AS 'MODULE_PATHNAME';

-- Table access method
CREATE FUNCTION pg_tdeam_handler(internal)
RETURNS TABLE_AM_HANDLER
LANGUAGE c
AS 'MODULE_PATHNAME';

CREATE ACCESS METHOD tde_heap TYPE TABLE HANDLER pg_tdeam_handler;
COMMENT ON ACCESS METHOD tde_heap IS 'tde_heap table access method';

CREATE FUNCTION pg_tde_ddl_command_start_capture()
RETURNS EVENT_TRIGGER
LANGUAGE c
AS 'MODULE_PATHNAME';

CREATE FUNCTION pg_tde_ddl_command_end_capture()
RETURNS EVENT_TRIGGER
LANGUAGE c
AS 'MODULE_PATHNAME';

CREATE EVENT TRIGGER pg_tde_ddl_start
ON ddl_command_start
EXECUTE FUNCTION pg_tde_ddl_command_start_capture();
ALTER EVENT TRIGGER pg_tde_ddl_start ENABLE ALWAYS;

CREATE EVENT TRIGGER pg_tde_ddl_end
ON ddl_command_end
EXECUTE FUNCTION pg_tde_ddl_command_end_capture();
ALTER EVENT TRIGGER pg_tde_ddl_end ENABLE ALWAYS;

-- Per database extension initialization
CREATE FUNCTION pg_tde_extension_initialize()
RETURNS VOID
LANGUAGE c
AS 'MODULE_PATHNAME';
SELECT pg_tde_extension_initialize();
DROP FUNCTION pg_tde_extension_initialize();

CREATE FUNCTION pg_tde_grant_database_key_management_to_role(
    target_role text)
RETURNS VOID
LANGUAGE plpgsql
SET search_path = @extschema@
AS $$
BEGIN
    EXECUTE format('GRANT EXECUTE ON FUNCTION pg_tde_set_key_using_database_key_provider(text, text, BOOLEAN) TO %I', target_role);
END;
$$;

CREATE FUNCTION pg_tde_grant_key_viewer_to_role(
    target_role text)
RETURNS VOID
LANGUAGE plpgsql
SET search_path = @extschema@
AS $$
BEGIN
    EXECUTE format('GRANT EXECUTE ON FUNCTION pg_tde_list_all_database_key_providers() TO %I', target_role);
    EXECUTE format('GRANT EXECUTE ON FUNCTION pg_tde_list_all_global_key_providers() TO %I', target_role);

    EXECUTE format('GRANT EXECUTE ON FUNCTION pg_tde_key_info() TO %I', target_role);
    EXECUTE format('GRANT EXECUTE ON FUNCTION pg_tde_server_key_info() TO %I', target_role);
    EXECUTE format('GRANT EXECUTE ON FUNCTION pg_tde_default_key_info() TO %I', target_role);

    EXECUTE format('GRANT EXECUTE ON FUNCTION pg_tde_verify_key() TO %I', target_role);
    EXECUTE format('GRANT EXECUTE ON FUNCTION pg_tde_verify_server_key() TO %I', target_role);
    EXECUTE format('GRANT EXECUTE ON FUNCTION pg_tde_verify_default_key() TO %I', target_role);
END;
$$;

CREATE FUNCTION pg_tde_revoke_database_key_management_from_role(
    target_role text)
RETURNS VOID
LANGUAGE plpgsql
SET search_path = @extschema@
AS $$
BEGIN
    EXECUTE format('REVOKE EXECUTE ON FUNCTION pg_tde_set_key_using_database_key_provider(text, text, BOOLEAN) FROM %I', target_role);
END;
$$;

CREATE FUNCTION pg_tde_revoke_key_viewer_from_role(
    target_role text)
RETURNS VOID
LANGUAGE plpgsql
SET search_path = @extschema@
AS $$
BEGIN
    EXECUTE format('REVOKE EXECUTE ON FUNCTION pg_tde_list_all_database_key_providers() FROM %I', target_role);
    EXECUTE format('REVOKE EXECUTE ON FUNCTION pg_tde_list_all_global_key_providers() FROM %I', target_role);

    EXECUTE format('REVOKE EXECUTE ON FUNCTION pg_tde_key_info() FROM %I', target_role);
    EXECUTE format('REVOKE EXECUTE ON FUNCTION pg_tde_server_key_info() FROM %I', target_role);
    EXECUTE format('REVOKE EXECUTE ON FUNCTION pg_tde_default_key_info() FROM %I', target_role);

    EXECUTE format('REVOKE EXECUTE ON FUNCTION pg_tde_verify_key() FROM %I', target_role);
    EXECUTE format('REVOKE EXECUTE ON FUNCTION pg_tde_verify_server_key() FROM %I', target_role);
    EXECUTE format('REVOKE EXECUTE ON FUNCTION pg_tde_verify_default_key() FROM %I', target_role);
END;
$$;

-- Revoking all the privileges from the public role
SELECT pg_tde_revoke_database_key_management_from_role('public');
SELECT pg_tde_revoke_key_viewer_from_role('public');
