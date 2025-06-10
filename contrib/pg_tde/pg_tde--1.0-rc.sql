-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pg_tde" to load this file. \quit

CREATE FUNCTION pg_tde_add_database_key_provider(
    provider_type text,
    provider_name text,
    options json
)
    RETURNS void
    LANGUAGE c
    AS 'MODULE_PATHNAME';
REVOKE ALL ON FUNCTION pg_tde_add_database_key_provider(text, text, json) FROM PUBLIC;

CREATE FUNCTION pg_tde_add_database_key_provider_file(
    provider_name text,
    file_path text
)
    RETURNS void
    LANGUAGE sql
    BEGIN ATOMIC
        SELECT pg_tde_add_database_key_provider(
            provider_type => 'file',
            provider_name => provider_name,
            options => json_build_object('path', file_path)
        );
    END;

CREATE FUNCTION pg_tde_add_database_key_provider_vault_v2(
    provider_name text,
    vault_token_path text,
    vault_url text,
    vault_mount_path text,
    vault_ca_path text
)
    RETURNS void
    LANGUAGE sql
    BEGIN ATOMIC
        SELECT pg_tde_add_database_key_provider(
            provider_type => 'vault-v2',
            provider_name => provider_name,
            options => json_build_object(
                'url', vault_url,
                'tokenPath', vault_token_path,
                'mountPath', vault_mount_path,
                'caPath', vault_ca_path
            )
        );
    END;

CREATE FUNCTION pg_tde_add_database_key_provider_kmip(
    provider_name text,
    kmip_host text,
    kmip_port integer,
    kmip_ca_path text,
    kmip_cert_path text,
    kmip_key_path text
)
    RETURNS void
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
REVOKE ALL ON FUNCTION pg_tde_list_all_database_key_providers() FROM PUBLIC;

CREATE FUNCTION pg_tde_list_all_global_key_providers(
    OUT id integer,
    OUT provider_name text,
    OUT provider_type text,
    OUT options json
)
    RETURNS SETOF RECORD
    LANGUAGE c
    AS 'MODULE_PATHNAME';
REVOKE ALL ON FUNCTION pg_tde_list_all_global_key_providers() FROM PUBLIC;

CREATE FUNCTION pg_tde_add_global_key_provider(
    provider_type text,
    provider_name text,
    options json
)
    RETURNS void
    LANGUAGE c
    AS 'MODULE_PATHNAME';
REVOKE ALL ON FUNCTION pg_tde_add_global_key_provider(text, text, json) FROM PUBLIC;

CREATE FUNCTION pg_tde_add_global_key_provider_file(
    provider_name text,
    file_path text
)
    RETURNS void
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
    vault_token_path text,
    vault_url text,
    vault_mount_path text,
    vault_ca_path text
)
    RETURNS void
    LANGUAGE sql
    BEGIN ATOMIC
        SELECT pg_tde_add_global_key_provider(
            provider_type => 'vault-v2',
            provider_name => provider_name,
            options => json_build_object(
                'url', vault_url,
                'tokenPath', vault_token_path,
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
    RETURNS void
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

CREATE FUNCTION pg_tde_change_database_key_provider(
    provider_type text,
    provider_name text,
    options json
)
    RETURNS void
    LANGUAGE c
    AS 'MODULE_PATHNAME';
REVOKE ALL ON FUNCTION pg_tde_change_database_key_provider(text, text, json) FROM PUBLIC;

CREATE FUNCTION pg_tde_change_database_key_provider_file(
    provider_name text,
    file_path text)
    RETURNS void
    LANGUAGE sql
    BEGIN ATOMIC
        SELECT pg_tde_change_database_key_provider(
            provider_type => 'file',
            provider_name => provider_name,
            options => json_build_object('path', file_path)
        );
    END;

CREATE FUNCTION pg_tde_change_database_key_provider_vault_v2(
    provider_name text,
    vault_token_path text,
    vault_url text,
    vault_mount_path text,
    vault_ca_path text
)
    RETURNS void
    LANGUAGE sql
    BEGIN ATOMIC
        SELECT pg_tde_change_database_key_provider(
            provider_type => 'vault-v2',
            provider_name => provider_name,
            options => json_build_object(
                'url', vault_url,
                'tokenPath', vault_token_path,
                'mountPath', vault_mount_path,
                'caPath', vault_ca_path
            )
        );
    END;

CREATE FUNCTION pg_tde_change_database_key_provider_kmip(
    provider_name text,
    kmip_host text,
    kmip_port integer,
    kmip_ca_path text,
    kmip_cert_path text,
    kmip_key_path text)
RETURNS void
LANGUAGE sql
BEGIN ATOMIC
    SELECT pg_tde_change_database_key_provider(
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

CREATE FUNCTION pg_tde_change_global_key_provider(
    provider_type text,
    provider_name text,
    options json
)
    RETURNS void
    LANGUAGE c
    AS 'MODULE_PATHNAME';
REVOKE ALL ON FUNCTION pg_tde_change_global_key_provider(text, text, json) FROM PUBLIC;

CREATE FUNCTION pg_tde_change_global_key_provider_file(provider_name text, file_path text)
    RETURNS void
    LANGUAGE sql
    BEGIN ATOMIC
        SELECT pg_tde_change_global_key_provider(
            provider_type => 'file',
            provider_name => provider_name,
            options => json_build_object('path', file_path)
        );
    END;

CREATE FUNCTION pg_tde_change_global_key_provider_vault_v2(
    provider_name text,
    vault_token_path text,
    vault_url text,
    vault_mount_path text,
    vault_ca_path text
)
    RETURNS void
    LANGUAGE sql
    BEGIN ATOMIC
        SELECT pg_tde_change_global_key_provider(
            provider_type => 'vault-v2',
            provider_name => provider_name,
            options => json_build_object(
                'url', vault_url,
                'tokenPath', vault_token_path,
                'mountPath', vault_mount_path,
                'caPath', vault_ca_path
            )
        );
    END;

CREATE FUNCTION pg_tde_change_global_key_provider_kmip(
    provider_name text,
    kmip_host text,
    kmip_port integer,
    kmip_ca_path text,
    kmip_cert_path text,
    kmip_key_path text
)
    RETURNS void
    LANGUAGE sql
    BEGIN ATOMIC
        SELECT pg_tde_change_global_key_provider(
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

CREATE FUNCTION pg_tde_is_encrypted(relation regclass)
    RETURNS boolean
    LANGUAGE c
    STRICT
    AS 'MODULE_PATHNAME';

CREATE FUNCTION pg_tde_set_key_using_database_key_provider(
    key_name text,
    provider_name text,
    ensure_new_key boolean DEFAULT FALSE
)
    RETURNS void
    LANGUAGE c
    AS 'MODULE_PATHNAME';
REVOKE ALL ON FUNCTION pg_tde_set_key_using_database_key_provider(text, text, boolean) FROM PUBLIC;

CREATE FUNCTION pg_tde_set_key_using_global_key_provider(
    key_name text,
    provider_name text,
    ensure_new_key boolean DEFAULT FALSE
)
    RETURNS void
    LANGUAGE c
    AS 'MODULE_PATHNAME';
REVOKE ALL ON FUNCTION pg_tde_set_key_using_global_key_provider(text, text, boolean) FROM PUBLIC;

CREATE FUNCTION pg_tde_set_server_key_using_global_key_provider(
    key_name text,
    provider_name text,
    ensure_new_key boolean DEFAULT FALSE
)
    RETURNS void
    LANGUAGE c
    AS 'MODULE_PATHNAME';
REVOKE ALL ON FUNCTION pg_tde_set_server_key_using_global_key_provider(text, text, boolean) FROM PUBLIC;

CREATE FUNCTION pg_tde_set_default_key_using_global_key_provider(
    key_name text,
    provider_name text,
    ensure_new_key boolean DEFAULT FALSE
)
    RETURNS void
    LANGUAGE c
    AS 'MODULE_PATHNAME';
REVOKE ALL ON FUNCTION pg_tde_set_default_key_using_global_key_provider(text, text, boolean) FROM PUBLIC;

CREATE FUNCTION pg_tde_verify_key()
    RETURNS void
    LANGUAGE c
    AS 'MODULE_PATHNAME';
REVOKE ALL ON FUNCTION pg_tde_verify_key() FROM PUBLIC;

CREATE FUNCTION pg_tde_verify_server_key()
    RETURNS void
    LANGUAGE c
    AS 'MODULE_PATHNAME';
REVOKE ALL ON FUNCTION pg_tde_verify_server_key() FROM PUBLIC;

CREATE FUNCTION pg_tde_verify_default_key()
    RETURNS void
    LANGUAGE c
    AS 'MODULE_PATHNAME';
REVOKE ALL ON FUNCTION pg_tde_verify_default_key() FROM PUBLIC;

CREATE FUNCTION pg_tde_key_info()
    RETURNS TABLE (
        key_name text,
        key_provider_name text,
        key_provider_id integer,
        key_creation_time timestamptz
    )
    LANGUAGE c
    AS 'MODULE_PATHNAME';
REVOKE ALL ON FUNCTION pg_tde_key_info() FROM PUBLIC;

CREATE FUNCTION pg_tde_server_key_info()
    RETURNS TABLE (
        key_name text,
        key_provider_name text,
        key_provider_id integer,
        key_creation_time timestamptz
    )
    LANGUAGE c
    AS 'MODULE_PATHNAME';
REVOKE ALL ON FUNCTION pg_tde_server_key_info() FROM PUBLIC;

CREATE FUNCTION pg_tde_default_key_info()
    RETURNS TABLE (
        key_name text,
        key_provider_name text,
        key_provider_id integer,
        key_creation_time timestamptz
    )
    LANGUAGE c
    AS 'MODULE_PATHNAME';
REVOKE ALL ON FUNCTION pg_tde_default_key_info() FROM PUBLIC;

CREATE FUNCTION pg_tde_delete_global_key_provider(provider_name text)
    RETURNS void
    LANGUAGE c
    AS 'MODULE_PATHNAME';
REVOKE ALL ON FUNCTION pg_tde_delete_global_key_provider(text) FROM PUBLIC;

CREATE FUNCTION pg_tde_delete_database_key_provider(provider_name text)
    RETURNS void
    LANGUAGE c
    AS 'MODULE_PATHNAME';
REVOKE ALL ON FUNCTION pg_tde_delete_database_key_provider(text) FROM PUBLIC;

CREATE FUNCTION pg_tde_version()
    RETURNS text
    LANGUAGE c
    AS 'MODULE_PATHNAME';

CREATE FUNCTION pg_tdeam_handler(internal)
    RETURNS table_am_handler
    LANGUAGE c
    AS 'MODULE_PATHNAME';
REVOKE ALL ON FUNCTION pg_tdeam_handler(internal) FROM PUBLIC;

CREATE ACCESS METHOD tde_heap TYPE TABLE HANDLER pg_tdeam_handler;
COMMENT ON ACCESS METHOD tde_heap IS 'tde_heap table access method';

CREATE FUNCTION pg_tde_ddl_command_start_capture()
    RETURNS event_trigger
    LANGUAGE c
    AS 'MODULE_PATHNAME';
REVOKE ALL ON FUNCTION pg_tde_ddl_command_start_capture() FROM PUBLIC;

CREATE EVENT TRIGGER pg_tde_ddl_start
    ON ddl_command_start
    EXECUTE FUNCTION pg_tde_ddl_command_start_capture();
ALTER EVENT TRIGGER pg_tde_ddl_start ENABLE ALWAYS;

CREATE FUNCTION pg_tde_ddl_command_end_capture()
    RETURNS event_trigger
    LANGUAGE c
    AS 'MODULE_PATHNAME';
REVOKE ALL ON FUNCTION pg_tde_ddl_command_end_capture() FROM PUBLIC;

CREATE EVENT TRIGGER pg_tde_ddl_end
    ON ddl_command_end
    EXECUTE FUNCTION pg_tde_ddl_command_end_capture();
ALTER EVENT TRIGGER pg_tde_ddl_end ENABLE ALWAYS;

CREATE FUNCTION pg_tde_extension_initialize()
    RETURNS void
    LANGUAGE c
    AS 'MODULE_PATHNAME';
SELECT pg_tde_extension_initialize();
DROP FUNCTION pg_tde_extension_initialize();
