SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: auth; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA auth;


--
-- Name: extensions; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA extensions;


--
-- Name: graphql; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA graphql;


--
-- Name: graphql_public; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA graphql_public;


--
-- Name: pgbouncer; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA pgbouncer;


--
-- Name: pgsodium; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA pgsodium;


--
-- Name: pgsodium; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgsodium WITH SCHEMA pgsodium;


--
-- Name: EXTENSION pgsodium; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pgsodium IS 'Pgsodium is a modern cryptography library for Postgres.';


--
-- Name: realtime; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA realtime;


--
-- Name: storage; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA storage;


--
-- Name: vault; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA vault;


--
-- Name: pg_graphql; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pg_graphql WITH SCHEMA graphql;


--
-- Name: EXTENSION pg_graphql; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pg_graphql IS 'pg_graphql: GraphQL support';


--
-- Name: pg_stat_statements; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pg_stat_statements WITH SCHEMA extensions;


--
-- Name: EXTENSION pg_stat_statements; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pg_stat_statements IS 'track planning and execution statistics of all SQL statements executed';


--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA extensions;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- Name: pgjwt; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgjwt WITH SCHEMA extensions;


--
-- Name: EXTENSION pgjwt; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pgjwt IS 'JSON Web Token API for Postgresql';


--
-- Name: supabase_vault; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS supabase_vault WITH SCHEMA vault;


--
-- Name: EXTENSION supabase_vault; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION supabase_vault IS 'Supabase Vault Extension';


--
-- Name: uuid-ossp; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA extensions;


--
-- Name: EXTENSION "uuid-ossp"; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION "uuid-ossp" IS 'generate universally unique identifiers (UUIDs)';


--
-- Name: aal_level; Type: TYPE; Schema: auth; Owner: -
--

CREATE TYPE auth.aal_level AS ENUM (
    'aal1',
    'aal2',
    'aal3'
);


--
-- Name: code_challenge_method; Type: TYPE; Schema: auth; Owner: -
--

CREATE TYPE auth.code_challenge_method AS ENUM (
    's256',
    'plain'
);


--
-- Name: factor_status; Type: TYPE; Schema: auth; Owner: -
--

CREATE TYPE auth.factor_status AS ENUM (
    'unverified',
    'verified'
);


--
-- Name: factor_type; Type: TYPE; Schema: auth; Owner: -
--

CREATE TYPE auth.factor_type AS ENUM (
    'totp',
    'webauthn'
);


--
-- Name: email(); Type: FUNCTION; Schema: auth; Owner: -
--

CREATE FUNCTION auth.email() RETURNS text
    LANGUAGE sql STABLE
    AS $$
  select 
  coalesce(
    nullif(current_setting('request.jwt.claim.email', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'email')
  )::text
$$;


--
-- Name: FUNCTION email(); Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON FUNCTION auth.email() IS 'Deprecated. Use auth.jwt() -> ''email'' instead.';


--
-- Name: jwt(); Type: FUNCTION; Schema: auth; Owner: -
--

CREATE FUNCTION auth.jwt() RETURNS jsonb
    LANGUAGE sql STABLE
    AS $$
  select 
    coalesce(
        nullif(current_setting('request.jwt.claim', true), ''),
        nullif(current_setting('request.jwt.claims', true), '')
    )::jsonb
$$;


--
-- Name: role(); Type: FUNCTION; Schema: auth; Owner: -
--

CREATE FUNCTION auth.role() RETURNS text
    LANGUAGE sql STABLE
    AS $$
  select 
  coalesce(
    nullif(current_setting('request.jwt.claim.role', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'role')
  )::text
$$;


--
-- Name: FUNCTION role(); Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON FUNCTION auth.role() IS 'Deprecated. Use auth.jwt() -> ''role'' instead.';


--
-- Name: uid(); Type: FUNCTION; Schema: auth; Owner: -
--

CREATE FUNCTION auth.uid() RETURNS uuid
    LANGUAGE sql STABLE
    AS $$
  select 
  coalesce(
    nullif(current_setting('request.jwt.claim.sub', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub')
  )::uuid
$$;


--
-- Name: FUNCTION uid(); Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON FUNCTION auth.uid() IS 'Deprecated. Use auth.jwt() -> ''sub'' instead.';


--
-- Name: grant_pg_cron_access(); Type: FUNCTION; Schema: extensions; Owner: -
--

CREATE FUNCTION extensions.grant_pg_cron_access() RETURNS event_trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF EXISTS (
    SELECT
    FROM pg_event_trigger_ddl_commands() AS ev
    JOIN pg_extension AS ext
    ON ev.objid = ext.oid
    WHERE ext.extname = 'pg_cron'
  )
  THEN
    grant usage on schema cron to postgres with grant option;

    alter default privileges in schema cron grant all on tables to postgres with grant option;
    alter default privileges in schema cron grant all on functions to postgres with grant option;
    alter default privileges in schema cron grant all on sequences to postgres with grant option;

    alter default privileges for user supabase_admin in schema cron grant all
        on sequences to postgres with grant option;
    alter default privileges for user supabase_admin in schema cron grant all
        on tables to postgres with grant option;
    alter default privileges for user supabase_admin in schema cron grant all
        on functions to postgres with grant option;

    grant all privileges on all tables in schema cron to postgres with grant option;
    revoke all on table cron.job from postgres;
    grant select on table cron.job to postgres with grant option;
  END IF;
END;
$$;


--
-- Name: FUNCTION grant_pg_cron_access(); Type: COMMENT; Schema: extensions; Owner: -
--

COMMENT ON FUNCTION extensions.grant_pg_cron_access() IS 'Grants access to pg_cron';


--
-- Name: grant_pg_graphql_access(); Type: FUNCTION; Schema: extensions; Owner: -
--

CREATE FUNCTION extensions.grant_pg_graphql_access() RETURNS event_trigger
    LANGUAGE plpgsql
    AS $_$
DECLARE
    func_is_graphql_resolve bool;
BEGIN
    func_is_graphql_resolve = (
        SELECT n.proname = 'resolve'
        FROM pg_event_trigger_ddl_commands() AS ev
        LEFT JOIN pg_catalog.pg_proc AS n
        ON ev.objid = n.oid
    );

    IF func_is_graphql_resolve
    THEN
        -- Update public wrapper to pass all arguments through to the pg_graphql resolve func
        DROP FUNCTION IF EXISTS graphql_public.graphql;
        create or replace function graphql_public.graphql(
            "operationName" text default null,
            query text default null,
            variables jsonb default null,
            extensions jsonb default null
        )
            returns jsonb
            language sql
        as $$
            select graphql.resolve(
                query := query,
                variables := coalesce(variables, '{}'),
                "operationName" := "operationName",
                extensions := extensions
            );
        $$;

        -- This hook executes when `graphql.resolve` is created. That is not necessarily the last
        -- function in the extension so we need to grant permissions on existing entities AND
        -- update default permissions to any others that are created after `graphql.resolve`
        grant usage on schema graphql to postgres, anon, authenticated, service_role;
        grant select on all tables in schema graphql to postgres, anon, authenticated, service_role;
        grant execute on all functions in schema graphql to postgres, anon, authenticated, service_role;
        grant all on all sequences in schema graphql to postgres, anon, authenticated, service_role;
        alter default privileges in schema graphql grant all on tables to postgres, anon, authenticated, service_role;
        alter default privileges in schema graphql grant all on functions to postgres, anon, authenticated, service_role;
        alter default privileges in schema graphql grant all on sequences to postgres, anon, authenticated, service_role;

        -- Allow postgres role to allow granting usage on graphql and graphql_public schemas to custom roles
        grant usage on schema graphql_public to postgres with grant option;
        grant usage on schema graphql to postgres with grant option;
    END IF;

END;
$_$;


--
-- Name: FUNCTION grant_pg_graphql_access(); Type: COMMENT; Schema: extensions; Owner: -
--

COMMENT ON FUNCTION extensions.grant_pg_graphql_access() IS 'Grants access to pg_graphql';


--
-- Name: grant_pg_net_access(); Type: FUNCTION; Schema: extensions; Owner: -
--

CREATE FUNCTION extensions.grant_pg_net_access() RETURNS event_trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM pg_event_trigger_ddl_commands() AS ev
    JOIN pg_extension AS ext
    ON ev.objid = ext.oid
    WHERE ext.extname = 'pg_net'
  )
  THEN
    IF NOT EXISTS (
      SELECT 1
      FROM pg_roles
      WHERE rolname = 'supabase_functions_admin'
    )
    THEN
      CREATE USER supabase_functions_admin NOINHERIT CREATEROLE LOGIN NOREPLICATION;
    END IF;

    GRANT USAGE ON SCHEMA net TO supabase_functions_admin, postgres, anon, authenticated, service_role;

    ALTER function net.http_get(url text, params jsonb, headers jsonb, timeout_milliseconds integer) SECURITY DEFINER;
    ALTER function net.http_post(url text, body jsonb, params jsonb, headers jsonb, timeout_milliseconds integer) SECURITY DEFINER;

    ALTER function net.http_get(url text, params jsonb, headers jsonb, timeout_milliseconds integer) SET search_path = net;
    ALTER function net.http_post(url text, body jsonb, params jsonb, headers jsonb, timeout_milliseconds integer) SET search_path = net;

    REVOKE ALL ON FUNCTION net.http_get(url text, params jsonb, headers jsonb, timeout_milliseconds integer) FROM PUBLIC;
    REVOKE ALL ON FUNCTION net.http_post(url text, body jsonb, params jsonb, headers jsonb, timeout_milliseconds integer) FROM PUBLIC;

    GRANT EXECUTE ON FUNCTION net.http_get(url text, params jsonb, headers jsonb, timeout_milliseconds integer) TO supabase_functions_admin, postgres, anon, authenticated, service_role;
    GRANT EXECUTE ON FUNCTION net.http_post(url text, body jsonb, params jsonb, headers jsonb, timeout_milliseconds integer) TO supabase_functions_admin, postgres, anon, authenticated, service_role;
  END IF;
END;
$$;


--
-- Name: FUNCTION grant_pg_net_access(); Type: COMMENT; Schema: extensions; Owner: -
--

COMMENT ON FUNCTION extensions.grant_pg_net_access() IS 'Grants access to pg_net';


--
-- Name: pgrst_ddl_watch(); Type: FUNCTION; Schema: extensions; Owner: -
--

CREATE FUNCTION extensions.pgrst_ddl_watch() RETURNS event_trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
  cmd record;
BEGIN
  FOR cmd IN SELECT * FROM pg_event_trigger_ddl_commands()
  LOOP
    IF cmd.command_tag IN (
      'CREATE SCHEMA', 'ALTER SCHEMA'
    , 'CREATE TABLE', 'CREATE TABLE AS', 'SELECT INTO', 'ALTER TABLE'
    , 'CREATE FOREIGN TABLE', 'ALTER FOREIGN TABLE'
    , 'CREATE VIEW', 'ALTER VIEW'
    , 'CREATE MATERIALIZED VIEW', 'ALTER MATERIALIZED VIEW'
    , 'CREATE FUNCTION', 'ALTER FUNCTION'
    , 'CREATE TRIGGER'
    , 'CREATE TYPE', 'ALTER TYPE'
    , 'CREATE RULE'
    , 'COMMENT'
    )
    -- don't notify in case of CREATE TEMP table or other objects created on pg_temp
    AND cmd.schema_name is distinct from 'pg_temp'
    THEN
      NOTIFY pgrst, 'reload schema';
    END IF;
  END LOOP;
END; $$;


--
-- Name: pgrst_drop_watch(); Type: FUNCTION; Schema: extensions; Owner: -
--

CREATE FUNCTION extensions.pgrst_drop_watch() RETURNS event_trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
  obj record;
BEGIN
  FOR obj IN SELECT * FROM pg_event_trigger_dropped_objects()
  LOOP
    IF obj.object_type IN (
      'schema'
    , 'table'
    , 'foreign table'
    , 'view'
    , 'materialized view'
    , 'function'
    , 'trigger'
    , 'type'
    , 'rule'
    )
    AND obj.is_temporary IS false -- no pg_temp objects
    THEN
      NOTIFY pgrst, 'reload schema';
    END IF;
  END LOOP;
END; $$;


--
-- Name: set_graphql_placeholder(); Type: FUNCTION; Schema: extensions; Owner: -
--

CREATE FUNCTION extensions.set_graphql_placeholder() RETURNS event_trigger
    LANGUAGE plpgsql
    AS $_$
    DECLARE
    graphql_is_dropped bool;
    BEGIN
    graphql_is_dropped = (
        SELECT ev.schema_name = 'graphql_public'
        FROM pg_event_trigger_dropped_objects() AS ev
        WHERE ev.schema_name = 'graphql_public'
    );

    IF graphql_is_dropped
    THEN
        create or replace function graphql_public.graphql(
            "operationName" text default null,
            query text default null,
            variables jsonb default null,
            extensions jsonb default null
        )
            returns jsonb
            language plpgsql
        as $$
            DECLARE
                server_version float;
            BEGIN
                server_version = (SELECT (SPLIT_PART((select version()), ' ', 2))::float);

                IF server_version >= 14 THEN
                    RETURN jsonb_build_object(
                        'errors', jsonb_build_array(
                            jsonb_build_object(
                                'message', 'pg_graphql extension is not enabled.'
                            )
                        )
                    );
                ELSE
                    RETURN jsonb_build_object(
                        'errors', jsonb_build_array(
                            jsonb_build_object(
                                'message', 'pg_graphql is only available on projects running Postgres 14 onwards.'
                            )
                        )
                    );
                END IF;
            END;
        $$;
    END IF;

    END;
$_$;


--
-- Name: FUNCTION set_graphql_placeholder(); Type: COMMENT; Schema: extensions; Owner: -
--

COMMENT ON FUNCTION extensions.set_graphql_placeholder() IS 'Reintroduces placeholder function for graphql_public.graphql';


--
-- Name: get_auth(text); Type: FUNCTION; Schema: pgbouncer; Owner: -
--

CREATE FUNCTION pgbouncer.get_auth(p_usename text) RETURNS TABLE(username text, password text)
    LANGUAGE plpgsql SECURITY DEFINER
    AS $$
BEGIN
    RAISE WARNING 'PgBouncer auth request: %', p_usename;

    RETURN QUERY
    SELECT usename::TEXT, passwd::TEXT FROM pg_catalog.pg_shadow
    WHERE usename = p_usename;
END;
$$;


--
-- Name: check_block_imported_at(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.check_block_imported_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
          BEGIN
            IF NEW.imported_at IS NOT NULL THEN
              IF EXISTS (
                SELECT 1
                FROM eth_blocks
                WHERE block_number < NEW.block_number
                  AND imported_at IS NULL
                LIMIT 1
              ) THEN
                RAISE EXCEPTION 'Previous block not yet imported';
              END IF;
            END IF;
            RETURN NEW;
          END;
          $$;


--
-- Name: check_block_order(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.check_block_order() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
          BEGIN
            IF NEW.is_genesis_block = false AND 
              NEW.block_number <> (SELECT MAX(block_number) + 1 FROM eth_blocks) THEN
              RAISE EXCEPTION 'Block number is not sequential';
            END IF;

            IF NEW.is_genesis_block = false AND 
              NEW.parent_blockhash <> (SELECT blockhash FROM eth_blocks WHERE block_number = NEW.block_number - 1) THEN
              RAISE EXCEPTION 'Parent block hash does not match the parent''s block hash';
            END IF;

            RETURN NEW;
          END;
          $$;


--
-- Name: check_block_order_on_update(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.check_block_order_on_update() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF NEW.imported_at IS NOT NULL AND NEW.state_hash IS NULL THEN
    RAISE EXCEPTION 'state_hash must be set when imported_at is set';
  END IF;

  IF NEW.is_genesis_block = false AND 
    NEW.parent_state_hash <> (SELECT state_hash FROM eth_blocks WHERE block_number = NEW.block_number - 1 AND imported_at IS NOT NULL) THEN
    RAISE EXCEPTION 'Parent state hash does not match the state hash of the previous block';
  END IF;

  RETURN NEW;
END;
$$;


--
-- Name: check_ethscription_order_and_sequence(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.check_ethscription_order_and_sequence() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
          BEGIN
            IF NEW.block_number < (SELECT MAX(block_number) FROM ethscriptions) OR
            (NEW.block_number = (SELECT MAX(block_number) FROM ethscriptions) AND NEW.transaction_index <= (SELECT MAX(transaction_index) FROM ethscriptions WHERE block_number = NEW.block_number)) THEN
              RAISE EXCEPTION 'Ethscriptions must be created in order';
            END IF;
            NEW.ethscription_number := (SELECT COALESCE(MAX(ethscription_number), -1) + 1 FROM ethscriptions);
            RETURN NEW;
          END;
          $$;


--
-- Name: delete_later_blocks(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.delete_later_blocks() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
          BEGIN
            DELETE FROM eth_blocks WHERE block_number > OLD.block_number;
            RETURN OLD;
          END;
          $$;


--
-- Name: update_current_owner(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.update_current_owner() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
          DECLARE
            latest_ownership_version RECORD;
          BEGIN
            IF TG_OP = 'INSERT' THEN
              SELECT INTO latest_ownership_version *
              FROM ethscription_ownership_versions
              WHERE ethscription_transaction_hash = NEW.ethscription_transaction_hash
              ORDER BY block_number DESC, transaction_index DESC, transfer_index DESC
              LIMIT 1;

              UPDATE ethscriptions
              SET current_owner = latest_ownership_version.current_owner,
                  previous_owner = latest_ownership_version.previous_owner,
                  updated_at = NOW()
              WHERE transaction_hash = NEW.ethscription_transaction_hash;
            ELSIF TG_OP = 'DELETE' THEN
              SELECT INTO latest_ownership_version *
              FROM ethscription_ownership_versions
              WHERE ethscription_transaction_hash = OLD.ethscription_transaction_hash
                AND id != OLD.id
              ORDER BY block_number DESC, transaction_index DESC, transfer_index DESC
              LIMIT 1;

              UPDATE ethscriptions
              SET current_owner = latest_ownership_version.current_owner,
                  previous_owner = latest_ownership_version.previous_owner,
                  updated_at = NOW()
              WHERE transaction_hash = OLD.ethscription_transaction_hash;
            END IF;

            RETURN NULL;
          END;
          $$;


--
-- Name: update_token_balances_and_supply(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.update_token_balances_and_supply() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
      DECLARE
        latest_token_state RECORD;
      BEGIN
        IF TG_OP = 'INSERT' THEN
          SELECT INTO latest_token_state *
          FROM token_states
          WHERE deploy_ethscription_transaction_hash = NEW.deploy_ethscription_transaction_hash
          ORDER BY block_number DESC
          LIMIT 1;

          UPDATE tokens
          SET balances = COALESCE(latest_token_state.balances, '{}'::jsonb),
              total_supply = COALESCE(latest_token_state.total_supply, 0),
              updated_at = NOW()
          WHERE deploy_ethscription_transaction_hash = NEW.deploy_ethscription_transaction_hash;
        ELSIF TG_OP = 'DELETE' THEN
          SELECT INTO latest_token_state *
          FROM token_states
          WHERE deploy_ethscription_transaction_hash = OLD.deploy_ethscription_transaction_hash
            AND id != OLD.id
          ORDER BY block_number DESC
          LIMIT 1;

          UPDATE tokens
          SET balances = COALESCE(latest_token_state.balances, '{}'::jsonb),
              total_supply = COALESCE(latest_token_state.total_supply, 0),
              updated_at = NOW()
          WHERE deploy_ethscription_transaction_hash = OLD.deploy_ethscription_transaction_hash;
        END IF;

        RETURN NULL;
      END;
      $$;


--
-- Name: can_insert_object(text, text, uuid, jsonb); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.can_insert_object(bucketid text, name text, owner uuid, metadata jsonb) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
  INSERT INTO "storage"."objects" ("bucket_id", "name", "owner", "metadata") VALUES (bucketid, name, owner, metadata);
  -- hack to rollback the successful insert
  RAISE sqlstate 'PT200' using
  message = 'ROLLBACK',
  detail = 'rollback successful insert';
END
$$;


--
-- Name: extension(text); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.extension(name text) RETURNS text
    LANGUAGE plpgsql
    AS $$
DECLARE
_parts text[];
_filename text;
BEGIN
	select string_to_array(name, '/') into _parts;
	select _parts[array_length(_parts,1)] into _filename;
	-- @todo return the last part instead of 2
	return reverse(split_part(reverse(_filename), '.', 1));
END
$$;


--
-- Name: filename(text); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.filename(name text) RETURNS text
    LANGUAGE plpgsql
    AS $$
DECLARE
_parts text[];
BEGIN
	select string_to_array(name, '/') into _parts;
	return _parts[array_length(_parts,1)];
END
$$;


--
-- Name: foldername(text); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.foldername(name text) RETURNS text[]
    LANGUAGE plpgsql
    AS $$
DECLARE
_parts text[];
BEGIN
	select string_to_array(name, '/') into _parts;
	return _parts[1:array_length(_parts,1)-1];
END
$$;


--
-- Name: get_size_by_bucket(); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.get_size_by_bucket() RETURNS TABLE(size bigint, bucket_id text)
    LANGUAGE plpgsql
    AS $$
BEGIN
    return query
        select sum((metadata->>'size')::int) as size, obj.bucket_id
        from "storage".objects as obj
        group by obj.bucket_id;
END
$$;


--
-- Name: search(text, text, integer, integer, integer, text, text, text); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.search(prefix text, bucketname text, limits integer DEFAULT 100, levels integer DEFAULT 1, offsets integer DEFAULT 0, search text DEFAULT ''::text, sortcolumn text DEFAULT 'name'::text, sortorder text DEFAULT 'asc'::text) RETURNS TABLE(name text, id uuid, updated_at timestamp with time zone, created_at timestamp with time zone, last_accessed_at timestamp with time zone, metadata jsonb)
    LANGUAGE plpgsql STABLE
    AS $_$
declare
  v_order_by text;
  v_sort_order text;
begin
  case
    when sortcolumn = 'name' then
      v_order_by = 'name';
    when sortcolumn = 'updated_at' then
      v_order_by = 'updated_at';
    when sortcolumn = 'created_at' then
      v_order_by = 'created_at';
    when sortcolumn = 'last_accessed_at' then
      v_order_by = 'last_accessed_at';
    else
      v_order_by = 'name';
  end case;

  case
    when sortorder = 'asc' then
      v_sort_order = 'asc';
    when sortorder = 'desc' then
      v_sort_order = 'desc';
    else
      v_sort_order = 'asc';
  end case;

  v_order_by = v_order_by || ' ' || v_sort_order;

  return query execute
    'with folders as (
       select path_tokens[$1] as folder
       from storage.objects
         where objects.name ilike $2 || $3 || ''%''
           and bucket_id = $4
           and array_length(regexp_split_to_array(objects.name, ''/''), 1) <> $1
       group by folder
       order by folder ' || v_sort_order || '
     )
     (select folder as "name",
            null as id,
            null as updated_at,
            null as created_at,
            null as last_accessed_at,
            null as metadata from folders)
     union all
     (select path_tokens[$1] as "name",
            id,
            updated_at,
            created_at,
            last_accessed_at,
            metadata
     from storage.objects
     where objects.name ilike $2 || $3 || ''%''
       and bucket_id = $4
       and array_length(regexp_split_to_array(objects.name, ''/''), 1) = $1
     order by ' || v_order_by || ')
     limit $5
     offset $6' using levels, prefix, search, bucketname, limits, offsets;
end;
$_$;


--
-- Name: update_updated_at_column(); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.update_updated_at_column() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW; 
END;
$$;


--
-- Name: secrets_encrypt_secret_secret(); Type: FUNCTION; Schema: vault; Owner: -
--

CREATE FUNCTION vault.secrets_encrypt_secret_secret() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
		BEGIN
		        new.secret = CASE WHEN new.secret IS NULL THEN NULL ELSE
			CASE WHEN new.key_id IS NULL THEN NULL ELSE pg_catalog.encode(
			  pgsodium.crypto_aead_det_encrypt(
				pg_catalog.convert_to(new.secret, 'utf8'),
				pg_catalog.convert_to((new.id::text || new.description::text || new.created_at::text || new.updated_at::text)::text, 'utf8'),
				new.key_id::uuid,
				new.nonce
			  ),
				'base64') END END;
		RETURN new;
		END;
		$$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: audit_log_entries; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.audit_log_entries (
    instance_id uuid,
    id uuid NOT NULL,
    payload json,
    created_at timestamp with time zone,
    ip_address character varying(64) DEFAULT ''::character varying NOT NULL
);


--
-- Name: TABLE audit_log_entries; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.audit_log_entries IS 'Auth: Audit trail for user actions.';


--
-- Name: flow_state; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.flow_state (
    id uuid NOT NULL,
    user_id uuid,
    auth_code text NOT NULL,
    code_challenge_method auth.code_challenge_method NOT NULL,
    code_challenge text NOT NULL,
    provider_type text NOT NULL,
    provider_access_token text,
    provider_refresh_token text,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    authentication_method text NOT NULL
);


--
-- Name: TABLE flow_state; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.flow_state IS 'stores metadata for pkce logins';


--
-- Name: identities; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.identities (
    provider_id text NOT NULL,
    user_id uuid NOT NULL,
    identity_data jsonb NOT NULL,
    provider text NOT NULL,
    last_sign_in_at timestamp with time zone,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    email text GENERATED ALWAYS AS (lower((identity_data ->> 'email'::text))) STORED,
    id uuid DEFAULT gen_random_uuid() NOT NULL
);


--
-- Name: TABLE identities; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.identities IS 'Auth: Stores identities associated to a user.';


--
-- Name: COLUMN identities.email; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON COLUMN auth.identities.email IS 'Auth: Email is a generated column that references the optional email property in the identity_data';


--
-- Name: instances; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.instances (
    id uuid NOT NULL,
    uuid uuid,
    raw_base_config text,
    created_at timestamp with time zone,
    updated_at timestamp with time zone
);


--
-- Name: TABLE instances; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.instances IS 'Auth: Manages users across multiple sites.';


--
-- Name: mfa_amr_claims; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.mfa_amr_claims (
    session_id uuid NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    authentication_method text NOT NULL,
    id uuid NOT NULL
);


--
-- Name: TABLE mfa_amr_claims; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.mfa_amr_claims IS 'auth: stores authenticator method reference claims for multi factor authentication';


--
-- Name: mfa_challenges; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.mfa_challenges (
    id uuid NOT NULL,
    factor_id uuid NOT NULL,
    created_at timestamp with time zone NOT NULL,
    verified_at timestamp with time zone,
    ip_address inet NOT NULL
);


--
-- Name: TABLE mfa_challenges; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.mfa_challenges IS 'auth: stores metadata about challenge requests made';


--
-- Name: mfa_factors; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.mfa_factors (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    friendly_name text,
    factor_type auth.factor_type NOT NULL,
    status auth.factor_status NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    secret text
);


--
-- Name: TABLE mfa_factors; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.mfa_factors IS 'auth: stores metadata about factors';


--
-- Name: refresh_tokens; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.refresh_tokens (
    instance_id uuid,
    id bigint NOT NULL,
    token character varying(255),
    user_id character varying(255),
    revoked boolean,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    parent character varying(255),
    session_id uuid
);


--
-- Name: TABLE refresh_tokens; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.refresh_tokens IS 'Auth: Store of tokens used to refresh JWT tokens once they expire.';


--
-- Name: refresh_tokens_id_seq; Type: SEQUENCE; Schema: auth; Owner: -
--

CREATE SEQUENCE auth.refresh_tokens_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: refresh_tokens_id_seq; Type: SEQUENCE OWNED BY; Schema: auth; Owner: -
--

ALTER SEQUENCE auth.refresh_tokens_id_seq OWNED BY auth.refresh_tokens.id;


--
-- Name: saml_providers; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.saml_providers (
    id uuid NOT NULL,
    sso_provider_id uuid NOT NULL,
    entity_id text NOT NULL,
    metadata_xml text NOT NULL,
    metadata_url text,
    attribute_mapping jsonb,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    CONSTRAINT "entity_id not empty" CHECK ((char_length(entity_id) > 0)),
    CONSTRAINT "metadata_url not empty" CHECK (((metadata_url = NULL::text) OR (char_length(metadata_url) > 0))),
    CONSTRAINT "metadata_xml not empty" CHECK ((char_length(metadata_xml) > 0))
);


--
-- Name: TABLE saml_providers; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.saml_providers IS 'Auth: Manages SAML Identity Provider connections.';


--
-- Name: saml_relay_states; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.saml_relay_states (
    id uuid NOT NULL,
    sso_provider_id uuid NOT NULL,
    request_id text NOT NULL,
    for_email text,
    redirect_to text,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    flow_state_id uuid,
    CONSTRAINT "request_id not empty" CHECK ((char_length(request_id) > 0))
);


--
-- Name: TABLE saml_relay_states; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.saml_relay_states IS 'Auth: Contains SAML Relay State information for each Service Provider initiated login.';


--
-- Name: schema_migrations; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.schema_migrations (
    version character varying(255) NOT NULL
);


--
-- Name: TABLE schema_migrations; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.schema_migrations IS 'Auth: Manages updates to the auth system.';


--
-- Name: sessions; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.sessions (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    factor_id uuid,
    aal auth.aal_level,
    not_after timestamp with time zone,
    refreshed_at timestamp without time zone,
    user_agent text,
    ip inet,
    tag text
);


--
-- Name: TABLE sessions; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.sessions IS 'Auth: Stores session data associated to a user.';


--
-- Name: COLUMN sessions.not_after; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON COLUMN auth.sessions.not_after IS 'Auth: Not after is a nullable column that contains a timestamp after which the session should be regarded as expired.';


--
-- Name: sso_domains; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.sso_domains (
    id uuid NOT NULL,
    sso_provider_id uuid NOT NULL,
    domain text NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    CONSTRAINT "domain not empty" CHECK ((char_length(domain) > 0))
);


--
-- Name: TABLE sso_domains; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.sso_domains IS 'Auth: Manages SSO email address domain mapping to an SSO Identity Provider.';


--
-- Name: sso_providers; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.sso_providers (
    id uuid NOT NULL,
    resource_id text,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    CONSTRAINT "resource_id not empty" CHECK (((resource_id = NULL::text) OR (char_length(resource_id) > 0)))
);


--
-- Name: TABLE sso_providers; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.sso_providers IS 'Auth: Manages SSO identity provider information; see saml_providers for SAML.';


--
-- Name: COLUMN sso_providers.resource_id; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON COLUMN auth.sso_providers.resource_id IS 'Auth: Uniquely identifies a SSO provider according to a user-chosen resource ID (case insensitive), useful in infrastructure as code.';


--
-- Name: users; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.users (
    instance_id uuid,
    id uuid NOT NULL,
    aud character varying(255),
    role character varying(255),
    email character varying(255),
    encrypted_password character varying(255),
    email_confirmed_at timestamp with time zone,
    invited_at timestamp with time zone,
    confirmation_token character varying(255),
    confirmation_sent_at timestamp with time zone,
    recovery_token character varying(255),
    recovery_sent_at timestamp with time zone,
    email_change_token_new character varying(255),
    email_change character varying(255),
    email_change_sent_at timestamp with time zone,
    last_sign_in_at timestamp with time zone,
    raw_app_meta_data jsonb,
    raw_user_meta_data jsonb,
    is_super_admin boolean,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    phone text DEFAULT NULL::character varying,
    phone_confirmed_at timestamp with time zone,
    phone_change text DEFAULT ''::character varying,
    phone_change_token character varying(255) DEFAULT ''::character varying,
    phone_change_sent_at timestamp with time zone,
    confirmed_at timestamp with time zone GENERATED ALWAYS AS (LEAST(email_confirmed_at, phone_confirmed_at)) STORED,
    email_change_token_current character varying(255) DEFAULT ''::character varying,
    email_change_confirm_status smallint DEFAULT 0,
    banned_until timestamp with time zone,
    reauthentication_token character varying(255) DEFAULT ''::character varying,
    reauthentication_sent_at timestamp with time zone,
    is_sso_user boolean DEFAULT false NOT NULL,
    deleted_at timestamp with time zone,
    is_anonymous boolean DEFAULT false NOT NULL,
    CONSTRAINT users_email_change_confirm_status_check CHECK (((email_change_confirm_status >= 0) AND (email_change_confirm_status <= 2)))
);


--
-- Name: TABLE users; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.users IS 'Auth: Stores user login data within a secure schema.';


--
-- Name: COLUMN users.is_sso_user; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON COLUMN auth.users.is_sso_user IS 'Auth: Set this column to true when the account comes from SSO. These accounts can have duplicate emails.';


--
-- Name: ar_internal_metadata; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ar_internal_metadata (
    key character varying NOT NULL,
    value character varying,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL
);


--
-- Name: eth_blocks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.eth_blocks (
    id bigint NOT NULL,
    block_number bigint NOT NULL,
    "timestamp" bigint NOT NULL,
    blockhash character varying NOT NULL,
    parent_blockhash character varying NOT NULL,
    imported_at timestamp(6) without time zone,
    state_hash character varying,
    parent_state_hash character varying,
    is_genesis_block boolean NOT NULL,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL,
    CONSTRAINT chk_rails_1c105acdac CHECK (((parent_blockhash)::text ~ '^0x[a-f0-9]{64}$'::text)),
    CONSTRAINT chk_rails_319237323b CHECK (((state_hash)::text ~ '^0x[a-f0-9]{64}$'::text)),
    CONSTRAINT chk_rails_7126b7c9d3 CHECK (((parent_state_hash)::text ~ '^0x[a-f0-9]{64}$'::text)),
    CONSTRAINT chk_rails_7e9881ece2 CHECK (((blockhash)::text ~ '^0x[a-f0-9]{64}$'::text))
);


--
-- Name: eth_blocks_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.eth_blocks_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: eth_blocks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.eth_blocks_id_seq OWNED BY public.eth_blocks.id;


--
-- Name: eth_transactions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.eth_transactions (
    id bigint NOT NULL,
    transaction_hash character varying NOT NULL,
    block_number bigint NOT NULL,
    block_timestamp bigint NOT NULL,
    block_blockhash character varying NOT NULL,
    from_address character varying NOT NULL,
    to_address character varying,
    input text NOT NULL,
    transaction_index bigint NOT NULL,
    status integer,
    logs jsonb DEFAULT '[]'::jsonb NOT NULL,
    created_contract_address character varying,
    gas_price numeric NOT NULL,
    gas_used bigint NOT NULL,
    transaction_fee numeric NOT NULL,
    value numeric NOT NULL,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL,
    CONSTRAINT chk_rails_37ed5d6017 CHECK (((to_address)::text ~ '^0x[a-f0-9]{40}$'::text)),
    CONSTRAINT chk_rails_4250f2c315 CHECK (((block_blockhash)::text ~ '^0x[a-f0-9]{64}$'::text)),
    CONSTRAINT chk_rails_9cdbd3b1ad CHECK (((transaction_hash)::text ~ '^0x[a-f0-9]{64}$'::text)),
    CONSTRAINT chk_rails_a4d3f41974 CHECK (((from_address)::text ~ '^0x[a-f0-9]{40}$'::text)),
    CONSTRAINT chk_rails_d460e80110 CHECK (((created_contract_address)::text ~ '^0x[a-f0-9]{40}$'::text)),
    CONSTRAINT contract_to_check CHECK ((((created_contract_address IS NULL) AND (to_address IS NOT NULL)) OR ((created_contract_address IS NOT NULL) AND (to_address IS NULL)))),
    CONSTRAINT status_check CHECK ((((block_number <= 4370000) AND (status IS NULL)) OR ((block_number > 4370000) AND (status = 1))))
);


--
-- Name: eth_transactions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.eth_transactions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: eth_transactions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.eth_transactions_id_seq OWNED BY public.eth_transactions.id;


--
-- Name: ethscription_ownership_versions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ethscription_ownership_versions (
    id bigint NOT NULL,
    transaction_hash character varying NOT NULL,
    ethscription_transaction_hash character varying NOT NULL,
    transfer_index bigint NOT NULL,
    block_number bigint NOT NULL,
    block_blockhash character varying NOT NULL,
    transaction_index bigint NOT NULL,
    block_timestamp bigint NOT NULL,
    current_owner character varying NOT NULL,
    previous_owner character varying NOT NULL,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL,
    CONSTRAINT chk_rails_0401bc8d3b CHECK (((transaction_hash)::text ~ '^0x[a-f0-9]{64}$'::text)),
    CONSTRAINT chk_rails_073cb8a4e9 CHECK (((current_owner)::text ~ '^0x[a-f0-9]{40}$'::text)),
    CONSTRAINT chk_rails_3c5af30513 CHECK (((block_blockhash)::text ~ '^0x[a-f0-9]{64}$'::text)),
    CONSTRAINT chk_rails_b5b3ce91a9 CHECK (((previous_owner)::text ~ '^0x[a-f0-9]{40}$'::text)),
    CONSTRAINT chk_rails_f8a9e94d3c CHECK (((ethscription_transaction_hash)::text ~ '^0x[a-f0-9]{64}$'::text))
);


--
-- Name: ethscription_ownership_versions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ethscription_ownership_versions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ethscription_ownership_versions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ethscription_ownership_versions_id_seq OWNED BY public.ethscription_ownership_versions.id;


--
-- Name: ethscription_transfers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ethscription_transfers (
    id bigint NOT NULL,
    ethscription_transaction_hash character varying NOT NULL,
    transaction_hash character varying NOT NULL,
    from_address character varying NOT NULL,
    to_address character varying NOT NULL,
    block_number bigint NOT NULL,
    block_timestamp bigint NOT NULL,
    block_blockhash character varying NOT NULL,
    event_log_index bigint,
    transfer_index bigint NOT NULL,
    transaction_index bigint NOT NULL,
    enforced_previous_owner character varying,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL,
    CONSTRAINT chk_rails_1c9802c481 CHECK (((enforced_previous_owner)::text ~ '^0x[a-f0-9]{40}$'::text)),
    CONSTRAINT chk_rails_448edb0194 CHECK (((block_blockhash)::text ~ '^0x[a-f0-9]{64}$'::text)),
    CONSTRAINT chk_rails_7959eeae60 CHECK (((from_address)::text ~ '^0x[a-f0-9]{40}$'::text)),
    CONSTRAINT chk_rails_7f4ef1507d CHECK (((transaction_hash)::text ~ '^0x[a-f0-9]{64}$'::text)),
    CONSTRAINT chk_rails_a138317254 CHECK (((to_address)::text ~ '^0x[a-f0-9]{40}$'::text))
);


--
-- Name: ethscription_transfers_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ethscription_transfers_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ethscription_transfers_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ethscription_transfers_id_seq OWNED BY public.ethscription_transfers.id;


--
-- Name: ethscriptions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ethscriptions (
    id bigint NOT NULL,
    transaction_hash character varying NOT NULL,
    block_number bigint NOT NULL,
    transaction_index bigint NOT NULL,
    block_timestamp bigint NOT NULL,
    block_blockhash character varying NOT NULL,
    event_log_index bigint,
    ethscription_number bigint NOT NULL,
    creator character varying NOT NULL,
    initial_owner character varying NOT NULL,
    current_owner character varying NOT NULL,
    previous_owner character varying NOT NULL,
    content_uri text NOT NULL,
    content_sha character varying NOT NULL,
    esip6 boolean NOT NULL,
    mimetype character varying(1000) NOT NULL,
    media_type character varying(1000) NOT NULL,
    mime_subtype character varying(1000) NOT NULL,
    gas_price numeric NOT NULL,
    gas_used bigint NOT NULL,
    transaction_fee numeric NOT NULL,
    value numeric NOT NULL,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL,
    CONSTRAINT chk_rails_52497428f2 CHECK (((previous_owner)::text ~ '^0x[a-f0-9]{40}$'::text)),
    CONSTRAINT chk_rails_528fcbfbaa CHECK (((content_sha)::text ~ '^0x[a-f0-9]{64}$'::text)),
    CONSTRAINT chk_rails_6f8922831e CHECK (((current_owner)::text ~ '^0x[a-f0-9]{40}$'::text)),
    CONSTRAINT chk_rails_788fa87594 CHECK (((block_blockhash)::text ~ '^0x[a-f0-9]{64}$'::text)),
    CONSTRAINT chk_rails_84591e2730 CHECK (((transaction_hash)::text ~ '^0x[a-f0-9]{64}$'::text)),
    CONSTRAINT chk_rails_b577b97822 CHECK (((creator)::text ~ '^0x[a-f0-9]{40}$'::text)),
    CONSTRAINT chk_rails_df21fdbe02 CHECK (((initial_owner)::text ~ '^0x[a-f0-9]{40}$'::text))
);


--
-- Name: ethscriptions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ethscriptions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ethscriptions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ethscriptions_id_seq OWNED BY public.ethscriptions.id;


--
-- Name: schema_migrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.schema_migrations (
    version character varying NOT NULL
);


--
-- Name: token_items; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.token_items (
    id bigint NOT NULL,
    ethscription_transaction_hash character varying NOT NULL,
    deploy_ethscription_transaction_hash character varying NOT NULL,
    block_number bigint NOT NULL,
    transaction_index bigint NOT NULL,
    token_item_id bigint NOT NULL,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL,
    CONSTRAINT chk_rails_37f43f9259 CHECK (((deploy_ethscription_transaction_hash)::text ~ '^0x[a-f0-9]{64}$'::text)),
    CONSTRAINT chk_rails_4a492d2c53 CHECK ((token_item_id > 0)),
    CONSTRAINT chk_rails_4e045edbe2 CHECK (((ethscription_transaction_hash)::text ~ '^0x[a-f0-9]{64}$'::text))
);


--
-- Name: token_items_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.token_items_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: token_items_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.token_items_id_seq OWNED BY public.token_items.id;


--
-- Name: token_states; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.token_states (
    id bigint NOT NULL,
    block_number bigint NOT NULL,
    block_timestamp bigint NOT NULL,
    block_blockhash character varying NOT NULL,
    deploy_ethscription_transaction_hash character varying NOT NULL,
    balances jsonb DEFAULT '{}'::jsonb NOT NULL,
    total_supply bigint DEFAULT 0 NOT NULL,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL,
    CONSTRAINT chk_rails_8b7e9525c6 CHECK (((deploy_ethscription_transaction_hash)::text ~ '^0x[a-f0-9]{64}$'::text)),
    CONSTRAINT chk_rails_97e78ee6f4 CHECK (((block_blockhash)::text ~ '^0x[a-f0-9]{64}$'::text))
);


--
-- Name: token_states_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.token_states_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: token_states_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.token_states_id_seq OWNED BY public.token_states.id;


--
-- Name: tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tokens (
    id bigint NOT NULL,
    deploy_ethscription_transaction_hash character varying NOT NULL,
    deploy_block_number bigint NOT NULL,
    deploy_transaction_index bigint NOT NULL,
    protocol character varying(1000) NOT NULL,
    tick character varying(1000) NOT NULL,
    max_supply bigint NOT NULL,
    total_supply bigint DEFAULT 0 NOT NULL,
    mint_amount bigint NOT NULL,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL,
    balances jsonb DEFAULT '{}'::jsonb NOT NULL,
    CONSTRAINT chk_rails_31c1808af4 CHECK (((tick)::text ~ '^[[:alnum:]p{Emoji_Presentation}]+$'::text)),
    CONSTRAINT chk_rails_3458514b65 CHECK (((deploy_ethscription_transaction_hash)::text ~ '^0x[a-f0-9]{64}$'::text)),
    CONSTRAINT chk_rails_3d55d7040f CHECK (((max_supply % mint_amount) = 0)),
    CONSTRAINT chk_rails_53ece3f224 CHECK ((total_supply <= max_supply)),
    CONSTRAINT chk_rails_596664ed3b CHECK ((total_supply >= 0)),
    CONSTRAINT chk_rails_b41faadd12 CHECK ((mint_amount > 0)),
    CONSTRAINT chk_rails_e954152758 CHECK ((max_supply > 0)),
    CONSTRAINT chk_rails_f38f6eac6d CHECK (((protocol)::text ~ '^[a-z0-9-]+$'::text))
);


--
-- Name: tokens_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.tokens_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: tokens_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.tokens_id_seq OWNED BY public.tokens.id;


--
-- Name: buckets; Type: TABLE; Schema: storage; Owner: -
--

CREATE TABLE storage.buckets (
    id text NOT NULL,
    name text NOT NULL,
    owner uuid,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    public boolean DEFAULT false,
    avif_autodetection boolean DEFAULT false,
    file_size_limit bigint,
    allowed_mime_types text[],
    owner_id text
);


--
-- Name: COLUMN buckets.owner; Type: COMMENT; Schema: storage; Owner: -
--

COMMENT ON COLUMN storage.buckets.owner IS 'Field is deprecated, use owner_id instead';


--
-- Name: migrations; Type: TABLE; Schema: storage; Owner: -
--

CREATE TABLE storage.migrations (
    id integer NOT NULL,
    name character varying(100) NOT NULL,
    hash character varying(40) NOT NULL,
    executed_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: objects; Type: TABLE; Schema: storage; Owner: -
--

CREATE TABLE storage.objects (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    bucket_id text,
    name text,
    owner uuid,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    last_accessed_at timestamp with time zone DEFAULT now(),
    metadata jsonb,
    path_tokens text[] GENERATED ALWAYS AS (string_to_array(name, '/'::text)) STORED,
    version text,
    owner_id text
);


--
-- Name: COLUMN objects.owner; Type: COMMENT; Schema: storage; Owner: -
--

COMMENT ON COLUMN storage.objects.owner IS 'Field is deprecated, use owner_id instead';


--
-- Name: decrypted_secrets; Type: VIEW; Schema: vault; Owner: -
--

CREATE VIEW vault.decrypted_secrets AS
 SELECT secrets.id,
    secrets.name,
    secrets.description,
    secrets.secret,
        CASE
            WHEN (secrets.secret IS NULL) THEN NULL::text
            ELSE
            CASE
                WHEN (secrets.key_id IS NULL) THEN NULL::text
                ELSE convert_from(pgsodium.crypto_aead_det_decrypt(decode(secrets.secret, 'base64'::text), convert_to(((((secrets.id)::text || secrets.description) || (secrets.created_at)::text) || (secrets.updated_at)::text), 'utf8'::name), secrets.key_id, secrets.nonce), 'utf8'::name)
            END
        END AS decrypted_secret,
    secrets.key_id,
    secrets.nonce,
    secrets.created_at,
    secrets.updated_at
   FROM vault.secrets;


--
-- Name: refresh_tokens id; Type: DEFAULT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.refresh_tokens ALTER COLUMN id SET DEFAULT nextval('auth.refresh_tokens_id_seq'::regclass);


--
-- Name: eth_blocks id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.eth_blocks ALTER COLUMN id SET DEFAULT nextval('public.eth_blocks_id_seq'::regclass);


--
-- Name: eth_transactions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.eth_transactions ALTER COLUMN id SET DEFAULT nextval('public.eth_transactions_id_seq'::regclass);


--
-- Name: ethscription_ownership_versions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ethscription_ownership_versions ALTER COLUMN id SET DEFAULT nextval('public.ethscription_ownership_versions_id_seq'::regclass);


--
-- Name: ethscription_transfers id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ethscription_transfers ALTER COLUMN id SET DEFAULT nextval('public.ethscription_transfers_id_seq'::regclass);


--
-- Name: ethscriptions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ethscriptions ALTER COLUMN id SET DEFAULT nextval('public.ethscriptions_id_seq'::regclass);


--
-- Name: token_items id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.token_items ALTER COLUMN id SET DEFAULT nextval('public.token_items_id_seq'::regclass);


--
-- Name: token_states id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.token_states ALTER COLUMN id SET DEFAULT nextval('public.token_states_id_seq'::regclass);


--
-- Name: tokens id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tokens ALTER COLUMN id SET DEFAULT nextval('public.tokens_id_seq'::regclass);


--
-- Name: mfa_amr_claims amr_id_pk; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.mfa_amr_claims
    ADD CONSTRAINT amr_id_pk PRIMARY KEY (id);


--
-- Name: audit_log_entries audit_log_entries_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.audit_log_entries
    ADD CONSTRAINT audit_log_entries_pkey PRIMARY KEY (id);


--
-- Name: flow_state flow_state_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.flow_state
    ADD CONSTRAINT flow_state_pkey PRIMARY KEY (id);


--
-- Name: identities identities_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.identities
    ADD CONSTRAINT identities_pkey PRIMARY KEY (id);


--
-- Name: identities identities_provider_id_provider_unique; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.identities
    ADD CONSTRAINT identities_provider_id_provider_unique UNIQUE (provider_id, provider);


--
-- Name: instances instances_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.instances
    ADD CONSTRAINT instances_pkey PRIMARY KEY (id);


--
-- Name: mfa_amr_claims mfa_amr_claims_session_id_authentication_method_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.mfa_amr_claims
    ADD CONSTRAINT mfa_amr_claims_session_id_authentication_method_pkey UNIQUE (session_id, authentication_method);


--
-- Name: mfa_challenges mfa_challenges_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.mfa_challenges
    ADD CONSTRAINT mfa_challenges_pkey PRIMARY KEY (id);


--
-- Name: mfa_factors mfa_factors_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.mfa_factors
    ADD CONSTRAINT mfa_factors_pkey PRIMARY KEY (id);


--
-- Name: refresh_tokens refresh_tokens_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.refresh_tokens
    ADD CONSTRAINT refresh_tokens_pkey PRIMARY KEY (id);


--
-- Name: refresh_tokens refresh_tokens_token_unique; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.refresh_tokens
    ADD CONSTRAINT refresh_tokens_token_unique UNIQUE (token);


--
-- Name: saml_providers saml_providers_entity_id_key; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.saml_providers
    ADD CONSTRAINT saml_providers_entity_id_key UNIQUE (entity_id);


--
-- Name: saml_providers saml_providers_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.saml_providers
    ADD CONSTRAINT saml_providers_pkey PRIMARY KEY (id);


--
-- Name: saml_relay_states saml_relay_states_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.saml_relay_states
    ADD CONSTRAINT saml_relay_states_pkey PRIMARY KEY (id);


--
-- Name: schema_migrations schema_migrations_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.schema_migrations
    ADD CONSTRAINT schema_migrations_pkey PRIMARY KEY (version);


--
-- Name: sessions sessions_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.sessions
    ADD CONSTRAINT sessions_pkey PRIMARY KEY (id);


--
-- Name: sso_domains sso_domains_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.sso_domains
    ADD CONSTRAINT sso_domains_pkey PRIMARY KEY (id);


--
-- Name: sso_providers sso_providers_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.sso_providers
    ADD CONSTRAINT sso_providers_pkey PRIMARY KEY (id);


--
-- Name: users users_phone_key; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.users
    ADD CONSTRAINT users_phone_key UNIQUE (phone);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: ar_internal_metadata ar_internal_metadata_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ar_internal_metadata
    ADD CONSTRAINT ar_internal_metadata_pkey PRIMARY KEY (key);


--
-- Name: eth_blocks eth_blocks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.eth_blocks
    ADD CONSTRAINT eth_blocks_pkey PRIMARY KEY (id);


--
-- Name: eth_transactions eth_transactions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.eth_transactions
    ADD CONSTRAINT eth_transactions_pkey PRIMARY KEY (id);


--
-- Name: ethscription_ownership_versions ethscription_ownership_versions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ethscription_ownership_versions
    ADD CONSTRAINT ethscription_ownership_versions_pkey PRIMARY KEY (id);


--
-- Name: ethscription_transfers ethscription_transfers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ethscription_transfers
    ADD CONSTRAINT ethscription_transfers_pkey PRIMARY KEY (id);


--
-- Name: ethscriptions ethscriptions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ethscriptions
    ADD CONSTRAINT ethscriptions_pkey PRIMARY KEY (id);


--
-- Name: schema_migrations schema_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.schema_migrations
    ADD CONSTRAINT schema_migrations_pkey PRIMARY KEY (version);


--
-- Name: token_items token_items_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.token_items
    ADD CONSTRAINT token_items_pkey PRIMARY KEY (id);


--
-- Name: token_states token_states_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.token_states
    ADD CONSTRAINT token_states_pkey PRIMARY KEY (id);


--
-- Name: tokens tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tokens
    ADD CONSTRAINT tokens_pkey PRIMARY KEY (id);


--
-- Name: buckets buckets_pkey; Type: CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY storage.buckets
    ADD CONSTRAINT buckets_pkey PRIMARY KEY (id);


--
-- Name: migrations migrations_name_key; Type: CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY storage.migrations
    ADD CONSTRAINT migrations_name_key UNIQUE (name);


--
-- Name: migrations migrations_pkey; Type: CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY storage.migrations
    ADD CONSTRAINT migrations_pkey PRIMARY KEY (id);


--
-- Name: objects objects_pkey; Type: CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY storage.objects
    ADD CONSTRAINT objects_pkey PRIMARY KEY (id);


--
-- Name: audit_logs_instance_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX audit_logs_instance_id_idx ON auth.audit_log_entries USING btree (instance_id);


--
-- Name: confirmation_token_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX confirmation_token_idx ON auth.users USING btree (confirmation_token) WHERE ((confirmation_token)::text !~ '^[0-9 ]*$'::text);


--
-- Name: email_change_token_current_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX email_change_token_current_idx ON auth.users USING btree (email_change_token_current) WHERE ((email_change_token_current)::text !~ '^[0-9 ]*$'::text);


--
-- Name: email_change_token_new_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX email_change_token_new_idx ON auth.users USING btree (email_change_token_new) WHERE ((email_change_token_new)::text !~ '^[0-9 ]*$'::text);


--
-- Name: factor_id_created_at_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX factor_id_created_at_idx ON auth.mfa_factors USING btree (user_id, created_at);


--
-- Name: flow_state_created_at_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX flow_state_created_at_idx ON auth.flow_state USING btree (created_at DESC);


--
-- Name: identities_email_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX identities_email_idx ON auth.identities USING btree (email text_pattern_ops);


--
-- Name: INDEX identities_email_idx; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON INDEX auth.identities_email_idx IS 'Auth: Ensures indexed queries on the email column';


--
-- Name: identities_user_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX identities_user_id_idx ON auth.identities USING btree (user_id);


--
-- Name: idx_auth_code; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX idx_auth_code ON auth.flow_state USING btree (auth_code);


--
-- Name: idx_user_id_auth_method; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX idx_user_id_auth_method ON auth.flow_state USING btree (user_id, authentication_method);


--
-- Name: mfa_challenge_created_at_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX mfa_challenge_created_at_idx ON auth.mfa_challenges USING btree (created_at DESC);


--
-- Name: mfa_factors_user_friendly_name_unique; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX mfa_factors_user_friendly_name_unique ON auth.mfa_factors USING btree (friendly_name, user_id) WHERE (TRIM(BOTH FROM friendly_name) <> ''::text);


--
-- Name: mfa_factors_user_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX mfa_factors_user_id_idx ON auth.mfa_factors USING btree (user_id);


--
-- Name: reauthentication_token_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX reauthentication_token_idx ON auth.users USING btree (reauthentication_token) WHERE ((reauthentication_token)::text !~ '^[0-9 ]*$'::text);


--
-- Name: recovery_token_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX recovery_token_idx ON auth.users USING btree (recovery_token) WHERE ((recovery_token)::text !~ '^[0-9 ]*$'::text);


--
-- Name: refresh_tokens_instance_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX refresh_tokens_instance_id_idx ON auth.refresh_tokens USING btree (instance_id);


--
-- Name: refresh_tokens_instance_id_user_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX refresh_tokens_instance_id_user_id_idx ON auth.refresh_tokens USING btree (instance_id, user_id);


--
-- Name: refresh_tokens_parent_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX refresh_tokens_parent_idx ON auth.refresh_tokens USING btree (parent);


--
-- Name: refresh_tokens_session_id_revoked_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX refresh_tokens_session_id_revoked_idx ON auth.refresh_tokens USING btree (session_id, revoked);


--
-- Name: refresh_tokens_updated_at_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX refresh_tokens_updated_at_idx ON auth.refresh_tokens USING btree (updated_at DESC);


--
-- Name: saml_providers_sso_provider_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX saml_providers_sso_provider_id_idx ON auth.saml_providers USING btree (sso_provider_id);


--
-- Name: saml_relay_states_created_at_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX saml_relay_states_created_at_idx ON auth.saml_relay_states USING btree (created_at DESC);


--
-- Name: saml_relay_states_for_email_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX saml_relay_states_for_email_idx ON auth.saml_relay_states USING btree (for_email);


--
-- Name: saml_relay_states_sso_provider_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX saml_relay_states_sso_provider_id_idx ON auth.saml_relay_states USING btree (sso_provider_id);


--
-- Name: sessions_not_after_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX sessions_not_after_idx ON auth.sessions USING btree (not_after DESC);


--
-- Name: sessions_user_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX sessions_user_id_idx ON auth.sessions USING btree (user_id);


--
-- Name: sso_domains_domain_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX sso_domains_domain_idx ON auth.sso_domains USING btree (lower(domain));


--
-- Name: sso_domains_sso_provider_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX sso_domains_sso_provider_id_idx ON auth.sso_domains USING btree (sso_provider_id);


--
-- Name: sso_providers_resource_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX sso_providers_resource_id_idx ON auth.sso_providers USING btree (lower(resource_id));


--
-- Name: user_id_created_at_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX user_id_created_at_idx ON auth.sessions USING btree (user_id, created_at);


--
-- Name: users_email_partial_key; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX users_email_partial_key ON auth.users USING btree (email) WHERE (is_sso_user = false);


--
-- Name: INDEX users_email_partial_key; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON INDEX auth.users_email_partial_key IS 'Auth: A partial unique index that applies only when is_sso_user is false';


--
-- Name: users_instance_id_email_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX users_instance_id_email_idx ON auth.users USING btree (instance_id, lower((email)::text));


--
-- Name: users_instance_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX users_instance_id_idx ON auth.users USING btree (instance_id);


--
-- Name: users_is_anonymous_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX users_is_anonymous_idx ON auth.users USING btree (is_anonymous);


--
-- Name: idx_on_block_number_deploy_ethscription_transaction_4559fe945a; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_on_block_number_deploy_ethscription_transaction_4559fe945a ON public.token_states USING btree (block_number, deploy_ethscription_transaction_hash);


--
-- Name: idx_on_block_number_transaction_index_event_log_ind_94b2c4b953; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_on_block_number_transaction_index_event_log_ind_94b2c4b953 ON public.ethscription_transfers USING btree (block_number, transaction_index, event_log_index);


--
-- Name: idx_on_block_number_transaction_index_transfer_inde_8090d24b9e; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_on_block_number_transaction_index_transfer_inde_8090d24b9e ON public.ethscription_ownership_versions USING btree (block_number, transaction_index, transfer_index);


--
-- Name: idx_on_block_number_transaction_index_transfer_inde_fc9ee59957; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_on_block_number_transaction_index_transfer_inde_fc9ee59957 ON public.ethscription_transfers USING btree (block_number, transaction_index, transfer_index);


--
-- Name: idx_on_current_owner_previous_owner_7bb4bbf3cf; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_on_current_owner_previous_owner_7bb4bbf3cf ON public.ethscription_ownership_versions USING btree (current_owner, previous_owner);


--
-- Name: idx_on_deploy_block_number_deploy_transaction_index_16cfcbe277; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_on_deploy_block_number_deploy_transaction_index_16cfcbe277 ON public.tokens USING btree (deploy_block_number, deploy_transaction_index);


--
-- Name: idx_on_deploy_ethscription_transaction_hash_token_i_8afe3c6082; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_on_deploy_ethscription_transaction_hash_token_i_8afe3c6082 ON public.token_items USING btree (deploy_ethscription_transaction_hash, token_item_id);


--
-- Name: idx_on_ethscription_transaction_hash_deploy_ethscri_5f2ffeede2; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_on_ethscription_transaction_hash_deploy_ethscri_5f2ffeede2 ON public.token_items USING btree (ethscription_transaction_hash, deploy_ethscription_transaction_hash, token_item_id);


--
-- Name: idx_on_ethscription_transaction_hash_e9e1b526f9; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_on_ethscription_transaction_hash_e9e1b526f9 ON public.ethscription_ownership_versions USING btree (ethscription_transaction_hash);


--
-- Name: idx_on_transaction_hash_event_log_index_c192a81bef; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_on_transaction_hash_event_log_index_c192a81bef ON public.ethscription_transfers USING btree (transaction_hash, event_log_index);


--
-- Name: idx_on_transaction_hash_transfer_index_4389678e0a; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_on_transaction_hash_transfer_index_4389678e0a ON public.ethscription_transfers USING btree (transaction_hash, transfer_index);


--
-- Name: idx_on_transaction_hash_transfer_index_b79931daa1; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_on_transaction_hash_transfer_index_b79931daa1 ON public.ethscription_ownership_versions USING btree (transaction_hash, transfer_index);


--
-- Name: index_eth_blocks_on_block_number; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_eth_blocks_on_block_number ON public.eth_blocks USING btree (block_number);


--
-- Name: index_eth_blocks_on_blockhash; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_eth_blocks_on_blockhash ON public.eth_blocks USING btree (blockhash);


--
-- Name: index_eth_blocks_on_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_eth_blocks_on_created_at ON public.eth_blocks USING btree (created_at);


--
-- Name: index_eth_blocks_on_imported_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_eth_blocks_on_imported_at ON public.eth_blocks USING btree (imported_at);


--
-- Name: index_eth_blocks_on_imported_at_and_block_number; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_eth_blocks_on_imported_at_and_block_number ON public.eth_blocks USING btree (imported_at, block_number);


--
-- Name: index_eth_blocks_on_parent_blockhash; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_eth_blocks_on_parent_blockhash ON public.eth_blocks USING btree (parent_blockhash);


--
-- Name: index_eth_blocks_on_parent_state_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_eth_blocks_on_parent_state_hash ON public.eth_blocks USING btree (parent_state_hash);


--
-- Name: index_eth_blocks_on_state_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_eth_blocks_on_state_hash ON public.eth_blocks USING btree (state_hash);


--
-- Name: index_eth_blocks_on_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_eth_blocks_on_timestamp ON public.eth_blocks USING btree ("timestamp");


--
-- Name: index_eth_blocks_on_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_eth_blocks_on_updated_at ON public.eth_blocks USING btree (updated_at);


--
-- Name: index_eth_transactions_on_block_blockhash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_eth_transactions_on_block_blockhash ON public.eth_transactions USING btree (block_blockhash);


--
-- Name: index_eth_transactions_on_block_number; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_eth_transactions_on_block_number ON public.eth_transactions USING btree (block_number);


--
-- Name: index_eth_transactions_on_block_number_and_transaction_index; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_eth_transactions_on_block_number_and_transaction_index ON public.eth_transactions USING btree (block_number, transaction_index);


--
-- Name: index_eth_transactions_on_block_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_eth_transactions_on_block_timestamp ON public.eth_transactions USING btree (block_timestamp);


--
-- Name: index_eth_transactions_on_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_eth_transactions_on_created_at ON public.eth_transactions USING btree (created_at);


--
-- Name: index_eth_transactions_on_from_address; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_eth_transactions_on_from_address ON public.eth_transactions USING btree (from_address);


--
-- Name: index_eth_transactions_on_logs; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_eth_transactions_on_logs ON public.eth_transactions USING gin (logs);


--
-- Name: index_eth_transactions_on_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_eth_transactions_on_status ON public.eth_transactions USING btree (status);


--
-- Name: index_eth_transactions_on_to_address; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_eth_transactions_on_to_address ON public.eth_transactions USING btree (to_address);


--
-- Name: index_eth_transactions_on_transaction_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_eth_transactions_on_transaction_hash ON public.eth_transactions USING btree (transaction_hash);


--
-- Name: index_eth_transactions_on_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_eth_transactions_on_updated_at ON public.eth_transactions USING btree (updated_at);


--
-- Name: index_ethscription_ownership_versions_on_block_blockhash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_ethscription_ownership_versions_on_block_blockhash ON public.ethscription_ownership_versions USING btree (block_blockhash);


--
-- Name: index_ethscription_ownership_versions_on_block_number; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_ethscription_ownership_versions_on_block_number ON public.ethscription_ownership_versions USING btree (block_number);


--
-- Name: index_ethscription_ownership_versions_on_block_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_ethscription_ownership_versions_on_block_timestamp ON public.ethscription_ownership_versions USING btree (block_timestamp);


--
-- Name: index_ethscription_ownership_versions_on_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_ethscription_ownership_versions_on_created_at ON public.ethscription_ownership_versions USING btree (created_at);


--
-- Name: index_ethscription_ownership_versions_on_current_owner; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_ethscription_ownership_versions_on_current_owner ON public.ethscription_ownership_versions USING btree (current_owner);


--
-- Name: index_ethscription_ownership_versions_on_previous_owner; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_ethscription_ownership_versions_on_previous_owner ON public.ethscription_ownership_versions USING btree (previous_owner);


--
-- Name: index_ethscription_ownership_versions_on_transaction_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_ethscription_ownership_versions_on_transaction_hash ON public.ethscription_ownership_versions USING btree (transaction_hash);


--
-- Name: index_ethscription_ownership_versions_on_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_ethscription_ownership_versions_on_updated_at ON public.ethscription_ownership_versions USING btree (updated_at);


--
-- Name: index_ethscription_transfers_on_block_blockhash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_ethscription_transfers_on_block_blockhash ON public.ethscription_transfers USING btree (block_blockhash);


--
-- Name: index_ethscription_transfers_on_block_number; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_ethscription_transfers_on_block_number ON public.ethscription_transfers USING btree (block_number);


--
-- Name: index_ethscription_transfers_on_block_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_ethscription_transfers_on_block_timestamp ON public.ethscription_transfers USING btree (block_timestamp);


--
-- Name: index_ethscription_transfers_on_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_ethscription_transfers_on_created_at ON public.ethscription_transfers USING btree (created_at);


--
-- Name: index_ethscription_transfers_on_enforced_previous_owner; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_ethscription_transfers_on_enforced_previous_owner ON public.ethscription_transfers USING btree (enforced_previous_owner);


--
-- Name: index_ethscription_transfers_on_ethscription_transaction_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_ethscription_transfers_on_ethscription_transaction_hash ON public.ethscription_transfers USING btree (ethscription_transaction_hash);


--
-- Name: index_ethscription_transfers_on_from_address; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_ethscription_transfers_on_from_address ON public.ethscription_transfers USING btree (from_address);


--
-- Name: index_ethscription_transfers_on_to_address; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_ethscription_transfers_on_to_address ON public.ethscription_transfers USING btree (to_address);


--
-- Name: index_ethscription_transfers_on_transaction_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_ethscription_transfers_on_transaction_hash ON public.ethscription_transfers USING btree (transaction_hash);


--
-- Name: index_ethscription_transfers_on_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_ethscription_transfers_on_updated_at ON public.ethscription_transfers USING btree (updated_at);


--
-- Name: index_ethscriptions_on_block_blockhash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_ethscriptions_on_block_blockhash ON public.ethscriptions USING btree (block_blockhash);


--
-- Name: index_ethscriptions_on_block_number; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_ethscriptions_on_block_number ON public.ethscriptions USING btree (block_number);


--
-- Name: index_ethscriptions_on_block_number_and_transaction_index; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_ethscriptions_on_block_number_and_transaction_index ON public.ethscriptions USING btree (block_number, transaction_index);


--
-- Name: index_ethscriptions_on_block_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_ethscriptions_on_block_timestamp ON public.ethscriptions USING btree (block_timestamp);


--
-- Name: index_ethscriptions_on_content_sha; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_ethscriptions_on_content_sha ON public.ethscriptions USING btree (content_sha);


--
-- Name: index_ethscriptions_on_content_sha_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_ethscriptions_on_content_sha_unique ON public.ethscriptions USING btree (content_sha) WHERE (esip6 = false);


--
-- Name: index_ethscriptions_on_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_ethscriptions_on_created_at ON public.ethscriptions USING btree (created_at);


--
-- Name: index_ethscriptions_on_creator; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_ethscriptions_on_creator ON public.ethscriptions USING btree (creator);


--
-- Name: index_ethscriptions_on_current_owner; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_ethscriptions_on_current_owner ON public.ethscriptions USING btree (current_owner);


--
-- Name: index_ethscriptions_on_esip6; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_ethscriptions_on_esip6 ON public.ethscriptions USING btree (esip6);


--
-- Name: index_ethscriptions_on_ethscription_number; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_ethscriptions_on_ethscription_number ON public.ethscriptions USING btree (ethscription_number);


--
-- Name: index_ethscriptions_on_initial_owner; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_ethscriptions_on_initial_owner ON public.ethscriptions USING btree (initial_owner);


--
-- Name: index_ethscriptions_on_media_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_ethscriptions_on_media_type ON public.ethscriptions USING btree (media_type);


--
-- Name: index_ethscriptions_on_mime_subtype; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_ethscriptions_on_mime_subtype ON public.ethscriptions USING btree (mime_subtype);


--
-- Name: index_ethscriptions_on_mimetype; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_ethscriptions_on_mimetype ON public.ethscriptions USING btree (mimetype);


--
-- Name: index_ethscriptions_on_previous_owner; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_ethscriptions_on_previous_owner ON public.ethscriptions USING btree (previous_owner);


--
-- Name: index_ethscriptions_on_transaction_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_ethscriptions_on_transaction_hash ON public.ethscriptions USING btree (transaction_hash);


--
-- Name: index_ethscriptions_on_transaction_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_ethscriptions_on_transaction_index ON public.ethscriptions USING btree (transaction_index);


--
-- Name: index_ethscriptions_on_updated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_ethscriptions_on_updated_at ON public.ethscriptions USING btree (updated_at);


--
-- Name: index_token_items_on_block_number_and_transaction_index; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_token_items_on_block_number_and_transaction_index ON public.token_items USING btree (block_number, transaction_index);


--
-- Name: index_token_items_on_ethscription_transaction_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_token_items_on_ethscription_transaction_hash ON public.token_items USING btree (ethscription_transaction_hash);


--
-- Name: index_token_items_on_transaction_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_token_items_on_transaction_index ON public.token_items USING btree (transaction_index);


--
-- Name: index_token_states_on_deploy_ethscription_transaction_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_token_states_on_deploy_ethscription_transaction_hash ON public.token_states USING btree (deploy_ethscription_transaction_hash);


--
-- Name: index_tokens_on_deploy_ethscription_transaction_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_tokens_on_deploy_ethscription_transaction_hash ON public.tokens USING btree (deploy_ethscription_transaction_hash);


--
-- Name: index_tokens_on_protocol_and_tick; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_tokens_on_protocol_and_tick ON public.tokens USING btree (protocol, tick);


--
-- Name: bname; Type: INDEX; Schema: storage; Owner: -
--

CREATE UNIQUE INDEX bname ON storage.buckets USING btree (name);


--
-- Name: bucketid_objname; Type: INDEX; Schema: storage; Owner: -
--

CREATE UNIQUE INDEX bucketid_objname ON storage.objects USING btree (bucket_id, name);


--
-- Name: name_prefix_search; Type: INDEX; Schema: storage; Owner: -
--

CREATE INDEX name_prefix_search ON storage.objects USING btree (name text_pattern_ops);


--
-- Name: eth_blocks check_block_imported_at_trigger; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER check_block_imported_at_trigger BEFORE UPDATE OF imported_at ON public.eth_blocks FOR EACH ROW EXECUTE FUNCTION public.check_block_imported_at();


--
-- Name: eth_blocks trigger_check_block_order; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trigger_check_block_order BEFORE INSERT ON public.eth_blocks FOR EACH ROW EXECUTE FUNCTION public.check_block_order();


--
-- Name: eth_blocks trigger_check_block_order_on_update; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trigger_check_block_order_on_update BEFORE UPDATE OF imported_at ON public.eth_blocks FOR EACH ROW WHEN ((new.imported_at IS NOT NULL)) EXECUTE FUNCTION public.check_block_order_on_update();


--
-- Name: ethscriptions trigger_check_ethscription_order_and_sequence; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trigger_check_ethscription_order_and_sequence BEFORE INSERT ON public.ethscriptions FOR EACH ROW EXECUTE FUNCTION public.check_ethscription_order_and_sequence();


--
-- Name: eth_blocks trigger_delete_later_blocks; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trigger_delete_later_blocks AFTER DELETE ON public.eth_blocks FOR EACH ROW EXECUTE FUNCTION public.delete_later_blocks();


--
-- Name: ethscription_ownership_versions update_current_owner; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER update_current_owner AFTER INSERT OR DELETE ON public.ethscription_ownership_versions FOR EACH ROW EXECUTE FUNCTION public.update_current_owner();


--
-- Name: token_states update_token_balances_and_supply; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER update_token_balances_and_supply AFTER INSERT OR DELETE ON public.token_states FOR EACH ROW EXECUTE FUNCTION public.update_token_balances_and_supply();


--
-- Name: objects update_objects_updated_at; Type: TRIGGER; Schema: storage; Owner: -
--

CREATE TRIGGER update_objects_updated_at BEFORE UPDATE ON storage.objects FOR EACH ROW EXECUTE FUNCTION storage.update_updated_at_column();


--
-- Name: identities identities_user_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.identities
    ADD CONSTRAINT identities_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;


--
-- Name: mfa_amr_claims mfa_amr_claims_session_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.mfa_amr_claims
    ADD CONSTRAINT mfa_amr_claims_session_id_fkey FOREIGN KEY (session_id) REFERENCES auth.sessions(id) ON DELETE CASCADE;


--
-- Name: mfa_challenges mfa_challenges_auth_factor_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.mfa_challenges
    ADD CONSTRAINT mfa_challenges_auth_factor_id_fkey FOREIGN KEY (factor_id) REFERENCES auth.mfa_factors(id) ON DELETE CASCADE;


--
-- Name: mfa_factors mfa_factors_user_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.mfa_factors
    ADD CONSTRAINT mfa_factors_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;


--
-- Name: refresh_tokens refresh_tokens_session_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.refresh_tokens
    ADD CONSTRAINT refresh_tokens_session_id_fkey FOREIGN KEY (session_id) REFERENCES auth.sessions(id) ON DELETE CASCADE;


--
-- Name: saml_providers saml_providers_sso_provider_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.saml_providers
    ADD CONSTRAINT saml_providers_sso_provider_id_fkey FOREIGN KEY (sso_provider_id) REFERENCES auth.sso_providers(id) ON DELETE CASCADE;


--
-- Name: saml_relay_states saml_relay_states_flow_state_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.saml_relay_states
    ADD CONSTRAINT saml_relay_states_flow_state_id_fkey FOREIGN KEY (flow_state_id) REFERENCES auth.flow_state(id) ON DELETE CASCADE;


--
-- Name: saml_relay_states saml_relay_states_sso_provider_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.saml_relay_states
    ADD CONSTRAINT saml_relay_states_sso_provider_id_fkey FOREIGN KEY (sso_provider_id) REFERENCES auth.sso_providers(id) ON DELETE CASCADE;


--
-- Name: sessions sessions_user_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.sessions
    ADD CONSTRAINT sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;


--
-- Name: sso_domains sso_domains_sso_provider_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.sso_domains
    ADD CONSTRAINT sso_domains_sso_provider_id_fkey FOREIGN KEY (sso_provider_id) REFERENCES auth.sso_providers(id) ON DELETE CASCADE;


--
-- Name: ethscriptions fk_rails_104cee2b3d; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ethscriptions
    ADD CONSTRAINT fk_rails_104cee2b3d FOREIGN KEY (block_number) REFERENCES public.eth_blocks(block_number) ON DELETE CASCADE;


--
-- Name: tokens fk_rails_1c09e75f12; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tokens
    ADD CONSTRAINT fk_rails_1c09e75f12 FOREIGN KEY (deploy_ethscription_transaction_hash) REFERENCES public.ethscriptions(transaction_hash) ON DELETE CASCADE;


--
-- Name: ethscriptions fk_rails_2accd8a448; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ethscriptions
    ADD CONSTRAINT fk_rails_2accd8a448 FOREIGN KEY (transaction_hash) REFERENCES public.eth_transactions(transaction_hash) ON DELETE CASCADE;


--
-- Name: ethscription_transfers fk_rails_2fe933886e; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ethscription_transfers
    ADD CONSTRAINT fk_rails_2fe933886e FOREIGN KEY (transaction_hash) REFERENCES public.eth_transactions(transaction_hash) ON DELETE CASCADE;


--
-- Name: token_states fk_rails_40574954c3; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.token_states
    ADD CONSTRAINT fk_rails_40574954c3 FOREIGN KEY (deploy_ethscription_transaction_hash) REFERENCES public.tokens(deploy_ethscription_transaction_hash) ON DELETE CASCADE;


--
-- Name: ethscription_transfers fk_rails_479ac03c16; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ethscription_transfers
    ADD CONSTRAINT fk_rails_479ac03c16 FOREIGN KEY (ethscription_transaction_hash) REFERENCES public.ethscriptions(transaction_hash) ON DELETE CASCADE;


--
-- Name: eth_transactions fk_rails_4937ed3300; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.eth_transactions
    ADD CONSTRAINT fk_rails_4937ed3300 FOREIGN KEY (block_number) REFERENCES public.eth_blocks(block_number) ON DELETE CASCADE;


--
-- Name: ethscription_ownership_versions fk_rails_8808aa138a; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ethscription_ownership_versions
    ADD CONSTRAINT fk_rails_8808aa138a FOREIGN KEY (ethscription_transaction_hash) REFERENCES public.ethscriptions(transaction_hash) ON DELETE CASCADE;


--
-- Name: token_items fk_rails_8d58f29890; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.token_items
    ADD CONSTRAINT fk_rails_8d58f29890 FOREIGN KEY (deploy_ethscription_transaction_hash) REFERENCES public.tokens(deploy_ethscription_transaction_hash) ON DELETE CASCADE;


--
-- Name: ethscription_transfers fk_rails_b68511af4b; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ethscription_transfers
    ADD CONSTRAINT fk_rails_b68511af4b FOREIGN KEY (block_number) REFERENCES public.eth_blocks(block_number) ON DELETE CASCADE;


--
-- Name: token_states fk_rails_c99350f4d3; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.token_states
    ADD CONSTRAINT fk_rails_c99350f4d3 FOREIGN KEY (block_number) REFERENCES public.eth_blocks(block_number) ON DELETE CASCADE;


--
-- Name: ethscription_ownership_versions fk_rails_e95d97c83e; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ethscription_ownership_versions
    ADD CONSTRAINT fk_rails_e95d97c83e FOREIGN KEY (block_number) REFERENCES public.eth_blocks(block_number) ON DELETE CASCADE;


--
-- Name: ethscription_ownership_versions fk_rails_ed1fdc1619; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ethscription_ownership_versions
    ADD CONSTRAINT fk_rails_ed1fdc1619 FOREIGN KEY (transaction_hash) REFERENCES public.eth_transactions(transaction_hash) ON DELETE CASCADE;


--
-- Name: token_items fk_rails_ffdbb769e4; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.token_items
    ADD CONSTRAINT fk_rails_ffdbb769e4 FOREIGN KEY (ethscription_transaction_hash) REFERENCES public.ethscriptions(transaction_hash) ON DELETE CASCADE;


--
-- Name: objects objects_bucketId_fkey; Type: FK CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY storage.objects
    ADD CONSTRAINT "objects_bucketId_fkey" FOREIGN KEY (bucket_id) REFERENCES storage.buckets(id);


--
-- Name: buckets; Type: ROW SECURITY; Schema: storage; Owner: -
--

ALTER TABLE storage.buckets ENABLE ROW LEVEL SECURITY;

--
-- Name: migrations; Type: ROW SECURITY; Schema: storage; Owner: -
--

ALTER TABLE storage.migrations ENABLE ROW LEVEL SECURITY;

--
-- Name: objects; Type: ROW SECURITY; Schema: storage; Owner: -
--

ALTER TABLE storage.objects ENABLE ROW LEVEL SECURITY;

--
-- Name: supabase_realtime; Type: PUBLICATION; Schema: -; Owner: -
--

CREATE PUBLICATION supabase_realtime WITH (publish = 'insert, update, delete, truncate');


--
-- Name: issue_graphql_placeholder; Type: EVENT TRIGGER; Schema: -; Owner: -
--

CREATE EVENT TRIGGER issue_graphql_placeholder ON sql_drop
         WHEN TAG IN ('DROP EXTENSION')
   EXECUTE FUNCTION extensions.set_graphql_placeholder();


--
-- Name: issue_pg_cron_access; Type: EVENT TRIGGER; Schema: -; Owner: -
--

CREATE EVENT TRIGGER issue_pg_cron_access ON ddl_command_end
         WHEN TAG IN ('CREATE EXTENSION')
   EXECUTE FUNCTION extensions.grant_pg_cron_access();


--
-- Name: issue_pg_graphql_access; Type: EVENT TRIGGER; Schema: -; Owner: -
--

CREATE EVENT TRIGGER issue_pg_graphql_access ON ddl_command_end
         WHEN TAG IN ('CREATE FUNCTION')
   EXECUTE FUNCTION extensions.grant_pg_graphql_access();


--
-- Name: issue_pg_net_access; Type: EVENT TRIGGER; Schema: -; Owner: -
--

CREATE EVENT TRIGGER issue_pg_net_access ON ddl_command_end
         WHEN TAG IN ('CREATE EXTENSION')
   EXECUTE FUNCTION extensions.grant_pg_net_access();


--
-- Name: pgrst_ddl_watch; Type: EVENT TRIGGER; Schema: -; Owner: -
--

CREATE EVENT TRIGGER pgrst_ddl_watch ON ddl_command_end
   EXECUTE FUNCTION extensions.pgrst_ddl_watch();


--
-- Name: pgrst_drop_watch; Type: EVENT TRIGGER; Schema: -; Owner: -
--

CREATE EVENT TRIGGER pgrst_drop_watch ON sql_drop
   EXECUTE FUNCTION extensions.pgrst_drop_watch();


--
-- PostgreSQL database dump complete
--

SET search_path TO "\$user", public, extensions;

INSERT INTO "schema_migrations" (version) VALUES
('20240126184612'),
('20240126162132'),
('20240115192312'),
('20240115151119'),
('20240115144930'),
('20231216215348'),
('20231216213103'),
('20231216164707'),
('20231216163233'),
('20231216161930');

