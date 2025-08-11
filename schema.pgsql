--
-- PostgreSQL database cluster dump
--

-- Started on 2025-08-11 08:04:12 UTC

SET default_transaction_read_only = off;

SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;

--
-- Roles
--

CREATE ROLE admin;
ALTER ROLE admin WITH SUPERUSER INHERIT CREATEROLE CREATEDB LOGIN REPLICATION BYPASSRLS PASSWORD 'SCRAM-SHA-256$4096:HPWam+oFMMTmkD9/YkEfwA==$ytPGIbi2nvoMdBO5AtpXcp58C4nVf668aOjTWwQJz04=:G9JK3kqqbG7tFEMo3pHsau8AUvQpcjSfVZB46iGphCw=';
CREATE ROLE authenticator;
ALTER ROLE authenticator WITH NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB NOLOGIN NOREPLICATION NOBYPASSRLS;
COMMENT ON ROLE authenticator IS 'A limited role for anonymous users, can only execute the login function.';
CREATE ROLE editor;
ALTER ROLE editor WITH NOSUPERUSER INHERIT NOCREATEROLE NOCREATEDB NOLOGIN NOREPLICATION NOBYPASSRLS;
COMMENT ON ROLE editor IS 'Editor role with read/write access to owned resources.';
CREATE ROLE storage_admin;
ALTER ROLE storage_admin WITH NOSUPERUSER INHERIT NOCREATEROLE NOCREATEDB NOLOGIN NOREPLICATION NOBYPASSRLS;
COMMENT ON ROLE storage_admin IS 'storage_administrator role with full access to all resources.';

--
-- User Configurations
--








--
-- Databases
--

--
-- Database "template1" dump
--

\connect template1

--
-- PostgreSQL database dump
--

-- Dumped from database version 15.13
-- Dumped by pg_dump version 15.5

-- Started on 2025-08-11 08:04:12 UTC

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

-- Completed on 2025-08-11 08:04:12 UTC

--
-- PostgreSQL database dump complete
--

--
-- Database "file_storage_db" dump
--

--
-- PostgreSQL database dump
--

-- Dumped from database version 15.13
-- Dumped by pg_dump version 15.5

-- Started on 2025-08-11 08:04:12 UTC

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
-- TOC entry 3494 (class 1262 OID 16384)
-- Name: file_storage_db; Type: DATABASE; Schema: -; Owner: admin
--

CREATE DATABASE file_storage_db WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE_PROVIDER = libc LOCALE = 'en_US.utf8';


ALTER DATABASE file_storage_db OWNER TO admin;

\connect file_storage_db

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
-- TOC entry 8 (class 2615 OID 24671)
-- Name: file_storage; Type: SCHEMA; Schema: -; Owner: admin
--

CREATE SCHEMA file_storage;


ALTER SCHEMA file_storage OWNER TO admin;

--
-- TOC entry 3495 (class 0 OID 0)
-- Dependencies: 8
-- Name: SCHEMA file_storage; Type: COMMENT; Schema: -; Owner: admin
--

COMMENT ON SCHEMA file_storage IS 'Schema for the file storage application, containing all related tables, functions, and views.';


--
-- TOC entry 2 (class 3079 OID 24672)
-- Name: plpython3u; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS plpython3u WITH SCHEMA pg_catalog;


--
-- TOC entry 3497 (class 0 OID 0)
-- Dependencies: 2
-- Name: EXTENSION plpython3u; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION plpython3u IS 'Enables the use of PL/Python3 procedural language.';


--
-- TOC entry 3 (class 3079 OID 24677)
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- TOC entry 3498 (class 0 OID 0)
-- Dependencies: 3
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION pgcrypto IS 'Provides cryptographic functions for PostgreSQL.';


--
-- TOC entry 893 (class 1247 OID 24776)
-- Name: application/octet-stream; Type: DOMAIN; Schema: public; Owner: admin
--

CREATE DOMAIN public."application/octet-stream" AS bytea;


ALTER DOMAIN public."application/octet-stream" OWNER TO admin;

--
-- TOC entry 271 (class 1255 OID 24770)
-- Name: algorithm_sign(text, text, text); Type: FUNCTION; Schema: file_storage; Owner: admin
--

CREATE FUNCTION file_storage.algorithm_sign(signables text, secret text, algorithm text) RETURNS text
    LANGUAGE sql IMMUTABLE
    AS $$
WITH
  alg AS (
    SELECT CASE
      WHEN algorithm = 'HS256' THEN 'sha256'
      WHEN algorithm = 'HS384' THEN 'sha384'
      WHEN algorithm = 'HS512' THEN 'sha512'
      ELSE '' END AS id
  )
SELECT file_storage.url_encode(public.hmac(signables, secret, alg.id)) FROM alg;
$$;


ALTER FUNCTION file_storage.algorithm_sign(signables text, secret text, algorithm text) OWNER TO admin;

--
-- TOC entry 3499 (class 0 OID 0)
-- Dependencies: 271
-- Name: FUNCTION algorithm_sign(signables text, secret text, algorithm text); Type: COMMENT; Schema: file_storage; Owner: admin
--

COMMENT ON FUNCTION file_storage.algorithm_sign(signables text, secret text, algorithm text) IS 'Signs a text string using HMAC with the specified SHA algorithm.';


--
-- TOC entry 268 (class 1255 OID 24757)
-- Name: internal_read_from_storage(text); Type: FUNCTION; Schema: file_storage; Owner: admin
--

CREATE FUNCTION file_storage.internal_read_from_storage(p_storage_path text) RETURNS bytea
    LANGUAGE plpython3u SECURITY DEFINER
    AS $$
  import os
  from fs import open_fs

  storage_url = os.environ.get('STORAGE_BACKEND_URL', 'osfs:///var/storage')
  with open_fs(storage_url) as home_fs:
    if not home_fs.exists(p_storage_path):
      plpy.error("File not found in storage backend.")
    return home_fs.readbytes(p_storage_path)
$$;


ALTER FUNCTION file_storage.internal_read_from_storage(p_storage_path text) OWNER TO admin;

--
-- TOC entry 3500 (class 0 OID 0)
-- Dependencies: 268
-- Name: FUNCTION internal_read_from_storage(p_storage_path text); Type: COMMENT; Schema: file_storage; Owner: admin
--

COMMENT ON FUNCTION file_storage.internal_read_from_storage(p_storage_path text) IS '[INTERNAL] Reads a file from the physical storage backend. Should only be called by wrapper functions.';


--
-- TOC entry 233 (class 1255 OID 24756)
-- Name: internal_write_to_storage(text, bytea); Type: FUNCTION; Schema: file_storage; Owner: admin
--

CREATE FUNCTION file_storage.internal_write_to_storage(p_storage_path text, p_file_data bytea) RETURNS void
    LANGUAGE plpython3u SECURITY DEFINER
    AS $$
  import os
  from fs import open_fs

  storage_url = os.environ.get('STORAGE_BACKEND_URL', 'osfs:///var/storage')
  with open_fs(storage_url) as home_fs:
    dir_path = os.path.dirname(p_storage_path)
    if dir_path:
        home_fs.makedirs(dir_path, recreate=True)
    home_fs.writebytes(p_storage_path, p_file_data)
$$;


ALTER FUNCTION file_storage.internal_write_to_storage(p_storage_path text, p_file_data bytea) OWNER TO admin;

--
-- TOC entry 3502 (class 0 OID 0)
-- Dependencies: 233
-- Name: FUNCTION internal_write_to_storage(p_storage_path text, p_file_data bytea); Type: COMMENT; Schema: file_storage; Owner: admin
--

COMMENT ON FUNCTION file_storage.internal_write_to_storage(p_storage_path text, p_file_data bytea) IS '[INTERNAL] Writes a file to the physical storage backend. Should only be called by wrapper functions.';


--
-- TOC entry 273 (class 1255 OID 24767)
-- Name: login(text, text); Type: FUNCTION; Schema: file_storage; Owner: admin
--

CREATE FUNCTION file_storage.login(email text, password text, OUT token text) RETURNS text
    LANGUAGE plpgsql SECURITY DEFINER
    AS $$
DECLARE
  user_record file_storage.users;
BEGIN
  -- Retrieve the user record based on the provided email
  SELECT * INTO user_record FROM file_storage.users WHERE users.email = login.email;

  -- Verify the password and, if correct, sign and return a JWT
  IF user_record.id IS NOT NULL AND user_record.password_hash = crypt(password, user_record.password_hash) THEN
    -- NOTE: The secret is hardcoded here for demonstration purposes.
    -- It MUST match the PGRST_JWT_SECRET in your docker-compose.yml file.
    -- In a production environment, you should set this using:
    -- ALTER DATABASE your_db_name SET "app.jwt_secret" TO 'your_super_secret';
    -- And then use current_setting('app.jwt_secret') instead of the hardcoded string.
    SELECT file_storage.sign(
      json_build_object(
        'role', user_record.role,
        'user_id', user_record.id,
        'username', user_record.username,
        'exp', extract(epoch from now() + interval '1 day')
      ),
      'a_very_secret_and_long_jwt_secret_key_that_is_at_least_32_characters'
    ) INTO token;
  ELSE
    RAISE invalid_password USING MESSAGE = 'Invalid email or password';
  END IF;
END;
$$;


ALTER FUNCTION file_storage.login(email text, password text, OUT token text) OWNER TO admin;

--
-- TOC entry 3504 (class 0 OID 0)
-- Dependencies: 273
-- Name: FUNCTION login(email text, password text, OUT token text); Type: COMMENT; Schema: file_storage; Owner: admin
--

COMMENT ON FUNCTION file_storage.login(email text, password text, OUT token text) IS 'Authenticates a user and returns a signed JWT.';


--
-- TOC entry 275 (class 1255 OID 24777)
-- Name: retrieve_file(text); Type: FUNCTION; Schema: file_storage; Owner: admin
--

CREATE FUNCTION file_storage.retrieve_file(p_file_path text) RETURNS public."application/octet-stream"
    LANGUAGE plpgsql SECURITY DEFINER
    AS $$
DECLARE
  v_user_id UUID;
  v_username TEXT;
  v_storage_path TEXT;
  v_is_owner BOOLEAN;
BEGIN
  -- Extract user info from JWT
  SELECT
    current_setting('request.jwt.claims', true)::jsonb ->> 'user_id',
    current_setting('request.jwt.claims', true)::jsonb ->> 'username'
  INTO v_user_id, v_username;

  -- Validate required information
  IF v_user_id IS NULL OR v_username IS NULL THEN
    RAISE EXCEPTION 'User ID or username not found in JWT claims. Authentication is required.';
  END IF;

  -- Explicitly verify ownership before accessing the filesystem.
  SELECT EXISTS (
    SELECT 1 FROM file_storage.files f
    WHERE f.user_id = v_user_id AND f.file_path = p_file_path
  ) INTO v_is_owner;

  IF NOT v_is_owner THEN
    RAISE EXCEPTION 'File not found.';
  END IF;

  -- Construct the actual storage path
  v_storage_path := v_username || '/' || p_file_path;

  -- Call the internal Python function to read the file from storage
  RETURN file_storage.internal_read_from_storage(v_storage_path);
END;
$$;


ALTER FUNCTION file_storage.retrieve_file(p_file_path text) OWNER TO admin;

--
-- TOC entry 3506 (class 0 OID 0)
-- Dependencies: 275
-- Name: FUNCTION retrieve_file(p_file_path text); Type: COMMENT; Schema: file_storage; Owner: admin
--

COMMENT ON FUNCTION file_storage.retrieve_file(p_file_path text) IS 'Public RPC endpoint to retrieve a file. Handles auth/ownership checks and calls the internal read function.';


--
-- TOC entry 272 (class 1255 OID 24771)
-- Name: sign(json, text, text); Type: FUNCTION; Schema: file_storage; Owner: admin
--

CREATE FUNCTION file_storage.sign(payload json, secret text, algorithm text DEFAULT 'HS256'::text) RETURNS text
    LANGUAGE sql IMMUTABLE
    AS $$
WITH
  header AS (
    SELECT file_storage.url_encode(convert_to('{"alg":"' || algorithm || '","typ":"JWT"}', 'utf8')) AS data
  ),
  payload AS (
    SELECT file_storage.url_encode(convert_to(payload::text, 'utf8')) AS data
  ),
  signables AS (
    SELECT header.data || '.' || payload.data AS data FROM header, payload
  )
SELECT
    signables.data || '.' ||
    file_storage.algorithm_sign(signables.data, secret, algorithm)
FROM signables;
$$;


ALTER FUNCTION file_storage.sign(payload json, secret text, algorithm text) OWNER TO admin;

--
-- TOC entry 3508 (class 0 OID 0)
-- Dependencies: 272
-- Name: FUNCTION sign(payload json, secret text, algorithm text); Type: COMMENT; Schema: file_storage; Owner: admin
--

COMMENT ON FUNCTION file_storage.sign(payload json, secret text, algorithm text) IS 'Creates a JWT token by signing the given payload.';


--
-- TOC entry 274 (class 1255 OID 24772)
-- Name: store_file(bytea); Type: FUNCTION; Schema: file_storage; Owner: admin
--

CREATE FUNCTION file_storage.store_file(bytea) RETURNS uuid
    LANGUAGE plpgsql SECURITY DEFINER
    AS $_$
DECLARE
  v_user_id UUID;
  v_username TEXT;
  v_user_provided_path TEXT;
  v_description TEXT;
  v_storage_path TEXT;
  v_file_id UUID;
BEGIN
  -- Extract user info from JWT and metadata from headers
  SELECT
    current_setting('request.jwt.claims', true)::jsonb ->> 'user_id',
    current_setting('request.jwt.claims', true)::jsonb ->> 'username',
    current_setting('request.headers', true)::jsonb ->> 'file-path',
    current_setting('request.headers', true)::jsonb ->> 'description'
  INTO v_user_id, v_username, v_user_provided_path, v_description;

  -- Validate required information
  IF v_user_id IS NULL OR v_username IS NULL THEN
    RAISE EXCEPTION 'User ID or username not found in JWT claims. Authentication is required.';
  END IF;
  IF v_user_provided_path IS NULL THEN
    RAISE EXCEPTION 'Mandatory ''File-Path'' header is missing.';
  END IF;

  -- Construct the actual storage path
  v_storage_path := v_username || '/' || v_user_provided_path;

  -- Call the internal Python function to write the file to storage
  PERFORM file_storage.internal_write_to_storage(v_storage_path, $1);

  -- Upsert the file's metadata into the database
  INSERT INTO file_storage.files (user_id, file_path, description)
  VALUES (v_user_id, v_user_provided_path, v_description)
  ON CONFLICT (user_id, file_path) DO UPDATE
  SET
    description = EXCLUDED.description,
    updated_at = NOW()
  RETURNING id INTO v_file_id;

  RETURN v_file_id;
END;
$_$;


ALTER FUNCTION file_storage.store_file(bytea) OWNER TO admin;

--
-- TOC entry 3510 (class 0 OID 0)
-- Dependencies: 274
-- Name: FUNCTION store_file(bytea); Type: COMMENT; Schema: file_storage; Owner: admin
--

COMMENT ON FUNCTION file_storage.store_file(bytea) IS 'Public RPC endpoint to store/update a file. Handles auth/metadata and calls the internal write function.';


--
-- TOC entry 232 (class 1255 OID 24734)
-- Name: update_updated_at_column(); Type: FUNCTION; Schema: file_storage; Owner: admin
--

CREATE FUNCTION file_storage.update_updated_at_column() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
   NEW.updated_at = NOW();
   RETURN NEW;
END;
$$;


ALTER FUNCTION file_storage.update_updated_at_column() OWNER TO admin;

--
-- TOC entry 3512 (class 0 OID 0)
-- Dependencies: 232
-- Name: FUNCTION update_updated_at_column(); Type: COMMENT; Schema: file_storage; Owner: admin
--

COMMENT ON FUNCTION file_storage.update_updated_at_column() IS 'Trigger function to automatically update the updated_at timestamp on row modification.';


--
-- TOC entry 270 (class 1255 OID 24769)
-- Name: url_decode(text); Type: FUNCTION; Schema: file_storage; Owner: admin
--

CREATE FUNCTION file_storage.url_decode(data text) RETURNS bytea
    LANGUAGE sql IMMUTABLE
    AS $$
    WITH t AS (SELECT translate(data, '-_', '+/') AS trans),
    rem AS (SELECT length(t.trans) % 4 AS rem FROM t)
    SELECT decode(
        t.trans ||
        CASE WHEN rem.rem = 2 THEN '==' WHEN rem.rem = 3 THEN '=' ELSE '' END,
        'base64'
    ) FROM t, rem;
$$;


ALTER FUNCTION file_storage.url_decode(data text) OWNER TO admin;

--
-- TOC entry 3514 (class 0 OID 0)
-- Dependencies: 270
-- Name: FUNCTION url_decode(data text); Type: COMMENT; Schema: file_storage; Owner: admin
--

COMMENT ON FUNCTION file_storage.url_decode(data text) IS 'URL-safe base64 decoding.';


--
-- TOC entry 269 (class 1255 OID 24768)
-- Name: url_encode(bytea); Type: FUNCTION; Schema: file_storage; Owner: admin
--

CREATE FUNCTION file_storage.url_encode(data bytea) RETURNS text
    LANGUAGE sql IMMUTABLE
    AS $$
    SELECT translate(encode(data, 'base64'), E'+/=\n', '-_');
$$;


ALTER FUNCTION file_storage.url_encode(data bytea) OWNER TO admin;

--
-- TOC entry 3515 (class 0 OID 0)
-- Dependencies: 269
-- Name: FUNCTION url_encode(data bytea); Type: COMMENT; Schema: file_storage; Owner: admin
--

COMMENT ON FUNCTION file_storage.url_encode(data bytea) IS 'URL-safe base64 encoding.';


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- TOC entry 218 (class 1259 OID 24736)
-- Name: files; Type: TABLE; Schema: file_storage; Owner: admin
--

CREATE TABLE file_storage.files (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    file_path text NOT NULL,
    description text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE file_storage.files OWNER TO admin;

--
-- TOC entry 3516 (class 0 OID 0)
-- Dependencies: 218
-- Name: TABLE files; Type: COMMENT; Schema: file_storage; Owner: admin
--

COMMENT ON TABLE file_storage.files IS 'Stores metadata for the files.';


--
-- TOC entry 3517 (class 0 OID 0)
-- Dependencies: 218
-- Name: COLUMN files.id; Type: COMMENT; Schema: file_storage; Owner: admin
--

COMMENT ON COLUMN file_storage.files.id IS 'Unique identifier for the file.';


--
-- TOC entry 3518 (class 0 OID 0)
-- Dependencies: 218
-- Name: COLUMN files.user_id; Type: COMMENT; Schema: file_storage; Owner: admin
--

COMMENT ON COLUMN file_storage.files.user_id IS 'The ID of the user who owns the file.';


--
-- TOC entry 3519 (class 0 OID 0)
-- Dependencies: 218
-- Name: COLUMN files.file_path; Type: COMMENT; Schema: file_storage; Owner: admin
--

COMMENT ON COLUMN file_storage.files.file_path IS 'The user-provided path of the file. The actual storage path is a combination of the user''s ID and this path.';


--
-- TOC entry 3520 (class 0 OID 0)
-- Dependencies: 218
-- Name: COLUMN files.description; Type: COMMENT; Schema: file_storage; Owner: admin
--

COMMENT ON COLUMN file_storage.files.description IS 'A description of the file.';


--
-- TOC entry 3521 (class 0 OID 0)
-- Dependencies: 218
-- Name: COLUMN files.created_at; Type: COMMENT; Schema: file_storage; Owner: admin
--

COMMENT ON COLUMN file_storage.files.created_at IS 'Timestamp of when the file was created.';


--
-- TOC entry 3522 (class 0 OID 0)
-- Dependencies: 218
-- Name: COLUMN files.updated_at; Type: COMMENT; Schema: file_storage; Owner: admin
--

COMMENT ON COLUMN file_storage.files.updated_at IS 'Timestamp of the last update to the file record.';


--
-- TOC entry 217 (class 1259 OID 24717)
-- Name: users; Type: TABLE; Schema: file_storage; Owner: admin
--

CREATE TABLE file_storage.users (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    username text NOT NULL,
    email text NOT NULL,
    password_hash text NOT NULL,
    role name NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT users_role_check CHECK ((role = ANY (ARRAY['storage_admin'::name, 'editor'::name])))
);


ALTER TABLE file_storage.users OWNER TO admin;

--
-- TOC entry 3524 (class 0 OID 0)
-- Dependencies: 217
-- Name: TABLE users; Type: COMMENT; Schema: file_storage; Owner: admin
--

COMMENT ON TABLE file_storage.users IS 'Stores user account information.';


--
-- TOC entry 3525 (class 0 OID 0)
-- Dependencies: 217
-- Name: COLUMN users.id; Type: COMMENT; Schema: file_storage; Owner: admin
--

COMMENT ON COLUMN file_storage.users.id IS 'Unique identifier for the user.';


--
-- TOC entry 3526 (class 0 OID 0)
-- Dependencies: 217
-- Name: COLUMN users.username; Type: COMMENT; Schema: file_storage; Owner: admin
--

COMMENT ON COLUMN file_storage.users.username IS 'Unique username for the user.';


--
-- TOC entry 3527 (class 0 OID 0)
-- Dependencies: 217
-- Name: COLUMN users.email; Type: COMMENT; Schema: file_storage; Owner: admin
--

COMMENT ON COLUMN file_storage.users.email IS 'User''s email address, used for login.';


--
-- TOC entry 3528 (class 0 OID 0)
-- Dependencies: 217
-- Name: COLUMN users.password_hash; Type: COMMENT; Schema: file_storage; Owner: admin
--

COMMENT ON COLUMN file_storage.users.password_hash IS 'Hashed password for the user.';


--
-- TOC entry 3529 (class 0 OID 0)
-- Dependencies: 217
-- Name: COLUMN users.role; Type: COMMENT; Schema: file_storage; Owner: admin
--

COMMENT ON COLUMN file_storage.users.role IS 'The role assigned to the user.';


--
-- TOC entry 3530 (class 0 OID 0)
-- Dependencies: 217
-- Name: COLUMN users.created_at; Type: COMMENT; Schema: file_storage; Owner: admin
--

COMMENT ON COLUMN file_storage.users.created_at IS 'Timestamp of when the user was created.';


--
-- TOC entry 3531 (class 0 OID 0)
-- Dependencies: 217
-- Name: COLUMN users.updated_at; Type: COMMENT; Schema: file_storage; Owner: admin
--

COMMENT ON COLUMN file_storage.users.updated_at IS 'Timestamp of the last update to the user record.';


--
-- TOC entry 3332 (class 2606 OID 24745)
-- Name: files files_pkey; Type: CONSTRAINT; Schema: file_storage; Owner: admin
--

ALTER TABLE ONLY file_storage.files
    ADD CONSTRAINT files_pkey PRIMARY KEY (id);


--
-- TOC entry 3334 (class 2606 OID 24747)
-- Name: files files_user_id_file_path_key; Type: CONSTRAINT; Schema: file_storage; Owner: admin
--

ALTER TABLE ONLY file_storage.files
    ADD CONSTRAINT files_user_id_file_path_key UNIQUE (user_id, file_path);


--
-- TOC entry 3533 (class 0 OID 0)
-- Dependencies: 3334
-- Name: CONSTRAINT files_user_id_file_path_key ON files; Type: COMMENT; Schema: file_storage; Owner: admin
--

COMMENT ON CONSTRAINT files_user_id_file_path_key ON file_storage.files IS 'Ensures that a user cannot have two files with the same path.';


--
-- TOC entry 3326 (class 2606 OID 24731)
-- Name: users users_email_key; Type: CONSTRAINT; Schema: file_storage; Owner: admin
--

ALTER TABLE ONLY file_storage.users
    ADD CONSTRAINT users_email_key UNIQUE (email);


--
-- TOC entry 3328 (class 2606 OID 24727)
-- Name: users users_pkey; Type: CONSTRAINT; Schema: file_storage; Owner: admin
--

ALTER TABLE ONLY file_storage.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- TOC entry 3330 (class 2606 OID 24729)
-- Name: users users_username_key; Type: CONSTRAINT; Schema: file_storage; Owner: admin
--

ALTER TABLE ONLY file_storage.users
    ADD CONSTRAINT users_username_key UNIQUE (username);


--
-- TOC entry 3335 (class 1259 OID 24753)
-- Name: idx_files_user_id; Type: INDEX; Schema: file_storage; Owner: admin
--

CREATE INDEX idx_files_user_id ON file_storage.files USING btree (user_id);


--
-- TOC entry 3534 (class 0 OID 0)
-- Dependencies: 3335
-- Name: INDEX idx_files_user_id; Type: COMMENT; Schema: file_storage; Owner: admin
--

COMMENT ON INDEX file_storage.idx_files_user_id IS 'Index on the user_id column for faster lookups of user files.';


--
-- TOC entry 3323 (class 1259 OID 24732)
-- Name: idx_users_email; Type: INDEX; Schema: file_storage; Owner: admin
--

CREATE INDEX idx_users_email ON file_storage.users USING btree (email);


--
-- TOC entry 3535 (class 0 OID 0)
-- Dependencies: 3323
-- Name: INDEX idx_users_email; Type: COMMENT; Schema: file_storage; Owner: admin
--

COMMENT ON INDEX file_storage.idx_users_email IS 'Index on the email column for faster lookups.';


--
-- TOC entry 3324 (class 1259 OID 24733)
-- Name: idx_users_username; Type: INDEX; Schema: file_storage; Owner: admin
--

CREATE INDEX idx_users_username ON file_storage.users USING btree (username);


--
-- TOC entry 3536 (class 0 OID 0)
-- Dependencies: 3324
-- Name: INDEX idx_users_username; Type: COMMENT; Schema: file_storage; Owner: admin
--

COMMENT ON INDEX file_storage.idx_users_username IS 'Index on the username column for faster lookups.';


--
-- TOC entry 3338 (class 2620 OID 24754)
-- Name: files set_files_updated_at; Type: TRIGGER; Schema: file_storage; Owner: admin
--

CREATE TRIGGER set_files_updated_at BEFORE UPDATE ON file_storage.files FOR EACH ROW EXECUTE FUNCTION file_storage.update_updated_at_column();


--
-- TOC entry 3537 (class 0 OID 0)
-- Dependencies: 3338
-- Name: TRIGGER set_files_updated_at ON files; Type: COMMENT; Schema: file_storage; Owner: admin
--

COMMENT ON TRIGGER set_files_updated_at ON file_storage.files IS 'Trigger to update the updated_at timestamp before a file record is updated.';


--
-- TOC entry 3337 (class 2620 OID 24735)
-- Name: users set_users_updated_at; Type: TRIGGER; Schema: file_storage; Owner: admin
--

CREATE TRIGGER set_users_updated_at BEFORE UPDATE ON file_storage.users FOR EACH ROW EXECUTE FUNCTION file_storage.update_updated_at_column();


--
-- TOC entry 3538 (class 0 OID 0)
-- Dependencies: 3337
-- Name: TRIGGER set_users_updated_at ON users; Type: COMMENT; Schema: file_storage; Owner: admin
--

COMMENT ON TRIGGER set_users_updated_at ON file_storage.users IS 'Trigger to update the updated_at timestamp before a user record is updated.';


--
-- TOC entry 3336 (class 2606 OID 24748)
-- Name: files files_user_id_fkey; Type: FK CONSTRAINT; Schema: file_storage; Owner: admin
--

ALTER TABLE ONLY file_storage.files
    ADD CONSTRAINT files_user_id_fkey FOREIGN KEY (user_id) REFERENCES file_storage.users(id) ON DELETE CASCADE;


--
-- TOC entry 3488 (class 3256 OID 24765)
-- Name: files delete_files; Type: POLICY; Schema: file_storage; Owner: admin
--

CREATE POLICY delete_files ON file_storage.files FOR DELETE USING (((((current_setting('request.jwt.claims'::text, true))::jsonb ->> 'role'::text) = 'storage_admin'::text) OR ((user_id)::text = ((current_setting('request.jwt.claims'::text, true))::jsonb ->> 'user_id'::text))));


--
-- TOC entry 3539 (class 0 OID 0)
-- Dependencies: 3488
-- Name: POLICY delete_files ON files; Type: COMMENT; Schema: file_storage; Owner: admin
--

COMMENT ON POLICY delete_files ON file_storage.files IS 'Allows users to delete their own files, or storage_admins to delete any file.';


--
-- TOC entry 3482 (class 0 OID 24736)
-- Dependencies: 218
-- Name: files; Type: ROW SECURITY; Schema: file_storage; Owner: admin
--

ALTER TABLE file_storage.files ENABLE ROW LEVEL SECURITY;

--
-- TOC entry 3486 (class 3256 OID 24763)
-- Name: files insert_files; Type: POLICY; Schema: file_storage; Owner: admin
--

CREATE POLICY insert_files ON file_storage.files FOR INSERT WITH CHECK (((((current_setting('request.jwt.claims'::text, true))::jsonb ->> 'role'::text) = ANY (ARRAY['storage_admin'::text, 'editor'::text])) AND ((user_id)::text = ((current_setting('request.jwt.claims'::text, true))::jsonb ->> 'user_id'::text))));


--
-- TOC entry 3540 (class 0 OID 0)
-- Dependencies: 3486
-- Name: POLICY insert_files ON files; Type: COMMENT; Schema: file_storage; Owner: admin
--

COMMENT ON POLICY insert_files ON file_storage.files IS 'Allows storage_admins and editors to insert files for themselves.';


--
-- TOC entry 3485 (class 3256 OID 24762)
-- Name: files select_files; Type: POLICY; Schema: file_storage; Owner: admin
--

CREATE POLICY select_files ON file_storage.files FOR SELECT USING (((((current_setting('request.jwt.claims'::text, true))::jsonb ->> 'role'::text) = 'storage_admin'::text) OR ((user_id)::text = ((current_setting('request.jwt.claims'::text, true))::jsonb ->> 'user_id'::text))));


--
-- TOC entry 3541 (class 0 OID 0)
-- Dependencies: 3485
-- Name: POLICY select_files ON files; Type: COMMENT; Schema: file_storage; Owner: admin
--

COMMENT ON POLICY select_files ON file_storage.files IS 'Allows users to select their own files, or all files if they are an storage_admin.';


--
-- TOC entry 3483 (class 3256 OID 24760)
-- Name: users select_own_user; Type: POLICY; Schema: file_storage; Owner: admin
--

CREATE POLICY select_own_user ON file_storage.users FOR SELECT USING (((id)::text = ((current_setting('request.jwt.claims'::text, true))::jsonb ->> 'user_id'::text)));


--
-- TOC entry 3542 (class 0 OID 0)
-- Dependencies: 3483
-- Name: POLICY select_own_user ON users; Type: COMMENT; Schema: file_storage; Owner: admin
--

COMMENT ON POLICY select_own_user ON file_storage.users IS 'Users can only view their own user record.';


--
-- TOC entry 3487 (class 3256 OID 24764)
-- Name: files update_files; Type: POLICY; Schema: file_storage; Owner: admin
--

CREATE POLICY update_files ON file_storage.files FOR UPDATE USING (((((current_setting('request.jwt.claims'::text, true))::jsonb ->> 'role'::text) = 'storage_admin'::text) OR ((user_id)::text = ((current_setting('request.jwt.claims'::text, true))::jsonb ->> 'user_id'::text))));


--
-- TOC entry 3543 (class 0 OID 0)
-- Dependencies: 3487
-- Name: POLICY update_files ON files; Type: COMMENT; Schema: file_storage; Owner: admin
--

COMMENT ON POLICY update_files ON file_storage.files IS 'Allows users to update their own files, or storage_admins to update any file.';


--
-- TOC entry 3484 (class 3256 OID 24761)
-- Name: users update_own_user; Type: POLICY; Schema: file_storage; Owner: admin
--

CREATE POLICY update_own_user ON file_storage.users FOR UPDATE USING (((id)::text = ((current_setting('request.jwt.claims'::text, true))::jsonb ->> 'user_id'::text)));


--
-- TOC entry 3544 (class 0 OID 0)
-- Dependencies: 3484
-- Name: POLICY update_own_user ON users; Type: COMMENT; Schema: file_storage; Owner: admin
--

COMMENT ON POLICY update_own_user ON file_storage.users IS 'Users can only update their own user record.';


--
-- TOC entry 3481 (class 0 OID 24717)
-- Dependencies: 217
-- Name: users; Type: ROW SECURITY; Schema: file_storage; Owner: admin
--

ALTER TABLE file_storage.users ENABLE ROW LEVEL SECURITY;

--
-- TOC entry 3496 (class 0 OID 0)
-- Dependencies: 8
-- Name: SCHEMA file_storage; Type: ACL; Schema: -; Owner: admin
--

GRANT USAGE ON SCHEMA file_storage TO storage_admin;
GRANT USAGE ON SCHEMA file_storage TO editor;
GRANT USAGE ON SCHEMA file_storage TO authenticator;


--
-- TOC entry 3501 (class 0 OID 0)
-- Dependencies: 268
-- Name: FUNCTION internal_read_from_storage(p_storage_path text); Type: ACL; Schema: file_storage; Owner: admin
--

REVOKE ALL ON FUNCTION file_storage.internal_read_from_storage(p_storage_path text) FROM PUBLIC;
GRANT ALL ON FUNCTION file_storage.internal_read_from_storage(p_storage_path text) TO storage_admin;


--
-- TOC entry 3503 (class 0 OID 0)
-- Dependencies: 233
-- Name: FUNCTION internal_write_to_storage(p_storage_path text, p_file_data bytea); Type: ACL; Schema: file_storage; Owner: admin
--

REVOKE ALL ON FUNCTION file_storage.internal_write_to_storage(p_storage_path text, p_file_data bytea) FROM PUBLIC;
GRANT ALL ON FUNCTION file_storage.internal_write_to_storage(p_storage_path text, p_file_data bytea) TO storage_admin;


--
-- TOC entry 3505 (class 0 OID 0)
-- Dependencies: 273
-- Name: FUNCTION login(email text, password text, OUT token text); Type: ACL; Schema: file_storage; Owner: admin
--

GRANT ALL ON FUNCTION file_storage.login(email text, password text, OUT token text) TO authenticator;


--
-- TOC entry 3507 (class 0 OID 0)
-- Dependencies: 275
-- Name: FUNCTION retrieve_file(p_file_path text); Type: ACL; Schema: file_storage; Owner: admin
--

REVOKE ALL ON FUNCTION file_storage.retrieve_file(p_file_path text) FROM PUBLIC;
GRANT ALL ON FUNCTION file_storage.retrieve_file(p_file_path text) TO editor;
GRANT ALL ON FUNCTION file_storage.retrieve_file(p_file_path text) TO storage_admin;


--
-- TOC entry 3509 (class 0 OID 0)
-- Dependencies: 272
-- Name: FUNCTION sign(payload json, secret text, algorithm text); Type: ACL; Schema: file_storage; Owner: admin
--

REVOKE ALL ON FUNCTION file_storage.sign(payload json, secret text, algorithm text) FROM PUBLIC;


--
-- TOC entry 3511 (class 0 OID 0)
-- Dependencies: 274
-- Name: FUNCTION store_file(bytea); Type: ACL; Schema: file_storage; Owner: admin
--

REVOKE ALL ON FUNCTION file_storage.store_file(bytea) FROM PUBLIC;
GRANT ALL ON FUNCTION file_storage.store_file(bytea) TO editor;


--
-- TOC entry 3513 (class 0 OID 0)
-- Dependencies: 232
-- Name: FUNCTION update_updated_at_column(); Type: ACL; Schema: file_storage; Owner: admin
--

GRANT ALL ON FUNCTION file_storage.update_updated_at_column() TO storage_admin;


--
-- TOC entry 3523 (class 0 OID 0)
-- Dependencies: 218
-- Name: TABLE files; Type: ACL; Schema: file_storage; Owner: admin
--

GRANT ALL ON TABLE file_storage.files TO storage_admin;
GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE file_storage.files TO editor;


--
-- TOC entry 3532 (class 0 OID 0)
-- Dependencies: 217
-- Name: TABLE users; Type: ACL; Schema: file_storage; Owner: admin
--

GRANT ALL ON TABLE file_storage.users TO storage_admin;
GRANT SELECT,UPDATE ON TABLE file_storage.users TO editor;


-- Completed on 2025-08-11 08:04:12 UTC

--
-- PostgreSQL database dump complete
--

--
-- Database "postgres" dump
--

\connect postgres

--
-- PostgreSQL database dump
--

-- Dumped from database version 15.13
-- Dumped by pg_dump version 15.5

-- Started on 2025-08-11 08:04:12 UTC

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

-- Completed on 2025-08-11 08:04:12 UTC

--
-- PostgreSQL database dump complete
--

-- Completed on 2025-08-11 08:04:12 UTC

--
-- PostgreSQL database cluster dump complete
--



--- Insert initial users


-- Insert an storage_admin user
INSERT INTO file_storage.users (username, email, password_hash, role)
VALUES (
    'storage_admin_user',
    'storage_admin@example.com',
    crypt('password123', gen_salt('bf')),
    'storage_admin'
);

-- Insert the first editor user
INSERT INTO file_storage.users (username, email, password_hash, role)
VALUES (
    'editor_one',
    'editor1@example.com',
    crypt('password123', gen_salt('bf')),
    'editor'
);

-- Insert the second editor user
INSERT INTO file_storage.users (username, email, password_hash, role)
VALUES (
    'editor_two',
    'editor2@example.com',
    crypt('password123', gen_salt('bf')),
    'editor'
);
