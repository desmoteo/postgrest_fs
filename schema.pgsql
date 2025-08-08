-- init.sql
-- This script initializes the database schema, tables, functions, roles, and RLS policies.

-- Create the schema for our file storage application
CREATE SCHEMA file_storage;
COMMENT ON SCHEMA file_storage IS 'Schema for the file storage application, containing all related tables, functions, and views.';

-- Enable the PL/Python extension
CREATE EXTENSION IF NOT EXISTS plpython3u;
COMMENT ON EXTENSION plpython3u IS 'Enables the use of PL/Python3 procedural language.';

-- Enable the pgcrypto extension for password hashing
CREATE EXTENSION IF NOT EXISTS pgcrypto;
COMMENT ON EXTENSION pgcrypto IS 'Provides cryptographic functions for PostgreSQL.';

--------------------------------------------------
-- PGJWT FUNCTIONS (for signing JWTs in SQL)
--------------------------------------------------

CREATE OR REPLACE FUNCTION file_storage.url_encode(data bytea) RETURNS text LANGUAGE sql AS $$
    SELECT translate(encode(data, 'base64'), E'+/=\n', '-_');
$$ IMMUTABLE;
COMMENT ON FUNCTION file_storage.url_encode(bytea) IS 'URL-safe base64 encoding.';

CREATE OR REPLACE FUNCTION file_storage.url_decode(data text) RETURNS bytea LANGUAGE sql AS $$
    WITH t AS (SELECT translate(data, '-_', '+/') AS trans),
    rem AS (SELECT length(t.trans) % 4 AS rem FROM t)
    SELECT decode(
        t.trans ||
        CASE WHEN rem.rem = 2 THEN '==' WHEN rem.rem = 3 THEN '=' ELSE '' END,
        'base64'
    ) FROM t, rem;
$$ IMMUTABLE;
COMMENT ON FUNCTION file_storage.url_decode(text) IS 'URL-safe base64 decoding.';

CREATE OR REPLACE FUNCTION file_storage.algorithm_sign(signables text, secret text, algorithm text)
RETURNS text LANGUAGE sql AS $$
WITH
  alg AS (
    SELECT CASE
      WHEN algorithm = 'HS256' THEN 'sha256'
      WHEN algorithm = 'HS384' THEN 'sha384'
      WHEN algorithm = 'HS512' THEN 'sha512'
      ELSE '' END AS id
  )
SELECT file_storage.url_encode(public.hmac(signables, secret, alg.id)) FROM alg;
$$ IMMUTABLE;
COMMENT ON FUNCTION file_storage.algorithm_sign(text, text, text) IS 'Signs a text string using HMAC with the specified SHA algorithm.';

CREATE OR REPLACE FUNCTION file_storage.sign(payload json, secret text, algorithm text DEFAULT 'HS256')
RETURNS text LANGUAGE sql AS $$
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
$$ IMMUTABLE;
COMMENT ON FUNCTION file_storage.sign(json, text, text) IS 'Creates a JWT token by signing the given payload.';

--------------------------------------------------
-- ROLES
--------------------------------------------------

-- Create roles for different levels of access
CREATE ROLE storage_admin;
COMMENT ON ROLE storage_admin IS 'storage_administrator role with full access to all resources.';
CREATE ROLE editor;
COMMENT ON ROLE editor IS 'Editor role with read/write access to owned resources.';

-- Create a limited role for anonymous users to authenticate
CREATE ROLE authenticator NOINHERIT;
COMMENT ON ROLE authenticator IS 'A limited role for anonymous users, can only execute the login function.';

-- Grant usage on the schema to all roles
GRANT USAGE ON SCHEMA file_storage TO storage_admin, editor, authenticator;

--------------------------------------------------
-- USERS TABLE
--------------------------------------------------

CREATE TABLE file_storage.users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role NAME NOT NULL CHECK (role IN ('storage_admin', 'editor')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
COMMENT ON TABLE file_storage.users IS 'Stores user account information.';
COMMENT ON COLUMN file_storage.users.id IS 'Unique identifier for the user.';
COMMENT ON COLUMN file_storage.users.username IS 'Unique username for the user.';
COMMENT ON COLUMN file_storage.users.email IS 'User''s email address, used for login.';
COMMENT ON COLUMN file_storage.users.password_hash IS 'Hashed password for the user.';
COMMENT ON COLUMN file_storage.users.role IS 'The role assigned to the user.';
COMMENT ON COLUMN file_storage.users.created_at IS 'Timestamp of when the user was created.';
COMMENT ON COLUMN file_storage.users.updated_at IS 'Timestamp of the last update to the user record.';

-- Indexes for the users table
CREATE INDEX idx_users_email ON file_storage.users(email);
COMMENT ON INDEX file_storage.idx_users_email IS 'Index on the email column for faster lookups.';
CREATE INDEX idx_users_username ON file_storage.users(username);
COMMENT ON INDEX file_storage.idx_users_username IS 'Index on the username column for faster lookups.';


-- Trigger to update the updated_at timestamp on user update
CREATE OR REPLACE FUNCTION file_storage.update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
   NEW.updated_at = NOW();
   RETURN NEW;
END;
$$ LANGUAGE plpgsql;
COMMENT ON FUNCTION file_storage.update_updated_at_column() IS 'Trigger function to automatically update the updated_at timestamp on row modification.';

CREATE TRIGGER set_users_updated_at
BEFORE UPDATE ON file_storage.users
FOR EACH ROW
EXECUTE FUNCTION file_storage.update_updated_at_column();
COMMENT ON TRIGGER set_users_updated_at ON file_storage.users IS 'Trigger to update the updated_at timestamp before a user record is updated.';

--------------------------------------------------
-- FILES TABLE
--------------------------------------------------

CREATE TABLE file_storage.files (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES file_storage.users(id) ON DELETE CASCADE,
    file_path TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, file_path)
);
COMMENT ON TABLE file_storage.files IS 'Stores metadata for the files.';
COMMENT ON COLUMN file_storage.files.id IS 'Unique identifier for the file.';
COMMENT ON COLUMN file_storage.files.user_id IS 'The ID of the user who owns the file.';
COMMENT ON COLUMN file_storage.files.file_path IS 'The user-provided path of the file. The actual storage path is a combination of the user''s ID and this path.';
COMMENT ON COLUMN file_storage.files.description IS 'A description of the file.';
COMMENT ON COLUMN file_storage.files.created_at IS 'Timestamp of when the file was created.';
COMMENT ON COLUMN file_storage.files.updated_at IS 'Timestamp of the last update to the file record.';
COMMENT ON CONSTRAINT files_user_id_file_path_key ON file_storage.files IS 'Ensures that a user cannot have two files with the same path.';


-- Indexes for the files table
CREATE INDEX idx_files_user_id ON file_storage.files(user_id);
COMMENT ON INDEX file_storage.idx_files_user_id IS 'Index on the user_id column for faster lookups of user files.';

-- Trigger to update the updated_at timestamp on file update
CREATE TRIGGER set_files_updated_at
BEFORE UPDATE ON file_storage.files
FOR EACH ROW
EXECUTE FUNCTION file_storage.update_updated_at_column();
COMMENT ON TRIGGER set_files_updated_at ON file_storage.files IS 'Trigger to update the updated_at timestamp before a file record is updated.';




--------------------------------------------------
-- AUTHENTICATION
--------------------------------------------------

CREATE OR REPLACE FUNCTION file_storage.login(email TEXT, password TEXT, OUT token text) AS $$
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
$$ LANGUAGE plpgsql SECURITY DEFINER;
COMMENT ON FUNCTION file_storage.login(TEXT, TEXT, OUT text) IS 'Authenticates a user and returns a signed JWT.';


--------------------------------------------------
-- INTERNAL FILE STORAGE FUNCTIONS (PL/Python)
--------------------------------------------------

-- Internal function to write data to the storage backend.
CREATE OR REPLACE FUNCTION file_storage.internal_write_to_storage(p_storage_path TEXT, p_file_data BYTEA)
RETURNS void AS $$
  import os
  from fs import open_fs

  storage_url = os.environ.get('STORAGE_BACKEND_URL', 'osfs:///var/storage')
  with open_fs(storage_url) as home_fs:
    dir_path = os.path.dirname(p_storage_path)
    if dir_path:
        home_fs.makedirs(dir_path, recreate=True)
    home_fs.writebytes(p_storage_path, p_file_data)
$$ LANGUAGE plpython3u SECURITY DEFINER;
COMMENT ON FUNCTION file_storage.internal_write_to_storage(TEXT, BYTEA) IS '[INTERNAL] Writes a file to the physical storage backend. Should only be called by wrapper functions.';

-- Internal function to read data from the storage backend.
CREATE OR REPLACE FUNCTION file_storage.internal_read_from_storage(p_storage_path TEXT)
RETURNS BYTEA AS $$
  import os
  from fs import open_fs

  storage_url = os.environ.get('STORAGE_BACKEND_URL', 'osfs:///var/storage')
  with open_fs(storage_url) as home_fs:
    if not home_fs.exists(p_storage_path):
      plpy.error("File not found in storage backend.")
    return home_fs.readbytes(p_storage_path)
$$ LANGUAGE plpython3u SECURITY DEFINER;
COMMENT ON FUNCTION file_storage.internal_read_from_storage(TEXT) IS '[INTERNAL] Reads a file from the physical storage backend. Should only be called by wrapper functions.';


--------------------------------------------------
-- PUBLIC FILE STORAGE FUNCTIONS (PL/pgSQL)
--------------------------------------------------

-- Public function to store or update a file (upsert). This is the RPC endpoint.
CREATE OR REPLACE FUNCTION file_storage.store_file(BYTEA)
RETURNS UUID AS $$
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
$$ LANGUAGE plpgsql;
COMMENT ON FUNCTION file_storage.store_file(BYTEA) IS 'Public RPC endpoint to store/update a file. Handles auth/metadata and calls the internal write function.';

-- Public function to retrieve a file. This is the RPC endpoint.
CREATE OR REPLACE FUNCTION file_storage.retrieve_file(p_file_path TEXT)
RETURNS BYTEA AS $$
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
$$ LANGUAGE plpgsql;
COMMENT ON FUNCTION file_storage.retrieve_file(TEXT) IS 'Public RPC endpoint to retrieve a file. Handles auth/ownership checks and calls the internal read function.';


GRANT EXECUTE ON FUNCTION file_storage.sign(json, text, text) TO admin;

REVOKE ALL ON FUNCTION file_storage.sign(json, text, text) FROM PUBLIC;
--------------------------------------------------
-- RLS POLICIES
--------------------------------------------------

-- Enable RLS on the tables
ALTER TABLE file_storage.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE file_storage.files ENABLE ROW LEVEL SECURITY;

-- Policies for the 'users' table
CREATE POLICY select_own_user ON file_storage.users FOR SELECT
    USING (id::text = current_setting('request.jwt.claims', true)::jsonb->>'user_id');
COMMENT ON POLICY select_own_user ON file_storage.users IS 'Users can only view their own user record.';

CREATE POLICY update_own_user ON file_storage.users FOR UPDATE
    USING (id::text = current_setting('request.jwt.claims', true)::jsonb->>'user_id');
COMMENT ON POLICY update_own_user ON file_storage.users IS 'Users can only update their own user record.';

-- Policies for the 'files' table
CREATE POLICY select_files ON file_storage.files FOR SELECT
    USING (
        (current_setting('request.jwt.claims', true)::jsonb->>'role' = 'storage_admin') OR
        (user_id::text = current_setting('request.jwt.claims', true)::jsonb->>'user_id')
    );
COMMENT ON POLICY select_files ON file_storage.files IS 'Allows users to select their own files, or all files if they are an storage_admin.';

CREATE POLICY insert_files ON file_storage.files FOR INSERT
    WITH CHECK (
        (current_setting('request.jwt.claims', true)::jsonb->>'role' IN ('storage_admin', 'editor')) AND
        (user_id::text = current_setting('request.jwt.claims', true)::jsonb->>'user_id')
    );
COMMENT ON POLICY insert_files ON file_storage.files IS 'Allows storage_admins and editors to insert files for themselves.';

CREATE POLICY update_files ON file_storage.files FOR UPDATE
    USING (
        (current_setting('request.jwt.claims', true)::jsonb->>'role' = 'storage_admin') OR
        (user_id::text = current_setting('request.jwt.claims', true)::jsonb->>'user_id')
    );
COMMENT ON POLICY update_files ON file_storage.files IS 'Allows users to update their own files, or storage_admins to update any file.';

CREATE POLICY delete_files ON file_storage.files FOR DELETE
    USING (
        (current_setting('request.jwt.claims', true)::jsonb->>'role' = 'storage_admin') OR
        (user_id::text = current_setting('request.jwt.claims', true)::jsonb->>'user_id')
    );
COMMENT ON POLICY delete_files ON file_storage.files IS 'Allows users to delete their own files, or storage_admins to delete any file.';

-- Make sure storage_admin or editor can never call internal functions such as 'sign'

REVOKE EXECUTE ON FUNCTION file_storage.sign(TEXT, TEXT) FROM storage_admin, editor;

--------------------------------------------------
-- GRANT PERMISSIONS
--------------------------------------------------

-- Grant permissions for the 'storage_admin' role
GRANT ALL ON ALL TABLES IN SCHEMA file_storage TO storage_admin;
GRANT ALL ON ALL FUNCTIONS IN SCHEMA file_storage TO storage_admin;
GRANT ALL ON ALL SEQUENCES IN SCHEMA file_storage TO storage_admin;

-- Grant permissions for the 'editor' role
GRANT SELECT, INSERT, UPDATE, DELETE ON file_storage.files TO editor;
GRANT SELECT, UPDATE ON file_storage.users TO editor;
-- **FIX:** This grant is now correct and only includes functions the editor role needs.
GRANT EXECUTE ON FUNCTION file_storage.store_file(BYTEA), file_storage.retrieve_file(TEXT) TO editor;

-- Grant permissions for the 'authenticator' role
GRANT EXECUTE ON FUNCTION file_storage.login(TEXT, TEXT, OUT text) TO authenticator;

-- Add these statements after the table creation in your init.sql

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
