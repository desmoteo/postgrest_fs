Secure File Storage Backend
This document outlines the architecture and API for a secure, private file storage backend. The system uses a PostgreSQL database with PostgREST to provide a RESTful API, and a PL/Python function to store files on a configurable backend (like a local filesystem or S3), keeping binary data out of the database.

The primary goal is to provide a foundation for a web application where users can log in, upload, update, and download their private files.

Key Features
JWT Authentication: User access is controlled via JSON Web Tokens.

Role-Based Access Control (RBAC): The system defines admin and editor roles with distinct permissions.

Row-Level Security (RLS): PostgreSQL's RLS is used to ensure users can only access their own data.

Abstracted File Storage: pyfilesystem is used within the database to allow for flexible storage backends (local, S3, etc.) without changing the API.

Secure by Design: Internal functions, especially for JWT signing, are isolated in a non-exposed database schema to prevent tampering.

User Roles
The system has two primary roles that are included in the JWT:

editor: This is the standard user role. Editors can upload, update, download, and delete their own files. They cannot see or interact with files belonging to other users.

admin: An administrator. This role has the ability to view the metadata of all files in the system for administrative purposes. However, due to security constraints in the API functions, an admin cannot download another user's files.

API Endpoints
The following endpoints are exposed by the PostgREST API.

1. User Login
This endpoint authenticates a user and returns a signed JWT.

HTTP Method: POST

URL: /rpc/login

Headers:

Content-Type: application/json

Request Body (JSON):

{
  "email": "user@example.com",
  "password": "user_password"
}

Success Response (200 OK):

Body (JSON): An array containing an object with the token.

[
  {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiZWRpdG9yIiwiZXhwIjoxNjE..."
  }
]

Error Response (400 Bad Request):

If credentials are invalid.

Body (JSON):

{
  "message": "Invalid email or password"
}

2. Store / Update File
This endpoint allows an authenticated user to upload a new file or update an existing one. The operation is an "upsert": if a file with the same path already exists for the user, it is overwritten.

HTTP Method: POST

URL: /rpc/store_file

Headers:

Authorization: Bearer <your_jwt_token>

Content-Type: application/octet-stream

File-Path: path/to/your/file.txt (Required. The desired path for the file in storage.)

Description: A brief description of the file. (Optional.)

Request Body: The raw binary data of the file.

Success Response (200 OK):

Body (JSON): The unique UUID of the file record in the database.

"a1b2c3d4-e5f6-7890-1234-567890abcdef"

Error Response (401 Unauthorized):

If the JWT is missing or invalid.

3. Retrieve File
This endpoint allows an authenticated user to download a file they own.

HTTP Method: GET

URL: /rpc/retrieve_file

Query Parameters:

p_file_path: The path of the file to download (e.g., ?p_file_path=path/to/your/file.txt).

Headers:

Authorization: Bearer <your_jwt_token>

Success Response (200 OK):

Body: The raw binary data of the requested file.

Error Response (400 Bad Request):

If the user does not own the file or the file does not exist.

Body (JSON):

{
  "message": "File not found."
}

Error Response (401 Unauthorized):

If the JWT is missing or invalid.

GUI Generation Instructions for AI
To build a web application for this backend, the AI should generate the following components:

Login Page:

A form with email and password fields.

On submit, it should call the POST /rpc/login endpoint.

Upon successful login, the returned JWT must be stored securely in the browser (e.g., in an HttpOnly cookie or local storage). This token must be included as a Bearer token in the Authorization header for all subsequent API calls.

File Manager Page (Main authenticated view):

This page should display a list of the user's files. The file metadata can be retrieved by making a GET request to the /files endpoint, which will automatically be filtered by the user's JWT thanks to RLS.

File Upload/Update:

Provide a file input button.

Allow the user to specify a File-Path (e.g., in a text input).

On upload, call the POST /rpc/store_file endpoint with the file's binary data and the required headers.

After a successful upload, the file list should be refreshed.

File Download:

Each file in the list should have a "Download" button.

Clicking it should trigger a GET request to /rpc/retrieve_file with the correct p_file_path parameter.

The browser should be prompted to save the returned binary data.

Logout Button:

This should clear the stored JWT and redirect the user to the login page.