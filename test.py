import requests
import json
import base64

# --- Configuration ---
# The URL now points to the Traefik proxy, which listens on port 80.
BASE_URL = "http://localhost:81" 

# --- User Credentials ---
users = {
    "storage_admin": {"email": "storage_admin@example.com", "password": "password123"},
    "editor1": {"email": "editor1@example.com", "password": "password123"},
    "editor2": {"email": "editor2@example.com", "password": "password123"},
}
tokens = {}

# --- API Helper Functions ---

def login(email, password):
    """Logs in a user and returns a JWT."""
    url = f"{BASE_URL}/rpc/login"
    payload = {"email": email, "password": password}
    headers = {"Content-Type": "application/json"}
    
    try:
        response = requests.post(url, data=json.dumps(payload), headers=headers)
        response.raise_for_status()
        # **FIX:** The response from PostgREST is an array containing an object.
        # We need to extract the 'token' value from the first object in the array.
        token = response.json()['token']
        print(f"Successfully logged in as {email}")
        return token
    except requests.exceptions.RequestException as e:
        print(f"Error logging in as {email}: {e}")
        print(f"Response body: {e.response.text}")
        return None

def upload_file(token, user_provided_path, file_content, description):
    """Uploads a file to the storage."""
    url = f"{BASE_URL}/rpc/store_file"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/octet-stream",
        "File-Path": user_provided_path,
        "Description": description,
    }
    
    try:
        response = requests.post(url, data=file_content, headers=headers)
        response.raise_for_status()
        print(f"Successfully uploaded '{user_provided_path}'. File ID: {response.json()}")
        return True
    except requests.exceptions.RequestException as e:
        print(f"Error uploading file '{user_provided_path}': {e.response.status_code}")
        print(f"Response body: {e.response.text}")
        return False

def download_file(token, user_provided_path):
    """Attempts to download a file from the storage."""
    url = f"{BASE_URL}/rpc/retrieve_file"
    params = {"p_file_path": user_provided_path}
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        print(f"\nAttempting to download '{user_provided_path}'...")
        response = requests.get(url, params=params, headers=headers)
        response.raise_for_status()
        print(f"SUCCESS: Downloaded '{user_provided_path}'. Size: {len(response.content)} bytes.")
        return response.content
    except requests.exceptions.RequestException as e:
        print(f"FAILURE: Could not download '{user_provided_path}'. Status: {e.response.status_code}")
        print(f"Reason: {e.response.json().get('message')}")
        return None

def test_internal_sign_function_access(token):
    """Attempts to call an internal-only function directly, which should fail."""
    url = f"{BASE_URL}/rpc/sign"
    # Dummy payload for the test. The content doesn't matter as the request should be rejected.
    payload = {"payload": {"data": "test"}, "secret": "any_secret"}
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    try:
        print(f"\nAttempting to call internal function 'sign' as an editor...")
        response = requests.post(url, data=json.dumps(payload), headers=headers)

        # We expect this to fail with a 4xx error code.
        if response.status_code >= 400:
            print(f"SUCCESS: Received expected error. Status: {response.status_code}")
            print(f"Reason: {response.json().get('message')}")
            return True
        else:
            print(f"FAILURE: Unexpectedly succeeded in calling internal function 'sign': {response.status_code}")
            return False

    except requests.exceptions.RequestException as e:
        # This is also a successful outcome in this context.
        print(f"SUCCESS: Request failed as expected. Status: {e.response.status_code}")
        print(f"Reason: {e.response.text}")
        return True

def test_internal_write_to_storage_function_access(token):
    """Attempts to call an internal-only function directly, which should fail."""
    url = f"{BASE_URL}/rpc/internal_write_to_storage"
    # Dummy payload for the test. The content doesn't matter as the request should be rejected.
    payload = {"p_storage_path": "dummy/path.txt", "p_file_data": base64.b64encode(b"test content").decode()}
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }



    try:
        print(f"\nAttempting to call internal function 'write_to_storage' as an editor with payload: {payload}...")
        response = requests.post(url, data=json.dumps(payload), headers=headers)

        # We expect this to fail with a 4xx error code.
        if response.status_code >= 400:
            print(f"SUCCESS: Received expected error. Status: {response.status_code}")
            print(f"Reason: {response.json().get('message')}")
            return True
        else:
            print(f"FAILURE: Unexpectedly succeeded in calling internal function 'write_to_storage': {response.status_code}")
            return False

    except requests.exceptions.RequestException as e:
        # This is also a successful outcome in this context.
        print(f"SUCCESS: Request failed as expected. Status: {e.response.status_code}")
        print(f"Reason: {e.response.text}")
        return True

def test_internal_read_from_storage_function_access(token):
    """Attempts to call an internal-only function directly, which should fail."""
    url = f"{BASE_URL}/rpc/internal_read_from_storage"
    # Dummy payload for the test. The content doesn't matter as the request should be rejected.
    payload = {"p_storage_path": "dummy/path.txt"}
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    try:
        print(f"\nAttempting to call internal function 'read_from_storage' as an editor with payload: {payload}...")
        response = requests.post(url, data=json.dumps(payload), headers=headers)

        # We expect this to fail with a 4xx error code.
        if response.status_code >= 400:
            print(f"SUCCESS: Received expected error. Status: {response.status_code}")
            print(f"Reason: {response.json().get('message')}")
            return True
        else:
            print(f"FAILURE: Unexpectedly succeeded in calling internal function 'read_from_storage': {response.status_code}")
            return False

    except requests.exceptions.RequestException as e:
        # This is also a successful outcome in this context.
        print(f"SUCCESS: Request failed as expected. Status: {e.response.status_code}")
        print(f"Reason: {e.response.text}")
        return True    
    
# --- Main Test Execution ---

if __name__ == "__main__":
    # 1. Authenticate all users and get their tokens
    print("--- 1. Logging in all users ---")
    for name, creds in users.items():
        tokens[name] = login(creds["email"], creds["password"])
    
    print("\n" + "="*40 + "\n")

    # 2. Editor 1 uploads a private file
    print("--- 2. Editor 1 uploads a file ---")
    editor1_token = tokens.get("editor1")
    file_path_to_test = "project_alpha/secrets.txt"
    file_content = b"This is a secret message from Editor 1."
    
    if editor1_token:
        upload_file(
            token=editor1_token,
            user_provided_path=file_path_to_test,
            file_content=file_content,
            description="Top secret project plans"
        )

    print("\n" + "="*40 + "\n")

    # 3. Test download permissions
    print("--- 3. Testing Download Permissions ---")
    if editor1_token:
        # Test A: Editor 1 tries to download their OWN file (should succeed)
        print("--- Test A: Owner (Editor 1) downloads their own file ---")
        download_file(editor1_token, file_path_to_test)

        # Test B: Editor 2 tries to download Editor 1's file (should fail)
        editor2_token = tokens.get("editor2")
        if editor2_token:
            print("\n--- Test B: Another user (Editor 2) tries to download the file ---")
            download_file(editor2_token, file_path_to_test)

        # Test C: Admin tries to download Editor 1's file (should fail)
        # NOTE: Even though the RLS policy for SELECT on the `files` table allows an admin
        # to see the metadata, our `retrieve_file` function has an explicit ownership
        # check, which prevents an admin from downloading another user's file via this RPC.
        # This is a defense-in-depth security measure.
        admin_token = tokens.get("storage_admin")
        if admin_token:
            print("\n--- Test C: Admin tries to download the file ---")
            download_file(admin_token, file_path_to_test)
            
        # Test D: test all user against fuctions thay should not be able to access:
        
        for user, token in tokens.items():
            print(f"\n--- Test D: {user} tries to call internal function 'sign' ---")
            test_internal_sign_function_access(token)
            print(f"\n--- Test D: {user} tries to call internal function 'write_to_storage' ---")
            test_internal_write_to_storage_function_access(token)
            print(f"\n--- Test D: {user} tries to call internal function 'read_from_storage' ---")
            test_internal_read_from_storage_function_access(token)
