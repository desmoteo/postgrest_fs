export const api = {
  login: async (email, password) => {
    try {
      const response = await fetch('http://localhost:81/rpc/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Login failed');
      }
      const data = await response.json();
      return { success: true, token: data.token };
    } catch (error) {
      return { success: false, error: error.message };
    }
  },

  listFiles: async (token) => {
    try {
      const response = await fetch('http://localhost:81/files', {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Failed to fetch files');
      }
      const files = await response.json();
      return { success: true, files };
    } catch (error) {
      return { success: false, error: error.message };
    }
  },

  retrieveFile: async (token, filePath) => {
    try {
      const response = await fetch('http://localhost:81/rpc/retrieve_file', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/octet-stream',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ p_file_path: filePath }),
      });
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Failed to retrieve file');
      }
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filePath.split('/').pop();
      document.body.appendChild(a);
      a.click();
      a.remove();
      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  },

  storeFile: async (token, filePath, file) => {
    try {
      const response = await fetch('http://localhost:81/rpc/store_file', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/octet-stream',
          Authorization: `Bearer ${token}`,
          'File-Path': filePath,
        },
        body: file,
      });
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Failed to store file');
      }
      return { success: true, message: 'File stored successfully' };
    } catch (error) {
      return { success: false, error: error.message };
    }
  },
};
