import React, { useState } from 'react';
import { Link } from 'react-router-dom';

export default function FileUploadPage({ token, api }) {
  const [selectedFile, setSelectedFile] = useState(null);
  const [filePath, setFilePath] = useState('');
  const [message, setMessage] = useState('');

  const handleFileChange = (event) => {
    setSelectedFile(event.target.files[0]);
  };

  const handleFilePathChange = (event) => {
    setFilePath(event.target.value);
  };

  const handleUpload = async (e) => {
    e.preventDefault();
    if (!selectedFile || !filePath) {
      setMessage('Please select a file and enter a file path.');
      return;
    }
    const result = await api.storeFile(token, filePath, selectedFile);
    setMessage(result.success ? result.message : 'Upload failed: ' + result.error);
  };

  return (
    <div>
      <h2>Upload/Update File</h2>
      <form onSubmit={handleUpload}>
        <div>
          <label>File Path:</label>
          <input type="text" value={filePath} onChange={handleFilePathChange} placeholder="e.g., documents/report.txt" required />
        </div>
        <div>
          <label>Select File:</label>
          <input type="file" onChange={handleFileChange} required />
        </div>
        <button type="submit">Upload/Update</button>
        {message && <p>{message}</p>}
      </form>
      <Link to="/files">Back to File Manager</Link>
    </div>
  );
}
