import React, { useState, useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { useNotification } from '../context/NotificationContext';

function useQuery() {
  return new URLSearchParams(useLocation().search);
}

export default function FileUploadPage({ token, api }) {
  const [selectedFile, setSelectedFile] = useState(null);
  const [filePath, setFilePath] = useState('');
  const { showNotification } = useNotification();
  const query = useQuery();
  const pathPrefix = query.get('path') ? query.get('path') + '/' : '';

  useEffect(() => {
    setFilePath(pathPrefix);
  }, [pathPrefix]);

  const handleFileChange = (event) => {
    const file = event.target.files[0];
    if (file) {
      setSelectedFile(file);
      setFilePath(pathPrefix + file.name);
    }
  };

  const handleFilePathChange = (event) => {
    setFilePath(event.target.value);
  };

  const handleUpload = async (e) => {
    e.preventDefault();
    if (!selectedFile || !filePath) {
      showNotification('Please select a file and enter a file path.', 'error');
      return;
    }
    const result = await api.storeFile(token, filePath, selectedFile);
    if (result.success) {
      showNotification('File uploaded successfully!', 'success');
      setSelectedFile(null);
      setFilePath(pathPrefix);
    } else {
      showNotification(result.error, 'error');
    }
  };

  return (
    <div className="form-container">
      <h2>Upload File</h2>
      <form onSubmit={handleUpload}>
        <div className="form-group">
          <label>Select File:</label>
          <input type="file" onChange={handleFileChange} required />
        </div>
        <div className="form-group">
          <label>File Path:</label>
          <input type="text" value={filePath} onChange={handleFilePathChange} placeholder="e.g., documents/report.txt" required />
        </div>
        <button type="submit" className="btn btn-primary">Upload/Update</button>
      </form>
      <Link to={-1} className="btn btn-secondary" style={{marginTop: '10px'}}>Back to File Manager</Link>
    </div>
  );
}
