import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';

export default function FileManagerPage({ token, api }) {
  const [files, setFiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    const fetchFiles = async () => {
      if (token) {
        const result = await api.listFiles(token);
        if (result.success) {
          setFiles(result.files);
        } else {
          setError(result.error);
        }
        setLoading(false);
      }
    };
    fetchFiles();
  }, [token, api]);

  const handleDownload = async (filePath) => {
    const result = await api.retrieveFile(token, filePath);
    if (!result.success) {
      alert('Download failed: ' + result.error);
    }
  };

  if (loading) return <p>Loading files...</p>;
  if (error) return <p style={{ color: 'red' }}>Error loading files: {error}</p>;

  return (
    <div>
      <h2>File Manager</h2>
      <ul>
        {files.map((file) => (
          <li key={file.id}>
            {file.file_path}{' '}
            <button onClick={() => handleDownload(file.file_path)}>Download</button>
          </li>
        ))}
      </ul>
      <Link to="/upload">Upload/Update File</Link>
    </div>
  );
}
