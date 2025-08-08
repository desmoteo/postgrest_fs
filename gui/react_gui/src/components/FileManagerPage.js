import React, { useState, useEffect } from 'react';
import { Link, useParams, useNavigate } from 'react-router-dom';
import { useNotification } from '../context/NotificationContext';

const parsePath = (path) => {
  const parts = path.split('/').filter(Boolean);
  return parts;
};

const buildBreadcrumbs = (pathParts) => {
  let currentPath = '';
  const breadcrumbs = [{ name: 'Root', path: '/files' }];
  for (const part of pathParts) {
    currentPath += `/${part}`;
    breadcrumbs.push({ name: part, path: `/files${currentPath}` });
  }
  return breadcrumbs;
};

export default function FileManagerPage({ token, api }) {
  const [allFiles, setAllFiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const { showNotification } = useNotification();
  const { '*': path = '' } = useParams();
  const navigate = useNavigate();

  useEffect(() => {
    const fetchFiles = async () => {
      if (token) {
        setLoading(true);
        const result = await api.listFiles(token);
        if (result.success) {
          setAllFiles(result.files);
        } else {
          showNotification(result.error, 'error');
        }
        setLoading(false);
      }
    };
    fetchFiles();
  }, [token, api, showNotification]);

  const handleDownload = async (filePath) => {
    const result = await api.retrieveFile(token, filePath);
    if (!result.success) {
      showNotification(result.error, 'error');
    }
  };

  const currentPathParts = parsePath(path);
  const breadcrumbs = buildBreadcrumbs(currentPathParts);

  const { directories, files } = allFiles.reduce(
    (acc, file) => {
      const fileParts = parsePath(file.file_path);
      if (fileParts.length > currentPathParts.length && file.file_path.startsWith(path)) {
        const nextPart = fileParts[currentPathParts.length];
        if (fileParts.length > currentPathParts.length + 1) {
          if (!acc.directories.includes(nextPart)) {
            acc.directories.push(nextPart);
          }
        } else {
          acc.files.push({ ...file, name: nextPart });
        }
      }
      return acc;
    },
    { directories: [], files: [] }
  );

  if (loading) return <p>Loading files...</p>;

  return (
    <div className="file-manager-container">
      <div className="breadcrumbs">
        {breadcrumbs.map((crumb, index) => (
          <span key={index}>
            <Link to={crumb.path}>{crumb.name}</Link>
            {index < breadcrumbs.length - 1 && ' / '}
          </span>
        ))}
      </div>

      <h2>{currentPathParts.length > 0 ? currentPathParts[currentPathParts.length - 1] : 'File Manager'}</h2>

      <ul className="file-list">
        {directories.map((dir, index) => (
          <li key={`dir-${index}`} className="file-list-item directory" onClick={() => navigate(`${breadcrumbs[breadcrumbs.length - 1].path}/${dir}`)}>
            <span>📁 {dir}</span>
          </li>
        ))}
        {files.map((file) => (
          <li key={file.id} className="file-list-item">
            <span>📄 {file.name}</span>
            <button onClick={() => handleDownload(file.file_path)} className="download-btn">Download</button>
          </li>
        ))}
      </ul>
      <Link to={`/upload?path=${path}`} className="upload-link">Upload to this directory</Link>
    </div>
  );
}
