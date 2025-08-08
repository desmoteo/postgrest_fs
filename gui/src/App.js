import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Link, Navigate } from 'react-router-dom';
import LoginPage from './components/LoginPage';
import FileManagerPage from './components/FileManagerPage';
import FileUploadPage from './components/FileUploadPage';
import { api } from './api';

function App() {
  const [token, setToken] = useState(localStorage.getItem('authToken'));

  const handleSetToken = (newToken) => {
    if (newToken) {
      localStorage.setItem('authToken', newToken);
    } else {
      localStorage.removeItem('authToken');
    }
    setToken(newToken);
  };

  return (
    <Router>
      <div style={{ padding: '20px' }}>
        <h1>File Storage App</h1>
        <nav>
          {token && (
            <>
              <Link to="/files" style={{ marginRight: '10px' }}>File Manager</Link>
              <Link to="/upload" style={{ marginRight: '10px' }}>Upload</Link>
              <button onClick={() => handleSetToken(null)}>Logout</button>
            </>
          )}
        </nav>
        <hr />
        <Routes>
          <Route path="/" element={token ? <Navigate to="/files" /> : <LoginPage setToken={handleSetToken} api={api} />} />
          <Route path="/files" element={token ? <FileManagerPage token={token} api={api} /> : <Navigate to="/" />} />
          <Route path="/upload" element={token ? <FileUploadPage token={token} api={api} /> : <Navigate to="/" />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;
