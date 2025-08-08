import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Link, Navigate } from 'react-router-dom';
import LoginPage from './components/LoginPage';
import FileManagerPage from './components/FileManagerPage';
import FileUploadPage from './components/FileUploadPage';
import { api } from './api';
import './App.css';
import { NotificationProvider } from './context/NotificationContext';

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
      <NotificationProvider>
        {!token ? (
          <Routes>
            <Route path="*" element={<LoginPage setToken={handleSetToken} api={api} />} />
          </Routes>
        ) : (
          <div className="app-container">
            <header className="app-header">
              <h1>File Storage App</h1>
              <nav className="app-nav">
                <Link to="/files">File Manager</Link>
                <Link to="/upload">Upload</Link>
                <button onClick={() => handleSetToken(null)} className="logout-button">Logout</button>
              </nav>
            </header>
            <main className="content-container">
              <Routes>
                <Route path="/files/*" element={<FileManagerPage token={token} api={api} />} />
                <Route path="/upload" element={<FileUploadPage token={token} api={api} />} />
                <Route path="*" element={<Navigate to="/files" />} />
              </Routes>
            </main>
          </div>
        )}
      </NotificationProvider>
    </Router>
  );
}

export default App;
