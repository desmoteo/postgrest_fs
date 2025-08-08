import React, { useState } from 'react';
import { useNotification } from '../context/NotificationContext';

export default function LoginPage({ setToken, api }) {
  const [email, setEmail] = useState('editor1@example.com');
  const [password, setPassword] = useState('password123');
  const { showNotification } = useNotification();

  const handleSubmit = async (e) => {
    e.preventDefault();
    const result = await api.login(email, password);
    if (result.success) {
      setToken(result.token);
      showNotification('Login successful!', 'success');
    } else {
      showNotification(result.error, 'error');
    }
  };

  return (
    <div className="login-page-container">
      <div className="login-card">
        <div className="form-container">
          <h2>Welcome Back</h2>
          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <label>Email Address</label>
              <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
            </div>
            <div className="form-group">
              <label>Password</label>
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
            </div>
            <button type="submit" className="btn btn-primary">Login</button>
          </form>
        </div>
      </div>
    </div>
  );
}
