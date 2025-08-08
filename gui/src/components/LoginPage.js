import React, { useState } from 'react';

export default function LoginPage({ setToken, api }) {
  const [email, setEmail] = useState('editor1@example.com');
  const [password, setPassword] = useState('password123');
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    const result = await api.login(email, password);
    if (result.success) {
      setToken(result.token);
    } else {
      setError(result.error);
    }
  };

  return (
    <div className="form-container">
      <h2>Login</h2>
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label>Email:</label>
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
        </div>
        <div className="form-group">
          <label>Password:</label>
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
        </div>
        <button type="submit" className="btn btn-primary">Login</button>
        {error && <p className="error-message">{error}</p>}
      </form>
    </div>
  );
}
