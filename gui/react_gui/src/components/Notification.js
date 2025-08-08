import React from 'react';
import './Notification.css';

const Notification = ({ notification, onClose }) => {
  if (!notification) {
    return null;
  }

  const { message, type } = notification;

  return (
    <div className={`notification ${type}`}>
      <span className="notification-message">{message}</span>
      <button onClick={onClose} className="notification-close-btn">&times;</button>
    </div>
  );
};

export default Notification;