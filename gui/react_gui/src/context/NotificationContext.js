import React, { createContext, useState, useContext } from 'react';
import Notification from '../components/Notification';

const NotificationContext = createContext();

export const useNotification = () => {
  return useContext(NotificationContext);
};

export const NotificationProvider = ({ children }) => {
  const [notification, setNotification] = useState(null);

  const showNotification = (message, type = 'success') => {
    setNotification({ message, type });
    setTimeout(() => {
      setNotification(null);
    }, 5000); // Auto-dismiss after 5 seconds
  };

  const closeNotification = () => {
    setNotification(null);
  };

  return (
    <NotificationContext.Provider value={{ showNotification }}>
      {notification && <div className="notification-container">
        <Notification notification={notification} onClose={closeNotification} />
        </div>}
      {children}
    </NotificationContext.Provider>
  );
};
