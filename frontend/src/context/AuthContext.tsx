import React, { createContext, useContext, useState, useEffect } from 'react';
import { ApiClient } from '../api/client';
import { User } from '../types';

interface AuthContextType {
  user: User | null;
  token: string | null;
  isLoading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
  isAdmin: boolean;
  isAnalyst: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(localStorage.getItem('sx_access_token'));
  const [isLoading, setIsLoading] = useState<boolean>(true);

  const fetchCurrentUser = async () => {
    try {
      if (localStorage.getItem('sx_access_token')) {
        const userData = await ApiClient.getMe();
        setUser(userData);
      } else {
        setUser(null);
      }
    } catch (err) {
      console.warn('Could not validate session, clearing token', err);
      ApiClient.clearToken();
      setToken(null);
      setUser(null);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchCurrentUser();
  }, [token]);

  const login = async (username: string, password: string) => {
    const formData = new FormData();
    formData.append('username', username);
    formData.append('password', password);

    const tokenResponse = await ApiClient.login(formData);
    ApiClient.setToken(tokenResponse.access_token);
    setToken(tokenResponse.access_token);
    setUser(tokenResponse.user);
  };

  const logout = () => {
    ApiClient.clearToken();
    setToken(null);
    setUser(null);
  };

  const roleName = user?.role?.name?.toLowerCase() || '';
  const isAdmin = roleName === 'admin';
  const isAnalyst = roleName === 'admin' || roleName === 'analyst';

  return (
    <AuthContext.Provider value={{ user, token, isLoading, login, logout, isAdmin, isAnalyst }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
