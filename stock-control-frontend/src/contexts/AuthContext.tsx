import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { useNavigate } from 'react-router-dom';
import authService from '../services/auth.service';
import { User, AuthContextType } from '../types';

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    // Check if user is already logged in
    const storedToken = authService.getToken();
    
    if (storedToken && authService.isAuthenticated()) {
      // Token is valid, restore user from localStorage
      const storedUser = authService.getCurrentUser();
      if (storedUser) {
        setUser(storedUser);
        setToken(storedToken);
      } else {
        // If user data is corrupted, logout
        authService.logout();
      }
    } else {
      // Token is invalid or expired
      authService.logout();
    }

    setLoading(false);
  }, []);

  const login = async (email: string, password: string) => {
    try {
      const { token, user } = await authService.login({ email, password });
      setUser(user);
      setToken(token);
      navigate('/dashboard');
    } catch (error) {
      authService.logout();
      throw error;
    }
  };

  const logout = () => {
    authService.logout();
    setUser(null);
    setToken(null);
    navigate('/login');
  };

  const value: AuthContextType = {
    user,
    token,
    login,
    logout,
    isAuthenticated: !!user && !!token && authService.isAuthenticated(),
    isAdmin: user?.role === 'admin',
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};