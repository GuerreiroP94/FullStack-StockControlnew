import { api } from './api';
import { UserLogin, AuthResponse, User } from '../types';
import { parseJwt } from '../utils/helpers';

class AuthService {
  async login(credentials: UserLogin): Promise<{ token: string; user: User }> {
    const response = await api.post<AuthResponse>('/auth/login', credentials);
    const { token } = response.data;
    
    // Parse user info from token
    const decoded = parseJwt(token);
    
    // Create user from token data (without fetching from backend)
    const user: User = {
  id: parseInt(decoded.userId), // agora com 'userId' em minúsculo
  name: decoded.email.split('@')[0], // nome baseado no e-mail
  email: decoded.email,
  role: decoded.role as 'admin' | 'operator',
  createdAt: new Date().toISOString()
};
    
    // Store in localStorage
    localStorage.setItem('token', token);
    localStorage.setItem('user', JSON.stringify(user));
    localStorage.setItem('userId', decoded.UserId);
    
    return { token, user };
  }

  logout(): void {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    localStorage.removeItem('userId');
  }

  getCurrentUser(): User | null {
    const userStr = localStorage.getItem('user');
    if (!userStr) return null;
    
    try {
      return JSON.parse(userStr);
    } catch {
      return null;
    }
  }

  getToken(): string | null {
    return localStorage.getItem('token');
  }

  isAuthenticated(): boolean {
    const token = this.getToken();
    if (!token) return false;
    
    // Check if token is expired
    const decoded = parseJwt(token);
    if (!decoded || !decoded.exp) return false;
    
    const currentTime = Date.now() / 1000;
    return decoded.exp > currentTime;
  }

  isAdmin(): boolean {
    const user = this.getCurrentUser();
    return user?.role === 'admin';
  }
}

export default new AuthService();