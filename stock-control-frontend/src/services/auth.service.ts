import { api } from './api';
import { UserLogin, AuthResponse, User } from '../types';
import { parseJwt } from '../utils/helpers';

class AuthService {
  async login(credentials: UserLogin): Promise<{ token: string; user: User }> {
    const response = await api.post<AuthResponse>('/auth/login', credentials);
    const { token } = response.data;
    
    // Parse user info from token
    const decoded = parseJwt(token);
    const userId = decoded?.UserId || decoded?.sub;
    
    // Get user details
    const userResponse = await api.get<User>(`/user/${userId}`);
    const user = userResponse.data;
    
    // Store in localStorage
    localStorage.setItem('token', token);
    localStorage.setItem('user', JSON.stringify(user));
    localStorage.setItem('userId', userId);
    
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