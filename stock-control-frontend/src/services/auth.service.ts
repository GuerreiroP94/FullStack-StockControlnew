// src/services/auth.service.ts
import { api } from './api';
import { UserLogin, AuthResponse, User } from '../types';
import { parseJwt } from '../utils/helpers';

class AuthService {
  async login(credentials: UserLogin): Promise<{ token: string; user: User }> {
    // 1. Faz o login e obtém o token
    const response = await api.post<AuthResponse>('/auth/login', credentials);
    const { token } = response.data;
    
    // 2. IMPORTANTE: Armazena o token IMEDIATAMENTE
    localStorage.setItem('token', token);
    
    // 3. IMPORTANTE: Configura o token no Axios ANTES de fazer outras requisições
    api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
    
    // 4. Parse user info from token
    const decoded = parseJwt(token);
    const userId = decoded?.UserId || decoded?.userId || decoded?.nameid || decoded?.sub;
    
    if (!userId) {
      throw new Error('ID do usuário não encontrado no token');
    }
    
    // 5. Armazena o userId para uso futuro
    localStorage.setItem('userId', userId);
    
    // 6. AGORA sim, busca os detalhes do usuário (com o token já configurado)
    const userResponse = await api.get<User>(`/user/${userId}`);
    const user = userResponse.data;
    
    // 7. Armazena os dados do usuário
    localStorage.setItem('user', JSON.stringify(user));
    
    return { token, user };
  }

  logout(): void {
    // Remove o token dos headers do Axios
    delete api.defaults.headers.common['Authorization'];
    
    // Limpa o localStorage
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

  getCurrentUserId(): string | null {
    return localStorage.getItem('userId');
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