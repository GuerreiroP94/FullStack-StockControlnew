import { api } from './api';
import { User, UserCreate, UserUpdate } from '../types';

class UsersService {
  async getAll(): Promise<User[]> {
    const response = await api.get<User[]>('/user');
    return response.data;
  }

  async getById(id: number): Promise<User> {
    const response = await api.get<User>(`/user/${id}`);
    return response.data;
  }

  async create(data: UserCreate): Promise<User> {
    const response = await api.post<User>('/user', data);
    return response.data;
  }

  async update(id: number, data: UserUpdate): Promise<void> {
    await api.put(`/user/${id}`, data);
  }

  async updateRole(id: number, role: string): Promise<void> {
    await api.put(`/user/${id}/role`, JSON.stringify(role), {
      headers: {
        'Content-Type': 'application/json'
      }
    });
  }

  async delete(id: number): Promise<void> {
    await api.delete(`/user/${id}`);
  }
}

export default new UsersService();