import { api } from './api';
import { Component, ComponentCreate, ComponentFilter } from '../types';

class ComponentsService {
  async getAll(filter?: ComponentFilter): Promise<Component[]> {
    const params = filter ? {
      name: filter.name,
      group: filter.group,
      pageNumber: filter.pageNumber,
      pageSize: filter.pageSize
    } : {};
    
    const response = await api.get<Component[]>('/component', { params });
    return response.data;
  }

  async getById(id: number): Promise<Component> {
    const response = await api.get<Component>(`/component/${id}`);
    return response.data;
  }

  async create(data: ComponentCreate): Promise<Component> {
    const response = await api.post<Component>('/component', data);
    return response.data;
  }

  async update(id: number, data: ComponentCreate): Promise<Component> {
    const response = await api.put<Component>(`/component/${id}`, data);
    return response.data;
  }

  async delete(id: number): Promise<void> {
    await api.delete(`/component/${id}`);
  }
}

export default new ComponentsService();