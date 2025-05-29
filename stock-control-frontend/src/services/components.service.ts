import { api, handleApiError } from './api';
import { Component, ComponentCreate, ComponentFilter } from '../types';

class ComponentsService {
  async getAll(filter?: ComponentFilter): Promise<Component[]> {
    try {
      const params = filter ? {
        name: filter.name,
        group: filter.group,
        device: filter.device,
        package: filter.package,
        value: filter.value,
        searchTerm: filter.searchTerm,
        pageNumber: filter.pageNumber,
        pageSize: filter.pageSize
      } : {};
      
      const response = await api.get<Component[]>('/component', { params });
      return response.data || [];
    } catch (error) {
      console.error('Erro ao buscar componentes:', error);
      throw new Error(handleApiError(error));
    }
  }

  async getById(id: number): Promise<Component> {
    try {
      const response = await api.get<Component>(`/component/${id}`);
      return response.data;
    } catch (error) {
      console.error('Erro ao buscar componente:', error);
      throw new Error(handleApiError(error));
    }
  }

  async create(data: ComponentCreate): Promise<Component> {
    try {
      const response = await api.post<Component>('/component', data);
      return response.data;
    } catch (error) {
      console.error('Erro ao criar componente:', error);
      throw new Error(handleApiError(error));
    }
  }

  async update(id: number, data: ComponentCreate): Promise<Component> {
    try {
      const response = await api.put<Component>(`/component/${id}`, data);
      return response.data;
    } catch (error) {
      console.error('Erro ao atualizar componente:', error);
      throw new Error(handleApiError(error));
    }
  }

  async delete(id: number): Promise<void> {
    try {
      await api.delete(`/component/${id}`);
    } catch (error) {
      console.error('Erro ao deletar componente:', error);
      throw new Error(handleApiError(error));
    }
  }

  async deleteMultiple(ids: number[]): Promise<void> {
    try {
      await api.delete('/component/bulk', { data: ids });
    } catch (error) {
      console.error('Erro ao deletar múltiplos componentes:', error);
      throw new Error(handleApiError(error));
    }
  }

  async bulkImport(file: File): Promise<any> {
    try {
      const formData = new FormData();
      formData.append('file', file);
      
      const response = await api.post('/component/bulk', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      
      return response.data;
    } catch (error) {
      console.error('Erro ao importar componentes:', error);
      throw new Error(handleApiError(error));
    }
  }
}

export default new ComponentsService();