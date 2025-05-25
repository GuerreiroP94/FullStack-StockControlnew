import { api } from './api';
import { Product, ProductCreate, ProductQueryParameters } from '../types';

class ProductsService {
  async getAll(params?: ProductQueryParameters): Promise<Product[]> {
    const response = await api.get<Product[]>('/product', { params });
    return response.data;
  }

  async getById(id: number): Promise<Product> {
    const response = await api.get<Product>(`/product/${id}`);
    return response.data;
  }

  async create(data: ProductCreate): Promise<Product> {
    const response = await api.post<Product>('/product', data);
    return response.data;
  }

  async update(id: number, data: ProductCreate): Promise<Product> {
    const updateData = { ...data, id };
    const response = await api.put<Product>('/product', updateData);
    return response.data;
  }

  async delete(id: number): Promise<void> {
    await api.delete(`/product/${id}`);
  }
}

export default new ProductsService();