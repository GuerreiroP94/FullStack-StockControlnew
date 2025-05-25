import { api } from './api';
import { StockMovement, StockMovementCreate, StockMovementQueryParameters } from '../types';

class MovementsService {
  async getAll(params?: StockMovementQueryParameters): Promise<StockMovement[]> {
    const response = await api.get<StockMovement[]>('/stockmovement', { params });
    return response.data;
  }

  async getByComponentId(componentId: number): Promise<StockMovement> {
    const response = await api.get<StockMovement>(`/stockmovement/component/${componentId}`);
    return response.data;
  }

  async create(data: StockMovementCreate): Promise<StockMovement> {
    const response = await api.post<StockMovement>('/stockmovement', data);
    return response.data;
  }
}

export default new MovementsService();