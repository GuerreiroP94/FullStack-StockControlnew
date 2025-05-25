import { api } from './api';
import { StockAlert, StockAlertQueryParameters } from '../types';

class AlertsService {
  async getAll(params?: StockAlertQueryParameters): Promise<StockAlert[]> {
    const response = await api.get<StockAlert[]>('/stockalert', { params });
    return response.data;
  }

  async getByComponentId(componentId: number): Promise<StockAlert[]> {
    const response = await api.get<StockAlert[]>(`/stockalert/component/${componentId}`);
    return response.data;
  }
}

export default new AlertsService();