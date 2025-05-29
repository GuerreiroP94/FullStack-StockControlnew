import { api } from './api';
import { StockMovement, StockMovementCreate, StockMovementQueryParameters } from '../types';

// Interfaces temporárias até adicionar no types/index.ts
interface BulkStockMovementDto {
  movements: Array<{
    componentId: number;
    movementType: 'Entrada' | 'Saida';
    quantity: number;
  }>;
}

interface BulkMovementResultDto {
  success: boolean;
  totalMovements: number;
  successCount: number;
  errorCount: number;
  errors: string[];
  alertsGenerated: number[];
}

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

  async createBulk(data: BulkStockMovementDto): Promise<BulkMovementResultDto> {
    const response = await api.post<BulkMovementResultDto>('/stockmovement/bulk', data);
    return response.data;
  }
}

export default new MovementsService();