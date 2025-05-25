import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  Plus, 
  Search, 
  Filter, 
  TrendingUp, 
  TrendingDown,
  Calendar,
  User,
  ChevronLeft,
  ChevronRight
} from 'lucide-react';
import movementsService from '../../services/movements.service';
import componentsService from '../../services/components.service';
import { StockMovement, StockMovementQueryParameters, Component } from '../../types';
import { MOVEMENT_TYPES, PAGINATION } from '../../utils/constants';
import { formatDateTime } from '../../utils/helpers';
import { useAuth } from '../../contexts/AuthContext';
import LoadingSpinner from '../../components/common/LoadingSpinner';
import ErrorMessage from '../../components/common/ErrorMessage';

const MovementsListPage: React.FC = () => {
  const navigate = useNavigate();
  const { isAdmin } = useAuth();
  const [movements, setMovements] = useState<StockMovement[]>([]);
  const [components, setComponents] = useState<Component[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  
  // Filters
  const [queryParams, setQueryParams] = useState<StockMovementQueryParameters>({
    componentId: undefined,
    movementType: '',
    startDate: '',
    endDate: '',
    page: 1,
    pageSize: PAGINATION.DEFAULT_PAGE_SIZE
  });

  useEffect(() => {
    fetchData();
  }, [queryParams]);

  const fetchData = async () => {
    try {
      setLoading(true);
      const [movementsData, componentsData] = await Promise.all([
        movementsService.getAll(queryParams),
        componentsService.getAll()
      ]);
      setMovements(movementsData);
      setComponents(componentsData);
    } catch (error) {
      setError('Erro ao carregar movimentações');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleFilterChange = (field: keyof StockMovementQueryParameters, value: any) => {
    setQueryParams(prev => ({ ...prev, [field]: value, page: 1 }));
  };

  const getComponentName = (componentId: number) => {
    const component = components.find(c => c.id === componentId);
    return component?.name || `Componente #${componentId}`;
  };

  const getTotalQuantity = (type: 'Entrada' | 'Saida') => {
    return movements
      .filter(m => m.movementType === type)
      .reduce((sum, m) => sum + Math.abs(m.quantity), 0);
  };

  const clearFilters = () => {
    setQueryParams({
      componentId: undefined,
      movementType: '',
      startDate: '',
      endDate: '',
      page: 1,
      pageSize: PAGINATION.DEFAULT_PAGE_SIZE
    });
  };

  return (
    <div className="p-6">
      {/* Header */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className="w-10 h-10 bg-gradient-to-br from-purple-500 to-purple-600 rounded-xl flex items-center justify-center shadow-lg">
              <TrendingUp className="text-white" size={20} />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-gray-800">Movimentações</h1>
              <p className="text-sm text-gray-500">Histórico de entradas e saídas do estoque</p>
            </div>
          </div>
          {isAdmin && (
            <button
              onClick={() => navigate('/movements/new')}
              className="flex items-center gap-2 px-4 py-2.5 bg-gradient-to-r from-purple-500 to-purple-600 text-white rounded-lg hover:from-purple-600 hover:to-purple-700 transition-all duration-200 shadow-sm"
            >
              <Plus size={18} />
              <span className="font-medium">Nova Movimentação</span>
            </button>
          )}
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500 mb-1">Total de Entradas</p>
              <p className="text-2xl font-bold text-green-600">+{getTotalQuantity('Entrada')}</p>
              <p className="text-xs text-gray-500 mt-1">unidades adicionadas</p>
            </div>
            <div className="w-12 h-12 bg-green-100 rounded-full flex items-center justify-center">
              <TrendingUp className="text-green-600" size={24} />
            </div>
          </div>
        </div>

        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500 mb-1">Total de Saídas</p>
              <p className="text-2xl font-bold text-red-600">-{getTotalQuantity('Saida')}</p>
              <p className="text-xs text-gray-500 mt-1">unidades removidas</p>
            </div>
            <div className="w-12 h-12 bg-red-100 rounded-full flex items-center justify-center">
              <TrendingDown className="text-red-600" size={24} />
            </div>
          </div>
        </div>
      </div>

      {/* Messages */}
      {error && <ErrorMessage message={error} onClose={() => setError('')} className="mb-6" />}

      {/* Filters */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <Filter size={20} className="text-gray-500" />
            <h2 className="text-lg font-semibold text-gray-800">Filtros</h2>
          </div>
          <button
            onClick={clearFilters}
            className="text-sm text-blue-600 hover:text-blue-700"
          >
            Limpar filtros
          </button>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Component Filter */}
          <select
            value={queryParams.componentId || ''}
            onChange={(e) => handleFilterChange('componentId', e.target.value ? Number(e.target.value) : undefined)}
            className="w-full px-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200 bg-white"
          >
            <option value="">Todos os Componentes</option>
            {components.map(comp => (
              <option key={comp.id} value={comp.id}>{comp.name}</option>
            ))}
          </select>

          {/* Movement Type Filter */}
          <select
            value={queryParams.movementType || ''}
            onChange={(e) => handleFilterChange('movementType', e.target.value)}
            className="w-full px-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200 bg-white"
          >
            <option value="">Todos os Tipos</option>
            <option value={MOVEMENT_TYPES.ENTRADA}>Entrada</option>
            <option value={MOVEMENT_TYPES.SAIDA}>Saída</option>
          </select>

          {/* Start Date */}
          <input
            type="date"
            value={queryParams.startDate || ''}
            onChange={(e) => handleFilterChange('startDate', e.target.value)}
            className="w-full px-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200"
          />

          {/* End Date */}
          <input
            type="date"
            value={queryParams.endDate || ''}
            onChange={(e) => handleFilterChange('endDate', e.target.value)}
            className="w-full px-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200"
          />
        </div>
      </div>

      {/* Table */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
        {loading ? (
          <div className="p-12 text-center">
            <LoadingSpinner size="lg" message="Carregando movimentações..." />
          </div>
        ) : movements.length === 0 ? (
          <div className="p-12 text-center">
            <TrendingUp className="mx-auto mb-4 text-gray-400" size={48} />
            <p className="text-lg font-medium text-gray-600">Nenhuma movimentação encontrada</p>
            <p className="text-sm text-gray-500 mt-1">
              {queryParams.componentId || queryParams.movementType || queryParams.startDate || queryParams.endDate
                ? "Tente ajustar os filtros de busca" 
                : "Registre novas movimentações de estoque"}
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full">
              <thead className="bg-gray-50 border-b border-gray-200">
                <tr>
                  <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Tipo
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Componente
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Quantidade
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Data/Hora
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Responsável
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {movements.map((movement) => (
                  <tr key={movement.id} className="hover:bg-gray-50 transition-colors duration-150">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className={`inline-flex items-center gap-2 px-3 py-1 rounded-full text-sm font-medium ${
                        movement.movementType === 'Entrada' 
                          ? 'bg-green-100 text-green-800' 
                          : 'bg-red-100 text-red-800'
                      }`}>
                        {movement.movementType === 'Entrada' ? (
                          <TrendingUp size={14} />
                        ) : (
                          <TrendingDown size={14} />
                        )}
                        {movement.movementType}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <p className="text-sm font-medium text-gray-900">
                        {getComponentName(movement.componentId)}
                      </p>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <p className={`text-sm font-bold ${
                        movement.movementType === 'Entrada' 
                          ? 'text-green-600' 
                          : 'text-red-600'
                      }`}>
                        {movement.movementType === 'Entrada' ? '+' : '-'}{Math.abs(movement.quantity)}
                      </p>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center gap-2 text-sm text-gray-600">
                        <Calendar size={14} />
                        {formatDateTime(movement.movementDate)}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center gap-2">
                        <div className="w-6 h-6 bg-gray-200 rounded-full flex items-center justify-center">
                          <User size={12} className="text-gray-600" />
                        </div>
                        <span className="text-sm text-gray-600">
                          {movement.userName || movement.performedBy}
                        </span>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination */}
        {movements.length > 0 && (
          <div className="px-6 py-4 border-t border-gray-200">
            <div className="flex items-center justify-between">
              <p className="text-sm text-gray-700">
                Página {queryParams.page} de {Math.ceil(movements.length / queryParams.pageSize)}
              </p>
              <div className="flex gap-2">
                <button
                  onClick={() => handleFilterChange('page', queryParams.page - 1)}
                  disabled={queryParams.page === 1}
                  className="p-2 rounded-lg border border-gray-300 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <ChevronLeft size={18} />
                </button>
                <button
                  onClick={() => handleFilterChange('page', queryParams.page + 1)}
                  disabled={movements.length < queryParams.pageSize}
                  className="p-2 rounded-lg border border-gray-300 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <ChevronRight size={18} />
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default MovementsListPage;