import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  AlertCircle, 
  Calendar, 
  Search,
  Filter,
  Package,
  ChevronLeft,
  ChevronRight,
  Eye
} from 'lucide-react';
import alertsService from '../../services/alerts.service';
import componentsService from '../../services/components.service';
import { StockAlert, StockAlertQueryParameters, Component } from '../../types';
import { PAGINATION } from '../../utils/constants';
import { formatDateTime } from '../../utils/helpers';
import LoadingSpinner from '../../components/common/LoadingSpinner';
import ErrorMessage from '../../components/common/ErrorMessage';

const AlertsPage: React.FC = () => {
  const navigate = useNavigate();
  const [alerts, setAlerts] = useState<StockAlert[]>([]);
  const [components, setComponents] = useState<Component[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  
  // Filters
  const [queryParams, setQueryParams] = useState<StockAlertQueryParameters>({
    page: 1,
    pageSize: PAGINATION.DEFAULT_PAGE_SIZE,
    componentId: undefined,
    fromDate: '',
    toDate: ''
  });

  useEffect(() => {
    fetchData();
  }, [queryParams]);

  const fetchData = async () => {
    try {
      setLoading(true);
      const [alertsData, componentsData] = await Promise.all([
        alertsService.getAll(queryParams),
        componentsService.getAll()
      ]);
      setAlerts(alertsData);
      setComponents(componentsData);
    } catch (error) {
      setError('Erro ao carregar alertas');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleFilterChange = (field: keyof StockAlertQueryParameters, value: any) => {
    setQueryParams(prev => ({ ...prev, [field]: value, page: 1 }));
  };

  const getComponentName = (componentId: number) => {
    const component = components.find(c => c.id === componentId);
    return component?.name || `Componente #${componentId}`;
  };

  const getComponentInfo = (componentId: number) => {
    return components.find(c => c.id === componentId);
  };

  const clearFilters = () => {
    setQueryParams({
      page: 1,
      pageSize: PAGINATION.DEFAULT_PAGE_SIZE,
      componentId: undefined,
      fromDate: '',
      toDate: ''
    });
  };

  const getAlertSeverity = (message: string): 'critical' | 'warning' | 'info' => {
    if (message.toLowerCase().includes('crítico') || message.toLowerCase().includes('zerado')) {
      return 'critical';
    }
    if (message.toLowerCase().includes('baixo')) {
      return 'warning';
    }
    return 'info';
  };

  const getSeverityStyles = (severity: 'critical' | 'warning' | 'info') => {
    switch (severity) {
      case 'critical':
        return 'bg-red-50 border-red-200 text-red-800';
      case 'warning':
        return 'bg-yellow-50 border-yellow-200 text-yellow-800';
      default:
        return 'bg-blue-50 border-blue-200 text-blue-800';
    }
  };

  return (
    <div className="p-6">
      {/* Header */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className="w-10 h-10 bg-gradient-to-br from-red-500 to-red-600 rounded-xl flex items-center justify-center shadow-lg">
              <AlertCircle className="text-white" size={20} />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-gray-800">Alertas de Estoque</h1>
              <p className="text-sm text-gray-500">Monitore componentes com estoque baixo</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-sm text-gray-500">Total de alertas:</span>
            <span className="text-lg font-semibold text-gray-800">{alerts.length}</span>
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
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
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

          {/* Start Date */}
          <div>
            <label className="block text-xs text-gray-500 mb-1">Data inicial</label>
            <input
              type="date"
              value={queryParams.fromDate || ''}
              onChange={(e) => handleFilterChange('fromDate', e.target.value)}
              className="w-full px-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200"
            />
          </div>

          {/* End Date */}
          <div>
            <label className="block text-xs text-gray-500 mb-1">Data final</label>
            <input
              type="date"
              value={queryParams.toDate || ''}
              onChange={(e) => handleFilterChange('toDate', e.target.value)}
              className="w-full px-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200"
            />
          </div>
        </div>
      </div>

      {/* Alerts List */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
        {loading ? (
          <div className="p-12 text-center">
            <LoadingSpinner size="lg" message="Carregando alertas..." />
          </div>
        ) : alerts.length === 0 ? (
          <div className="p-12 text-center">
            <div className="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <Package className="text-green-600" size={32} />
            </div>
            <p className="text-lg font-medium text-gray-600">Nenhum alerta ativo</p>
            <p className="text-sm text-gray-500 mt-1">
              Todos os componentes estão com estoque adequado
            </p>
          </div>
        ) : (
          <div className="divide-y divide-gray-200">
            {alerts.map((alert) => {
              const severity = getAlertSeverity(alert.message);
              const component = getComponentInfo(alert.componentId);
              
              return (
                <div
                  key={alert.id}
                  className={`p-6 hover:bg-gray-50 transition-colors cursor-pointer ${getSeverityStyles(severity)}`}
                  onClick={() => navigate('/components')}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-start gap-4">
                      <div className={`w-10 h-10 rounded-full flex items-center justify-center flex-shrink-0 ${
                        severity === 'critical' ? 'bg-red-500' :
                        severity === 'warning' ? 'bg-yellow-500' : 'bg-blue-500'
                      }`}>
                        <AlertCircle className="text-white" size={20} />
                      </div>
                      <div>
                        <h3 className="font-semibold text-gray-900 mb-1">
                          {getComponentName(alert.componentId)}
                        </h3>
                        <p className="text-sm mb-2">{alert.message}</p>
                        <div className="flex items-center gap-4 text-xs text-gray-600">
                          <div className="flex items-center gap-1">
                            <Calendar size={14} />
                            {formatDateTime(alert.createdAt)}
                          </div>
                          {component && (
                            <div className="flex items-center gap-2">
                              <span>Estoque: {component.quantityInStock}</span>
                              <span>•</span>
                              <span>Mínimo: {component.minimumQuantity}</span>
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        navigate(`/movements/new`);
                      }}
                      className="flex items-center gap-2 px-3 py-1.5 text-sm bg-white border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors"
                    >
                      <Eye size={14} />
                      Resolver
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* Pagination */}
        {alerts.length > 0 && (
          <div className="px-6 py-4 border-t border-gray-200 bg-white">
            <div className="flex items-center justify-between">
              <p className="text-sm text-gray-700">
                Página {queryParams.page}
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
                  disabled={alerts.length < queryParams.pageSize}
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

export default AlertsPage;