import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  Plus, 
  Search, 
  Filter, 
  Pencil, 
  Trash2, 
  Cpu,
  AlertCircle,
  Package
} from 'lucide-react';
import componentsService from '../../services/components.service';
import { Component, ComponentFilter } from '../../types';
import { COMPONENT_GROUPS, PAGINATION } from '../../utils/constants';
import { getStockStatus, getStockStatusColor } from '../../utils/helpers';
import LoadingSpinner from '../../components/common/LoadingSpinner';
import ConfirmModal from '../../components/common/ConfirmModal';
import ErrorMessage from '../../components/common/ErrorMessage';
import SuccessMessage from '../../components/common/SuccessMessage';

const ComponentsListPage: React.FC = () => {
  const navigate = useNavigate();
  const [components, setComponents] = useState<Component[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [deleteModal, setDeleteModal] = useState<{ show: boolean; component?: Component }>({ show: false });
  
  // Filters
  const [filters, setFilters] = useState<ComponentFilter>({
    name: '',
    group: '',
    pageNumber: 1,
    pageSize: PAGINATION.DEFAULT_PAGE_SIZE
  });

  useEffect(() => {
    fetchComponents();
  }, [filters]);

  const fetchComponents = async () => {
    try {
      setLoading(true);
      const data = await componentsService.getAll(filters);
      setComponents(data);
    } catch (error) {
      setError('Erro ao carregar componentes');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async () => {
    if (!deleteModal.component) return;
    
    try {
      await componentsService.delete(deleteModal.component.id);
      setSuccess('Componente excluído com sucesso!');
      fetchComponents();
      setDeleteModal({ show: false });
    } catch (error) {
      setError('Erro ao excluir componente');
    }
  };

  const handleSearch = (value: string) => {
    setFilters(prev => ({ ...prev, name: value, pageNumber: 1 }));
  };

  const handleGroupFilter = (group: string) => {
    setFilters(prev => ({ ...prev, group, pageNumber: 1 }));
  };

  return (
    <div className="p-6">
      {/* Header */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className="w-10 h-10 bg-gradient-to-br from-blue-500 to-blue-600 rounded-xl flex items-center justify-center shadow-lg">
              <Cpu className="text-white" size={20} />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-gray-800">Componentes</h1>
              <p className="text-sm text-gray-500">Gerencie os componentes do estoque</p>
            </div>
          </div>
          <button
            onClick={() => navigate('/components/new')}
            className="flex items-center gap-2 px-4 py-2.5 bg-gradient-to-r from-blue-500 to-blue-600 text-white rounded-lg hover:from-blue-600 hover:to-blue-700 transition-all duration-200 shadow-sm"
          >
            <Plus size={18} />
            <span className="font-medium">Novo Componente</span>
          </button>
        </div>
      </div>

      {/* Messages */}
      {error && <ErrorMessage message={error} onClose={() => setError('')} className="mb-6" />}
      {success && <SuccessMessage message={success} onClose={() => setSuccess('')} className="mb-6" />}

      {/* Filters */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
        <div className="flex items-center gap-3 mb-4">
          <Filter size={20} className="text-gray-500" />
          <h2 className="text-lg font-semibold text-gray-800">Filtros</h2>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {/* Search */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" size={18} />
            <input
              type="text"
              placeholder="Buscar por nome..."
              value={filters.name}
              onChange={(e) => handleSearch(e.target.value)}
              className="w-full pl-10 pr-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200"
            />
          </div>

          {/* Group Filter */}
          <select
            value={filters.group || ''}
            onChange={(e) => handleGroupFilter(e.target.value)}
            className="w-full px-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200 bg-white"
          >
            <option value="">Todos os Grupos</option>
            {COMPONENT_GROUPS.map(group => (
              <option key={group} value={group}>{group}</option>
            ))}
          </select>

          {/* Page Size */}
          <select
            value={filters.pageSize}
            onChange={(e) => setFilters(prev => ({ ...prev, pageSize: Number(e.target.value), pageNumber: 1 }))}
            className="w-full px-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200 bg-white"
          >
            {PAGINATION.PAGE_SIZE_OPTIONS.map(size => (
              <option key={size} value={size}>{size} por página</option>
            ))}
          </select>
        </div>
      </div>

      {/* Table */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
        {loading ? (
          <div className="p-12 text-center">
            <LoadingSpinner size="lg" message="Carregando componentes..." />
          </div>
        ) : components.length === 0 ? (
          <div className="p-12 text-center">
            <Package className="mx-auto mb-4 text-gray-400" size={48} />
            <p className="text-lg font-medium text-gray-600">Nenhum componente encontrado</p>
            <p className="text-sm text-gray-500 mt-1">
              {filters.name || filters.group 
                ? "Tente ajustar os filtros de busca" 
                : "Adicione novos componentes ao sistema"}
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full">
              <thead className="bg-gray-50 border-b border-gray-200">
                <tr>
                  <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Componente
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Grupo
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Estoque
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Mínimo
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-6 py-4 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Ações
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {components.map((component) => {
                  const status = getStockStatus(component.quantityInStock, component.minimumQuantity);
                  return (
                    <tr key={component.id} className="hover:bg-gray-50 transition-colors duration-150">
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div>
                          <p className="text-sm font-medium text-gray-900">{component.name}</p>
                          {component.description && (
                            <p className="text-xs text-gray-500">{component.description}</p>
                          )}
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className="inline-flex px-2 py-1 text-xs font-medium bg-gray-100 text-gray-800 rounded-md">
                          {component.group}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <p className="text-sm font-medium text-gray-900">{component.quantityInStock}</p>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <p className="text-sm text-gray-600">{component.minimumQuantity}</p>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ${getStockStatusColor(status)}`}>
                          {status === 'critical' && <AlertCircle size={12} />}
                          {status === 'critical' ? 'Crítico' : status === 'low' ? 'Baixo' : 'Normal'}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-right">
                        <div className="flex items-center justify-end gap-2">
                          <button
                            onClick={() => navigate(`/components/${component.id}/edit`)}
                            className="p-2 text-blue-600 hover:bg-blue-50 rounded-lg transition-all duration-200"
                            title="Editar"
                          >
                            <Pencil size={18} />
                          </button>
                          <button
                            onClick={() => setDeleteModal({ show: true, component })}
                            className="p-2 text-red-600 hover:bg-red-50 rounded-lg transition-all duration-200"
                            title="Excluir"
                          >
                            <Trash2 size={18} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Delete Modal */}
      <ConfirmModal
        isOpen={deleteModal.show}
        onClose={() => setDeleteModal({ show: false })}
        onConfirm={handleDelete}
        title="Excluir Componente"
        message={`Tem certeza que deseja excluir o componente "${deleteModal.component?.name}"? Esta ação não pode ser desfeita.`}
        confirmText="Excluir"
        type="danger"
      />
    </div>
  );
};

export default ComponentsListPage;