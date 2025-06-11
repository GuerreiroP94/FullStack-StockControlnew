import React, { useEffect, useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { 
  Plus, 
  Search, 
  Filter, 
  Pencil, 
  Trash2, 
  Cpu,
  FileSpreadsheet,
  X,
  Save,
  CheckSquare,
  Square,
  Package,
  ShoppingBag,
  TrendingUp,
  TrendingDown
} from 'lucide-react';
import componentsService from '../../services/components.service';
import exportService from '../../services/export.service';
import movementsService from '../../services/movements.service';
import { Component, ComponentFilter, ComponentStockEntry } from '../../types';
import { COMPONENT_GROUPS, PAGINATION } from '../../utils/constants';
import LoadingSpinner from '../../components/common/LoadingSpinner';
import ConfirmModal from '../../components/common/ConfirmModal';
import ErrorMessage from '../../components/common/ErrorMessage';
import SuccessMessage from '../../components/common/SuccessMessage';
import PageHeader from '../../components/common/PageHeader';
import EmptyState from '../../components/common/EmptyState';
import FilterSection from '../../components/common/FilterSection';
import TableWrapper from '../../components/common/TableWrapper';
import Pagination from '../../components/common/Pagination';
import { useFilters, useComponentSelection } from '../../hooks';
import ComponentFilters from '../../components/forms/ComponentFilters';
import { getStockStatusClasses, getEnvironmentClasses, getEnvironmentLabel } from '../../utils/tableHelpers';

const ComponentsManagePage: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const [components, setComponents] = useState<Component[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [deleteModal, setDeleteModal] = useState<{ show: boolean; components: Component[] }>({ show: false, components: [] });

  // Estados de paginação
  const [totalItems, setTotalItems] = useState(0);
  const [pageNumber, setPageNumber] = useState(1);
  const [pageSize, setPageSize] = useState(PAGINATION.DEFAULT_PAGE_SIZE);

  // Hook de seleção
  const {
    selectedComponents,
    handleSelectComponent,
    handleSelectAll,
    clearSelection,
    selectedCount
  } = useComponentSelection();

  // Hook de filtros
  const {
    filters,
    updateFilter,
    clearFilters,
    searchTerm,
    setSearchTerm,
    groups,
    devices,
    packages,
    values,
    updateDropdowns
  } = useFilters();
  
  // Estados de edição
  const [isEditMode, setIsEditMode] = useState(false);
  const [stockEntries, setStockEntries] = useState<Map<number, ComponentStockEntry>>(new Map());
  const [editedComponents, setEditedComponents] = useState<Map<number, Component>>(new Map());
  
  // Estados para exportação personalizada
  const [showExportModal, setShowExportModal] = useState(false);
  const [selectedColumns, setSelectedColumns] = useState<Set<string>>(new Set([
    'id', 'group', 'device', 'value', 'package', 'createdAt',
    'price', 'characteristics', 'environment', 'drawer', 'division',
    'quantityInStock', 'minimumQuantity', 'ncm', 'nve'
  ]));

  // Busca em tempo real
  const [filteredComponents, setFilteredComponents] = useState<Component[]>([]);

  useEffect(() => {
    fetchComponents();
  }, [filters.group, filters.device, filters.package, filters.value, pageNumber, pageSize]);

  useEffect(() => {
    // Filtrar componentes localmente quando o usuário digitar
    if (searchTerm) {
      const filtered = components.filter(comp => 
        Object.values(comp).some(value => 
          value && value.toString().toLowerCase().includes(searchTerm.toLowerCase())
        )
      );
      setFilteredComponents(filtered);
    } else {
      setFilteredComponents(components);
    }
  }, [searchTerm, components]);

  const fetchComponents = async () => {
    try {
      setLoading(true);
      const filterParams = {
        ...filters,
        pageNumber,
        pageSize
      };
      const data = await componentsService.getAll(filterParams);
      setComponents(data);
      setFilteredComponents(data);
      updateDropdowns(data);
      
      // Calcular total de itens
      setTotalItems(data.length === pageSize ? pageNumber * pageSize + 1 : (pageNumber - 1) * pageSize + data.length);
    } catch (error) {
      setError('Erro ao carregar componentes');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handlePageChange = (page: number) => {
    setPageNumber(page);
    clearSelection();
  };

  const handlePageSizeChange = (newPageSize: number) => {
    setPageSize(newPageSize);
    setPageNumber(1);
    clearSelection();
  };

  const handleStockEntry = (componentId: number, field: 'entry' | 'exit', value: string) => {
    const numValue = parseInt(value) || 0;
    const current = stockEntries.get(componentId) || { componentId, entryQuantity: 0, exitQuantity: 0 };
    
    if (field === 'entry') {
      current.entryQuantity = numValue;
    } else {
      current.exitQuantity = numValue;
    }
    
    const newEntries = new Map(stockEntries);
    newEntries.set(componentId, current);
    setStockEntries(newEntries);
  };

  const handleComponentEdit = (componentId: number, field: keyof Component, value: any) => {
    const component = editedComponents.get(componentId) || components.find(c => c.id === componentId);
    if (!component) return;

    const updatedComponent = { ...component, [field]: value };
    const newEditedComponents = new Map(editedComponents);
    newEditedComponents.set(componentId, updatedComponent);
    setEditedComponents(newEditedComponents);
  };

  const handleEditClick = () => {
    setIsEditMode(!isEditMode);
    if (!isEditMode) {
      const newEditedComponents = new Map<number, Component>();
      components.forEach(component => {
        newEditedComponents.set(component.id, { ...component });
      });
      setEditedComponents(newEditedComponents);
    } else {
      setEditedComponents(new Map());
      setStockEntries(new Map());
    }
  };

  const handleSaveChanges = async () => {
    if (!isEditMode) {
      setError('Habilite a edição antes de tentar salvar as edições');
      return;
    }

    try {
      const movements: any[] = [];
      const updates: Promise<any>[] = [];
      
      const editedEntries = Array.from(editedComponents.entries());
      for (const [componentId, editedComponent] of editedEntries) {
        const originalComponent = components.find(c => c.id === componentId);
        if (!originalComponent) continue;

        const hasChanges = JSON.stringify(originalComponent) !== JSON.stringify(editedComponent);
        const stockEntry = stockEntries.get(componentId);
        const hasStockMovement = stockEntry && 
          ((stockEntry.entryQuantity !== undefined && stockEntry.entryQuantity > 0) || 
           (stockEntry.exitQuantity !== undefined && stockEntry.exitQuantity > 0));

        if (!hasChanges && !hasStockMovement) continue;

        if (!editedComponent.name) {
          setError('Nome é obrigatório');
          return;
        }

        if (hasChanges) {
          updates.push(componentsService.update(componentId, editedComponent));
        }

        if (stockEntry) {
          if (stockEntry.entryQuantity !== undefined && stockEntry.entryQuantity > 0) {
            movements.push({
              componentId,
              movementType: 'Entrada',
              quantity: stockEntry.entryQuantity
            });
          }
          
          if (stockEntry.exitQuantity !== undefined && stockEntry.exitQuantity > 0) {
            if (stockEntry.exitQuantity > editedComponent.quantityInStock) {
              setError('Quantidade de saída maior que o estoque disponível');
              return;
            }
            movements.push({
              componentId,
              movementType: 'Saida',
              quantity: stockEntry.exitQuantity
            });
          }
        }
      }
      
      if (updates.length > 0) {
        await Promise.all(updates);
      }
      
      if (movements.length > 0) {
        await movementsService.createBulk({ movements });
      }
      
      if (updates.length > 0 || movements.length > 0) {
        const updateMsg = updates.length > 0 ? `${updates.length} componente(s) atualizado(s)` : '';
        const movementMsg = movements.length > 0 ? `${movements.length} movimentação(ões) registrada(s)` : '';
        const successMsg = [updateMsg, movementMsg].filter(Boolean).join(' e ');
        setSuccess(successMsg + '!');
      } else {
        setSuccess('Nenhuma alteração foi detectada para salvar.');
      }
      
      setIsEditMode(false);
      setStockEntries(new Map());
      setEditedComponents(new Map());
      clearSelection();
      fetchComponents();
    } catch (error) {
      setError('Erro ao salvar alterações');
    }
  };

  const handleDeleteClick = () => {
    if (selectedCount === 0) {
      setError('Selecione ao menos um componente para deletar');
      return;
    }
    setDeleteModal({ show: true, components: components.filter(c => selectedComponents.has(c.id)) });
  };

  const handleDelete = async () => {
    try {
      const selectedIds = Array.from(selectedComponents);
      await componentsService.deleteMultiple(selectedIds);
      
      setSuccess('Componentes excluídos com sucesso!');
      clearSelection();
      fetchComponents();
      setDeleteModal({ show: false, components: [] });
    } catch (error) {
      setError('Erro ao excluir componentes');
    }
  };

  const handleCreateProductClick = () => {
    if (selectedComponents.size === 0) {
      setError('Selecione ao menos um componente para criar produto');
      return;
    }
    
    const selectedData = components.filter(c => selectedComponents.has(c.id));
    navigate('/products/new', { state: { selectedComponents: selectedData } });
  };

  const handleExportClick = () => {
    if (selectedCount === 0) {
      setError('Selecione ao menos um componente para exportar');
      return;
    }
    setShowExportModal(true);
  };

  const handleExport = () => {
    const selectedData = filteredComponents.filter(c => selectedComponents.has(c.id));
    exportService.exportComponentsToExcel(selectedData, 
      `componentes_${new Date().toISOString().split('T')[0]}.xlsx`
    );
    
    setSuccess(`${selectedData.length} componentes exportados com sucesso!`);
    setShowExportModal(false);
  };

  const columnOptions = [
    { id: 'id', label: 'ID' },
    { id: 'group', label: 'Grupo' },
    { id: 'device', label: 'Device' },
    { id: 'value', label: 'Value' },
    { id: 'package', label: 'Package' },
    { id: 'createdAt', label: 'Data' },
    { id: 'price', label: 'Preço' },
    { id: 'characteristics', label: 'Característica' },
    { id: 'environment', label: 'Ambiente' },
    { id: 'drawer', label: 'Gaveta' },
    { id: 'division', label: 'Divisão' },
    { id: 'quantityInStock', label: 'Qtd. Estoque' },
    { id: 'minimumQuantity', label: 'Qtd Min' },
    { id: 'ncm', label: 'NCM' },
    { id: 'nve', label: 'NVE' }
  ];

  const pageActions = (
    <div className="flex items-center gap-2 flex-wrap">
      <button
        onClick={() => navigate('/components/new')}
        className="flex items-center gap-2 px-4 py-2.5 bg-gradient-to-r from-blue-500 to-blue-600 text-white rounded-lg hover:from-blue-600 hover:to-blue-700 transition-all duration-200 shadow-sm"
      >
        <Plus size={18} />
        <span className="font-medium">Novo Componente</span>
      </button>
      
      <button
        onClick={handleEditClick}
        className={`flex items-center gap-2 px-4 py-2.5 rounded-lg transition-all duration-200 ${
          isEditMode
            ? 'bg-orange-600 text-white hover:bg-orange-700'
            : 'bg-gray-600 text-white hover:bg-gray-700'
        }`}
      >
        <Pencil size={18} />
        <span className="font-medium">{isEditMode ? 'Cancelar Edição' : 'Editar'}</span>
      </button>
      
      <button
        onClick={handleDeleteClick}
        className={`flex items-center gap-2 px-4 py-2.5 rounded-lg transition-all duration-200 ${
          selectedCount > 0
            ? 'bg-red-600 text-white hover:bg-red-700'
            : 'bg-gray-300 text-gray-500 cursor-not-allowed'
        }`}
        disabled={selectedCount === 0}
      >
        <Trash2 size={18} />
        <span className="font-medium">Deletar</span>
      </button>
      
      <button
        onClick={handleExportClick}
        className={`flex items-center gap-2 px-4 py-2.5 rounded-lg transition-all duration-200 ${
          selectedCount > 0
            ? 'bg-purple-600 text-white hover:bg-purple-700'
            : 'bg-gray-300 text-gray-500 cursor-not-allowed'
        }`}
        disabled={selectedCount === 0}
      >
        <FileSpreadsheet size={18} />
        <span className="font-medium">Exportar</span>
      </button>
      
      <button
        onClick={handleCreateProductClick}
        className={`flex items-center gap-2 px-4 py-2.5 rounded-lg transition-all duration-200 ${
          selectedCount > 0
            ? 'bg-gradient-to-r from-green-500 to-green-600 text-white hover:from-green-600 hover:to-green-700'
            : 'bg-gray-300 text-gray-500 cursor-not-allowed'
        }`}
        disabled={selectedCount === 0}
      >
        <ShoppingBag size={18} />
        <span className="font-medium">Criar Produto</span>
      </button>
      
      {isEditMode && (
        <button
          onClick={handleSaveChanges}
          className="flex items-center gap-2 px-4 py-2.5 bg-gradient-to-r from-green-500 to-green-600 text-white rounded-lg hover:from-green-600 hover:to-green-700 transition-all duration-200"
        >
          <Save size={18} />
          <span className="font-medium">Salvar Alterações</span>
        </button>
      )}
      
      {selectedCount > 0 && (
        <button
          onClick={() => {
            clearSelection();
            if (isEditMode) {
              setIsEditMode(false);
              setEditedComponents(new Map());
              setStockEntries(new Map());
            }
          }}
          className="flex items-center gap-2 px-4 py-2.5 bg-gray-400 text-white rounded-lg hover:bg-gray-500 transition-all duration-200"
        >
          <X size={18} />
          <span className="font-medium">Cancelar Seleção ({selectedCount})</span>
        </button>
      )}
    </div>
  );

  return (
    <div className="p-6">
      {/* Header */}
      <PageHeader
        title="Gerenciar Componentes"
        subtitle="Cadastre, edite e gerencie componentes do estoque"
        icon={Cpu}
        iconColor="from-blue-500 to-blue-600"
        actions={pageActions}
      />

      {/* Messages */}
      {error && <ErrorMessage message={error} onClose={() => setError('')} className="mb-6" />}
      {success && <SuccessMessage message={success} onClose={() => setSuccess('')} className="mb-6" />}

      {/* Filters */}
      <FilterSection
        onClearFilters={clearFilters}
      >
        <ComponentFilters
          searchTerm={searchTerm}
          onSearchChange={setSearchTerm}
          filters={filters}
          onFilterChange={updateFilter}
          groups={groups}
          devices={devices}
          packages={packages}
          values={values}
          onClearFilters={clearFilters}
          showClearButton={false}
        />
      </FilterSection>

      {/* Table */}
      <TableWrapper
        loading={loading}
        isEmpty={filteredComponents.length === 0}
        loadingMessage="Carregando componentes..."
        emptyIcon={Package}
        emptyTitle="Nenhum componente encontrado"
        emptyDescription={
          searchTerm || filters.group || filters.device || filters.package || filters.value
            ? "Tente ajustar os filtros de busca" 
            : "Adicione novos componentes ao sistema"
        }
        headerMessage={
          isEditMode && (
            <p className="text-sm text-orange-800 font-medium">
              📝 Modo de Edição Ativo - Todos os componentes podem ser editados
            </p>
          )
        }
      >
        {/* Paginação no topo */}
        {filteredComponents.length > 0 && (
          <div className="border-b border-gray-200 bg-gray-50">
            <Pagination
              currentPage={pageNumber}
              pageSize={pageSize}
              totalItems={totalItems}
              onPageChange={handlePageChange}
              onPageSizeChange={handlePageSizeChange}
              loading={loading}
            />
          </div>
        )}

        <table className="min-w-full">
          <thead className="bg-gray-50 border-b border-gray-200">
            <tr>
              <th className="px-3 py-4">
                <button
                  onClick={() => handleSelectAll(filteredComponents.map(c => c.id))}
                  className="text-gray-600 hover:text-gray-800"
                >
                  {selectedCount === filteredComponents.length ? 
                    <CheckSquare size={20} /> : 
                    <Square size={20} />
                  }
                </button>
              </th>
              <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                ID
              </th>
              <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Grupo
              </th>
              <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Device
              </th>
              <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Value
              </th>
              <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Package
              </th>
              <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Data
              </th>
              <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Preço
              </th>
              <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Característica
              </th>
              <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Ambiente
              </th>
              <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Gaveta
              </th>
              <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Divisão
              </th>
              <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Qtd. Estoque
              </th>
              <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Qtd Min
              </th>
              {isEditMode && (
                <>
                  <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Entrada
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Saída
                  </th>
                </>
              )}
              <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                NCM
              </th>
              <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                NVE
              </th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {filteredComponents.map((component) => {
              const isSelected = selectedComponents.has(component.id);
              const isBeingEdited = isEditMode;
              const componentData = isBeingEdited && editedComponents.has(component.id) 
                ? editedComponents.get(component.id)! 
                : component;
              const stockEntry = stockEntries.get(component.id);
              
              return (
                <tr 
                  key={component.id} 
                  className={`hover:bg-gray-50 transition-colors duration-150 ${
                    isSelected ? 'bg-blue-50' : ''
                  } ${
                    isBeingEdited ? 'border-l-4 border-orange-500' : ''
                  }`}
                >
                  <td className="px-3 py-4">
                    <button
                      onClick={() => handleSelectComponent(component.id)}
                      className="text-gray-600 hover:text-gray-800"
                    >
                      {isSelected ? 
                        <CheckSquare size={18} className="text-blue-600" /> : 
                        <Square size={18} />
                      }
                    </button>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {component.id}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {isBeingEdited ? (
                      <select
                        value={componentData.group}
                        onChange={(e) => handleComponentEdit(component.id, 'group', e.target.value)}
                        className="w-full px-2 py-1 border border-gray-300 rounded-lg focus:border-blue-500 focus:ring-1 focus:ring-blue-200 bg-white"
                      >
                        {COMPONENT_GROUPS.map(group => (
                          <option key={group} value={group}>{group}</option>
                        ))}
                      </select>
                    ) : (
                      component.group
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {isBeingEdited ? (
                      <input
                        type="text"
                        value={componentData.device || ''}
                        onChange={(e) => handleComponentEdit(component.id, 'device', e.target.value)}
                        className="w-full px-2 py-1 border border-gray-300 rounded-lg focus:border-blue-500 focus:ring-1 focus:ring-blue-200"
                      />
                    ) : (
                      component.device || '-'
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {isBeingEdited ? (
                      <input
                        type="text"
                        value={componentData.value || ''}
                        onChange={(e) => handleComponentEdit(component.id, 'value', e.target.value)}
                        className="w-full px-2 py-1 border border-gray-300 rounded-lg focus:border-blue-500 focus:ring-1 focus:ring-blue-200"
                      />
                    ) : (
                      component.value || '-'
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {isBeingEdited ? (
                      <input
                        type="text"
                        value={componentData.package || ''}
                        onChange={(e) => handleComponentEdit(component.id, 'package', e.target.value)}
                        className="w-full px-2 py-1 border border-gray-300 rounded-lg focus:border-blue-500 focus:ring-1 focus:ring-blue-200"
                      />
                    ) : (
                      component.package || '-'
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {component.createdAt ? new Date(component.createdAt).toLocaleDateString('pt-BR') : '-'}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {isBeingEdited ? (
                      <input
                        type="number"
                        step="0.01"
                        value={componentData.price || ''}
                        onChange={(e) => handleComponentEdit(component.id, 'price', Number(e.target.value))}
                        className="w-24 px-2 py-1 border border-gray-300 rounded-lg focus:border-blue-500 focus:ring-1 focus:ring-blue-200"
                      />
                    ) : (
                      component.price ? `R$ ${component.price.toFixed(2)}` : '-'
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {isBeingEdited ? (
                      <input
                        type="text"
                        value={componentData.characteristics || ''}
                        onChange={(e) => handleComponentEdit(component.id, 'characteristics', e.target.value)}
                        className="w-full px-2 py-1 border border-gray-300 rounded-lg focus:border-blue-500 focus:ring-1 focus:ring-blue-200"
                      />
                    ) : (
                      component.characteristics || '-'
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    {isBeingEdited ? (
                      <select
                        value={componentData.environment || 'estoque'}
                        onChange={(e) => handleComponentEdit(component.id, 'environment', e.target.value as 'estoque' | 'laboratorio')}
                        className="w-full px-2 py-1 border border-gray-300 rounded-lg focus:border-blue-500 focus:ring-1 focus:ring-blue-200 bg-white"
                      >
                        <option value="estoque">Estoque</option>
                        <option value="laboratorio">Laboratório</option>
                      </select>
                    ) : (
                      <span className={`inline-flex px-2 py-1 text-xs font-medium rounded-md ${
                        getEnvironmentClasses(component.environment || 'estoque')
                      }`}>
                        {getEnvironmentLabel(component.environment || 'estoque')}
                      </span>
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {isBeingEdited ? (
                      <input
                        type="text"
                        value={componentData.drawer || ''}
                        onChange={(e) => handleComponentEdit(component.id, 'drawer', e.target.value)}
                        className="w-full px-2 py-1 border border-gray-300 rounded-lg focus:border-blue-500 focus:ring-1 focus:ring-blue-200"
                      />
                    ) : (
                      component.drawer || '-'
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {isBeingEdited ? (
                      <input
                        type="text"
                        value={componentData.division || ''}
                        onChange={(e) => handleComponentEdit(component.id, 'division', e.target.value)}
                        className="w-full px-2 py-1 border border-gray-300 rounded-lg focus:border-blue-500 focus:ring-1 focus:ring-blue-200"
                      />
                    ) : (
                      component.division || '-'
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    {isBeingEdited ? (
                      <input
                        type="number"
                        value={componentData.quantityInStock}
                        onChange={(e) => handleComponentEdit(component.id, 'quantityInStock', Number(e.target.value))}
                        className="w-24 px-2 py-1 border border-gray-300 rounded-lg focus:border-blue-500 focus:ring-1 focus:ring-blue-200"
                      />
                    ) : (
                      <span className={`inline-flex px-2.5 py-1 text-xs font-medium rounded-full ${
                        getStockStatusClasses(component.quantityInStock, component.minimumQuantity)
                      }`}>
                        {component.quantityInStock}
                      </span>
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    {isBeingEdited ? (
                      <input
                        type="number"
                        value={componentData.minimumQuantity}
                        onChange={(e) => handleComponentEdit(component.id, 'minimumQuantity', Number(e.target.value))}
                        className="w-20 px-2 py-1 border border-gray-300 rounded-lg focus:border-blue-500 focus:ring-1 focus:ring-blue-200"
                      />
                    ) : (
                      <span className={`text-sm ${
                        component.quantityInStock <= component.minimumQuantity ? 'text-red-600 font-medium' : ''
                      }`}>
                        {component.minimumQuantity}
                      </span>
                    )}
                  </td>
                  {isEditMode && (
                    <>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center gap-1">
                          <TrendingUp className="text-green-500" size={16} />
                          <input
                            type="number"
                            value={stockEntry?.entryQuantity || ''}
                            onChange={(e) => handleStockEntry(component.id, 'entry', e.target.value)}
                            placeholder="0"
                            min="0"
                            className="w-20 px-2 py-1 border border-green-300 rounded-lg focus:border-green-500 focus:ring-1 focus:ring-green-200"
                          />
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center gap-1">
                          <TrendingDown className="text-red-500" size={16} />
                          <input
                            type="number"
                            value={stockEntry?.exitQuantity || ''}
                            onChange={(e) => handleStockEntry(component.id, 'exit', e.target.value)}
                            placeholder="0"
                            min="0"
                            max={componentData.quantityInStock}
                            className="w-20 px-2 py-1 border border-red-300 rounded-lg focus:border-red-500 focus:ring-1 focus:ring-red-200"
                          />
                        </div>
                      </td>
                    </>
                  )}
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {isBeingEdited ? (
                      <input
                        type="text"
                        value={componentData.ncm || ''}
                        onChange={(e) => handleComponentEdit(component.id, 'ncm', e.target.value)}
                        className="w-full px-2 py-1 border border-gray-300 rounded-lg focus:border-blue-500 focus:ring-1 focus:ring-blue-200"
                      />
                    ) : (
                      component.ncm || '-'
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {isBeingEdited ? (
                      <input
                        type="text"
                        value={componentData.nve || ''}
                        onChange={(e) => handleComponentEdit(component.id, 'nve', e.target.value)}
                        className="w-full px-2 py-1 border border-gray-300 rounded-lg focus:border-blue-500 focus:ring-1 focus:ring-blue-200"
                      />
                    ) : (
                      component.nve || '-'
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>

        {/* Paginação no final */}
        {filteredComponents.length > 0 && (
          <div className="border-t border-gray-200 bg-gray-50">
            <Pagination
              currentPage={pageNumber}
              pageSize={pageSize}
              totalItems={totalItems}
              onPageChange={handlePageChange}
              onPageSizeChange={handlePageSizeChange}
              loading={loading}
            />
          </div>
        )}
      </TableWrapper>

      {/* Delete Modal */}
      <ConfirmModal
        isOpen={deleteModal.show}
        onClose={() => setDeleteModal({ show: false, components: [] })}
        onConfirm={handleDelete}
        title="Excluir Componentes"
        message={`Tem certeza que deseja excluir ${deleteModal.components.length} componente(s)? Esta ação não pode ser desfeita.`}
        confirmText="Excluir"
        type="danger"
      />

      {/* Modal de Exportação */}
      {showExportModal && (
        <div className="fixed inset-0 bg-black bg-opacity-30 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl shadow-xl w-full max-w-lg p-6">
            <h3 className="text-lg font-semibold text-gray-800 mb-4">
              Selecione as colunas para exportar
            </h3>
            
            <div className="mb-4 max-h-60 overflow-y-auto">
              {columnOptions.map(col => (
                <label key={col.id} className="flex items-center gap-2 p-2 hover:bg-gray-50 rounded">
                  <input
                    type="checkbox"
                    checked={selectedColumns.has(col.id)}
                    onChange={(e) => {
                      const newSelected = new Set(selectedColumns);
                      if (e.target.checked) {
                        newSelected.add(col.id);
                      } else {
                        newSelected.delete(col.id);
                      }
                      setSelectedColumns(newSelected);
                    }}
                    className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                  />
                  <span className="text-sm text-gray-700">{col.label}</span>
                </label>
              ))}
            </div>
            
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setShowExportModal(false)}
                className="px-4 py-2 text-gray-600 hover:text-gray-800 hover:bg-gray-100 rounded-lg"
              >
                Cancelar
              </button>
              <button
                onClick={handleExport}
                disabled={selectedColumns.size === 0}
                className="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 disabled:bg-gray-400 disabled:cursor-not-allowed"
              >
                Exportar
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ComponentsManagePage;