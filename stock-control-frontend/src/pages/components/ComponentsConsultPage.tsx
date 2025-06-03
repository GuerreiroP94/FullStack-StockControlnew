import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  Search, 
  Filter, 
  Pencil, 
  Cpu,
  FileSpreadsheet,
  X,
  CheckSquare,
  Square,
  ShoppingBag,
  Package,
  Save
} from 'lucide-react';
import componentsService from '../../services/components.service';
import exportService from '../../services/export.service';
import { Component, ComponentFilter } from '../../types';
import { COMPONENT_GROUPS } from '../../utils/constants';
import LoadingSpinner from '../../components/common/LoadingSpinner';
import ErrorMessage from '../../components/common/ErrorMessage';
import SuccessMessage from '../../components/common/SuccessMessage';
import { useFilters, useComponentSelection } from '../../hooks';
import ComponentFilters from '../../components/forms/ComponentFilters';

const ComponentsConsultPage: React.FC = () => {
  const navigate = useNavigate();
  const [components, setComponents] = useState<Component[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  
  // Hook de seleção
const {
  selectedComponents,
  handleSelectComponent,
  handleSelectAll,
  clearSelection,
  selectedCount
} = useComponentSelection();
  
  // Estados de edição
  const [isEditMode, setIsEditMode] = useState(false);
  const [editedComponents, setEditedComponents] = useState<Map<number, Component>>(new Map());
  
  // Estados para exportação personalizada
  const [showExportModal, setShowExportModal] = useState(false);
  const [selectedColumns, setSelectedColumns] = useState<Set<string>>(new Set([
    'grupo', 'device', 'value', 'package', 'caracteristica', 
    'cod_interno', 'gaveta', 'divisao', 'preco', 'data_entrada',
    'qtd_estoque', 'entrada', 'saida', 'ncm', 'nve'
  ]));
  
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

  // Busca em tempo real
  const [filteredComponents, setFilteredComponents] = useState<Component[]>([]);

  useEffect(() => {
    fetchComponents();
  }, [filters.group, filters.device, filters.package, filters.value]);

  useEffect(() => {
  fetchComponents();
}, [filters.group, filters.device, filters.package, filters.value]);

const fetchComponents = async () => {
  try {
    setLoading(true);
    const data = await componentsService.getAll(filters);
    setComponents(data);
    setFilteredComponents(data);
    
    // Usar o hook para atualizar dropdowns
    updateDropdowns(data);
  } catch (error) {
    setError('Erro ao carregar componentes');
    console.error(error);
  } finally {
    setLoading(false);
  }
};
  const handleEditClick = () => {
    setIsEditMode(!isEditMode);
    if (!isEditMode) {
      // Inicializar todos os componentes para edição
      const newEditedComponents = new Map<number, Component>();
      filteredComponents.forEach(component => {
        newEditedComponents.set(component.id, { ...component });
      });
      setEditedComponents(newEditedComponents);
    } else {
      // Ao sair do modo de edição, limpar componentes editados
      setEditedComponents(new Map());
    }
  };

  const handleComponentEdit = (componentId: number, field: keyof Component, value: any) => {
    const component = editedComponents.get(componentId) || components.find(c => c.id === componentId);
    if (!component) return;

    const updatedComponent = { ...component, [field]: value };
    const newEditedComponents = new Map(editedComponents);
    newEditedComponents.set(componentId, updatedComponent);
    setEditedComponents(newEditedComponents);
  };

  const handleSaveChanges = async () => {
    if (!isEditMode) {
      setError('Habilite a edição antes de tentar salvar as edições');
      return;
    }

    try {
      const updates: Promise<any>[] = [];
      
      // Processar apenas componentes que foram modificados
      const editedEntries = Array.from(editedComponents.entries());
      for (const [componentId, editedComponent] of editedEntries) {
        const originalComponent = components.find(c => c.id === componentId);
        if (!originalComponent) continue;

        // Verificar se houve mudanças no componente
        const hasChanges = JSON.stringify(originalComponent) !== JSON.stringify(editedComponent);
        
        if (!hasChanges) continue;

        // Atualizar componente
        updates.push(componentsService.update(componentId, editedComponent));
      }
      
      // Executar atualizações
      if (updates.length > 0) {
        await Promise.all(updates);
        setSuccess(`${updates.length} componente(s) atualizado(s) com sucesso!`);
      } else {
        setSuccess('Nenhuma alteração foi detectada para salvar.');
      }
      
      setIsEditMode(false);
      setEditedComponents(new Map());
      fetchComponents();
    } catch (error) {
      setError('Erro ao salvar alterações');
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
    if (selectedComponents.size === 0) {
      setError('Selecione ao menos um componente para exportar');
      return;
    }
    setShowExportModal(true);
  };

  const handleExport = () => {
    const selectedData = filteredComponents.filter(c => selectedComponents.has(c.id));
    
    // Filtrar apenas as colunas selecionadas
    const columnsArray = Array.from(selectedColumns);
    const filteredData = selectedData.map(comp => {
      const filtered: any = { id: comp.id };
      
      columnsArray.forEach(col => {
        switch(col) {
          case 'grupo': filtered.group = comp.group; break;
          case 'device': filtered.device = comp.device; break;
          case 'value': filtered.value = comp.value; break;
          case 'package': filtered.package = comp.package; break;
          case 'caracteristica': filtered.characteristics = comp.characteristics; break;
          case 'cod_interno': filtered.internalCode = comp.internalCode; break;
          case 'gaveta': filtered.drawer = comp.drawer; break;
          case 'divisao': filtered.division = comp.division; break;
          case 'preco': filtered.price = comp.price; break;
          case 'data_entrada': filtered.createdAt = comp.createdAt; break;
          case 'qtd_estoque': filtered.quantityInStock = comp.quantityInStock; break;
          case 'ncm': filtered.ncm = comp.ncm; break;
          case 'nve': filtered.nve = comp.nve; break;
        }
      });
      
      return filtered;
    });
    
    exportService.exportComponentsToExcel(filteredData as Component[], 
      `componentes_consulta_${new Date().toISOString().split('T')[0]}.csv`
    );
    
    setSuccess(`${selectedData.length} componentes exportados com sucesso!`);
    setShowExportModal(false);
  };

  const columnOptions = [
    { id: 'grupo', label: 'Grupo' },
    { id: 'device', label: 'Device' },
    { id: 'value', label: 'Value' },
    { id: 'package', label: 'Package' },
    { id: 'caracteristica', label: 'Característica' },
    { id: 'cod_interno', label: 'Cód. Interno' },
    { id: 'gaveta', label: 'Gaveta' },
    { id: 'divisao', label: 'Divisão' },
    { id: 'preco', label: 'Preço' },
    { id: 'data_entrada', label: 'Data de Entrada' },
    { id: 'qtd_estoque', label: 'Qtd. Estoque' },
    { id: 'entrada', label: 'Entrada' },
    { id: 'saida', label: 'Saída' },
    { id: 'ncm', label: 'NCM' },
    { id: 'nve', label: 'NVE' }
  ];

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
              <h1 className="text-2xl font-bold text-gray-800">Consulta de Componentes</h1>
              <p className="text-sm text-gray-500">Consulte e exporte componentes do estoque</p>
            </div>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
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
            
            {selectedComponents.size > 0 && (
              <button
                onClick={() => clearSelection()}
                className="flex items-center gap-2 px-4 py-2.5 bg-gray-400 text-white rounded-lg hover:bg-gray-500 transition-all duration-200"
              >
                <X size={18} />
                <span className="font-medium">Limpar Seleção ({selectedComponents.size})</span>
              </button>
            )}
            
            <button
              onClick={handleExportClick}
              className={`flex items-center gap-2 px-4 py-2.5 rounded-lg transition-all duration-200 ${
                selectedComponents.size > 0
                  ? 'bg-purple-600 text-white hover:bg-purple-700'
                  : 'bg-gray-300 text-gray-500 cursor-not-allowed'
              }`}
              disabled={selectedComponents.size === 0}
            >
              <FileSpreadsheet size={18} />
              <span className="font-medium">Exportar</span>
            </button>
            
            <button
              onClick={handleCreateProductClick}
              className={`flex items-center gap-2 px-4 py-2.5 rounded-lg transition-all duration-200 ${
                selectedComponents.size > 0
                  ? 'bg-gradient-to-r from-green-500 to-green-600 text-white hover:from-green-600 hover:to-green-700'
                  : 'bg-gray-300 text-gray-500 cursor-not-allowed'
              }`}
              disabled={selectedComponents.size === 0}
            >
              <ShoppingBag size={18} />
              <span className="font-medium">Criar Produto</span>
            </button>
            
            {isEditMode && (
              <button
                onClick={handleSaveChanges}
                className="flex items-center gap-2 px-4 py-2.5 bg-gradient-to-r from-blue-500 to-blue-600 text-white rounded-lg hover:from-blue-600 hover:to-blue-700 transition-all duration-200"
              >
                <Save size={18} />
                <span className="font-medium">Salvar Alterações</span>
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Messages */}
      {error && <ErrorMessage message={error} onClose={() => setError('')} className="mb-6" />}
      {success && <SuccessMessage message={success} onClose={() => setSuccess('')} className="mb-6" />}

      {/* Filters */}
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
/>

      {/* Table */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
        {isEditMode && (
          <div className="bg-orange-50 border-b border-orange-200 p-3 text-center">
            <p className="text-sm text-orange-800 font-medium">
              📝 Modo de Edição Ativo - Todos os campos podem ser editados
            </p>
          </div>
        )}
        {loading ? (
          <div className="p-12 text-center">
            <LoadingSpinner size="lg" message="Carregando componentes..." />
          </div>
        ) : filteredComponents.length === 0 ? (
          <div className="p-12 text-center">
            <Package className="mx-auto mb-4 text-gray-400" size={48} />
            <p className="text-lg font-medium text-gray-600">Nenhum componente encontrado</p>
            <p className="text-sm text-gray-500 mt-1">
              {searchTerm || filters.group || filters.device || filters.package || filters.value
                ? "Tente ajustar os filtros de busca" 
                : "Adicione novos componentes ao sistema"}
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
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
                    Característica
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Cód. Interno
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Gaveta
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Divisão
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Preço
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Data de Entrada
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Qtd. Estoque
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Entrada
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Saída
                  </th>
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
                        {isBeingEdited ? (
                          <input
                            type="text"
                            value={componentData.group}
                            onChange={(e) => handleComponentEdit(component.id, 'group', e.target.value)}
                            className="w-full px-2 py-1 border border-gray-300 rounded-lg focus:border-blue-500 focus:ring-1 focus:ring-blue-200"
                          />
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
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        {isBeingEdited ? (
                          <input
                            type="text"
                            value={componentData.internalCode || ''}
                            onChange={(e) => handleComponentEdit(component.id, 'internalCode', e.target.value)}
                            className="w-full px-2 py-1 border border-gray-300 rounded-lg focus:border-blue-500 focus:ring-1 focus:ring-blue-200"
                          />
                        ) : (
                          component.internalCode || '-'
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
                        {component.createdAt ? new Date(component.createdAt).toLocaleDateString('pt-BR') : '-'}
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
                            component.quantityInStock === 0 
                              ? 'bg-red-100 text-red-800' 
                              : component.quantityInStock <= component.minimumQuantity 
                                ? 'bg-yellow-100 text-yellow-800'
                                : 'bg-green-100 text-green-800'
                          }`}>
                            {component.quantityInStock}
                          </span>
                        )}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        0
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        0
                      </td>
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
          </div>
        )}
      </div>

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

export default ComponentsConsultPage;