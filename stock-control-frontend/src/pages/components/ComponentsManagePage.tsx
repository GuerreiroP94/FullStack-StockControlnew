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
  Package
} from 'lucide-react';
import componentsService from '../../services/components.service';
import exportService from '../../services/export.service';
import { Component, ComponentFilter, ComponentStockEntry } from '../../types';
import { COMPONENT_GROUPS } from '../../utils/constants';
import LoadingSpinner from '../../components/common/LoadingSpinner';
import ConfirmModal from '../../components/common/ConfirmModal';
import ErrorMessage from '../../components/common/ErrorMessage';
import SuccessMessage from '../../components/common/SuccessMessage';
import movementsService from '../../services/movements.service';

const ComponentsManagePage: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const [components, setComponents] = useState<Component[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [deleteModal, setDeleteModal] = useState<{ show: boolean; components: Component[] }>({ show: false, components: [] });
  
  // Estados de edição
  const [isEditMode, setIsEditMode] = useState(false);
  const [selectedComponents, setSelectedComponents] = useState<Set<number>>(new Set());
  const [stockEntries, setStockEntries] = useState<Map<number, ComponentStockEntry>>(new Map());
  const [editedComponents, setEditedComponents] = useState<Map<number, Component>>(new Map());
  
  // Estados removidos: importação não é mais necessária
  
  // Estados para exportação personalizada
  const [showExportModal, setShowExportModal] = useState(false);
  const [selectedColumns, setSelectedColumns] = useState<Set<string>>(new Set([
    'id', 'name', 'characteristics', 'package', 'createdAt',
    'price', 'quantityInStock', 'minimumQuantity', 'environment',
    'drawer', 'division', 'ncm', 'nve'
  ]));
  
  // Dropdowns de grupos
  const [groups, setGroups] = useState<string[]>(COMPONENT_GROUPS);
  const [devices, setDevices] = useState<string[]>([]);
  const [packages, setPackages] = useState<string[]>([]);
  const [values, setValues] = useState<string[]>([]);
  
  // Filtros
  const [filters, setFilters] = useState<ComponentFilter>({
    name: '',
    group: '',
    device: '',
    package: '',
    value: '',
    searchTerm: '',
    pageNumber: 1,
    pageSize: 100
  });

  // Busca em tempo real
  const [searchTerm, setSearchTerm] = useState('');
  const [filteredComponents, setFilteredComponents] = useState<Component[]>([]);

  useEffect(() => {
    // Verificar se vieram componentes pré-selecionados da página de consulta
    const state = location.state as { selectedComponents?: number[] };
    if (state?.selectedComponents) {
      setSelectedComponents(new Set(state.selectedComponents));
      setIsEditMode(true);
    }
    
    fetchComponents();
  }, [filters.group, filters.device, filters.package, filters.value]);

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
      const data = await componentsService.getAll(filters);
      setComponents(data);
      setFilteredComponents(data);
      
      // Extrair valores únicos para os dropdowns
      const uniqueGroups = Array.from(new Set(data.map(c => c.group).filter(Boolean)));
      const uniqueDevices = Array.from(new Set(data.map(c => c.device).filter(Boolean)));
      const uniquePackages = Array.from(new Set(data.map(c => c.package).filter(Boolean)));
      const uniqueValues = Array.from(new Set(data.map(c => c.value).filter(Boolean)));

      if (uniqueGroups.length > 0) {
        setGroups([...COMPONENT_GROUPS, ...uniqueGroups.filter(g => !COMPONENT_GROUPS.includes(g))]);
      }
      if (uniqueDevices.length > 0) {
        setDevices(uniqueDevices as string[]);
      }
      if (uniquePackages.length > 0) {
        setPackages(uniquePackages as string[]);
      }
      if (uniqueValues.length > 0) {
        setValues(uniqueValues as string[]);
      }
    } catch (error) {
      setError('Erro ao carregar componentes');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleSelectAll = () => {
    if (selectedComponents.size === filteredComponents.length) {
      setSelectedComponents(new Set());
    } else {
      setSelectedComponents(new Set(filteredComponents.map(c => c.id)));
    }
  };

  const handleSelectComponent = (id: number) => {
    const newSelected = new Set(selectedComponents);
    if (newSelected.has(id)) {
      newSelected.delete(id);
    } else {
      newSelected.add(id);
    }
    setSelectedComponents(newSelected);
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
      // Inicializar todos os componentes para edição
      const newEditedComponents = new Map<number, Component>();
      components.forEach(component => {
        newEditedComponents.set(component.id, { ...component });
      });
      setEditedComponents(newEditedComponents);
      
      // Se não há componentes selecionados, selecionar todos automaticamente
      if (selectedComponents.size === 0) {
        setSelectedComponents(new Set(components.map(c => c.id)));
      }
    } else {
      // Ao sair do modo de edição, limpar seleções e componentes editados
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
      
      // Processar apenas componentes que foram modificados ou têm movimentações
      const editedEntries = Array.from(editedComponents.entries());
      for (const [componentId, editedComponent] of editedEntries) {
        const originalComponent = components.find(c => c.id === componentId);
        if (!originalComponent) continue;

        // Verificar se houve mudanças no componente
        const hasChanges = JSON.stringify(originalComponent) !== JSON.stringify(editedComponent);
        const stockEntry = stockEntries.get(componentId);
        const hasStockMovement = stockEntry && 
          ((stockEntry.entryQuantity !== undefined && stockEntry.entryQuantity > 0) || 
           (stockEntry.exitQuantity !== undefined && stockEntry.exitQuantity > 0));

        // Só processar se houve mudanças ou movimentações
        if (!hasChanges && !hasStockMovement) continue;

        // Validações
        if (!editedComponent.name) {
          setError('Nome é obrigatório');
          return;
        }

        // Atualizar componente se houve mudanças
        if (hasChanges) {
          updates.push(componentsService.update(componentId, editedComponent));
        }

        // Processar movimentações de estoque
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
      
      // Executar atualizações
      if (updates.length > 0) {
        await Promise.all(updates);
      }
      
      // Criar movimentações se houver
      if (movements.length > 0) {
        await movementsService.createBulk({ movements });
      }
      
      // Mensagem de sucesso
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
      setSelectedComponents(new Set());
      fetchComponents();
    } catch (error) {
      setError('Erro ao salvar alterações');
    }
  };

  const handleDeleteClick = () => {
    if (selectedComponents.size === 0) {
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
      setSelectedComponents(new Set());
      fetchComponents();
      setDeleteModal({ show: false, components: [] });
    } catch (error) {
      setError('Erro ao excluir componentes');
    }
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
        if (col in comp) {
          filtered[col] = comp[col as keyof Component];
        }
      });
      
      return filtered;
    });
    
    exportService.exportComponentsToExcel(filteredData as Component[], 
      `componentes_${new Date().toISOString().split('T')[0]}.csv`
    );
    
    setSuccess(`${selectedData.length} componentes exportados com sucesso!`);
    setShowExportModal(false);
  };

  const columnOptions = [
    { id: 'id', label: 'Id' },
    { id: 'name', label: 'Nome' },
    { id: 'characteristics', label: 'Característica' },
    { id: 'package', label: 'Package' },
    { id: 'createdAt', label: 'Data' },
    { id: 'price', label: 'Preço' },
    { id: 'quantityInStock', label: 'Quantidade em Estoque' },
    { id: 'minimumQuantity', label: 'QT MIN' },
    { id: 'environment', label: 'Ambiente' },
    { id: 'drawer', label: 'Gaveta' },
    { id: 'division', label: 'Divisão' },
    { id: 'ncm', label: 'NCM' },
    { id: 'nve', label: 'NVE' },
    { id: 'group', label: 'Grupo' },
    { id: 'device', label: 'Device' },
    { id: 'value', label: 'Value' }
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
              <h1 className="text-2xl font-bold text-gray-800">Gerenciar Componentes</h1>
              <p className="text-sm text-gray-500">Cadastre, edite e gerencie componentes do estoque</p>
            </div>
          </div>
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
                selectedComponents.size > 0
                  ? 'bg-red-600 text-white hover:bg-red-700'
                  : 'bg-gray-300 text-gray-500 cursor-not-allowed'
              }`}
              disabled={selectedComponents.size === 0}
            >
              <Trash2 size={18} />
              <span className="font-medium">Deletar</span>
            </button>
            
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
              onClick={handleSaveChanges}
              className={`flex items-center gap-2 px-4 py-2.5 rounded-lg transition-all duration-200 ${
                isEditMode
                  ? 'bg-gradient-to-r from-green-500 to-green-600 text-white hover:from-green-600 hover:to-green-700'
                  : 'bg-gray-300 text-gray-500 cursor-not-allowed'
              }`}
              disabled={!isEditMode}
            >
              <Save size={18} />
              <span className="font-medium">Salvar Alterações</span>
            </button>
            
            {selectedComponents.size > 0 && (
              <button
                onClick={() => {
                  setSelectedComponents(new Set());
                  if (isEditMode) {
                    setIsEditMode(false);
                    setEditedComponents(new Map());
                    setStockEntries(new Map());
                  }
                }}
                className="flex items-center gap-2 px-4 py-2.5 bg-gray-400 text-white rounded-lg hover:bg-gray-500 transition-all duration-200"
              >
                <X size={18} />
                <span className="font-medium">Cancelar Seleção ({selectedComponents.size})</span>
              </button>
            )}
          </div>
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
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 xl:grid-cols-5 gap-4">
          {/* Grupo */}
          <select
            value={filters.group || ''}
            onChange={(e) => setFilters(prev => ({ ...prev, group: e.target.value }))}
            className="w-full px-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200 bg-white"
          >
            <option value="">Todos os Grupos</option>
            {groups.map(group => (
              <option key={group} value={group}>{group}</option>
            ))}
          </select>

          {/* Device */}
          <select
            value={filters.device || ''}
            onChange={(e) => setFilters(prev => ({ ...prev, device: e.target.value }))}
            className="w-full px-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200 bg-white"
          >
            <option value="">Todos os Devices</option>
            {devices.map(device => (
              <option key={device} value={device}>{device}</option>
            ))}
          </select>

          {/* Package */}
          <select
            value={filters.package || ''}
            onChange={(e) => setFilters(prev => ({ ...prev, package: e.target.value }))}
            className="w-full px-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200 bg-white"
          >
            <option value="">Todos os Packages</option>
            {packages.map(pkg => (
              <option key={pkg} value={pkg}>{pkg}</option>
            ))}
          </select>

          {/* Value */}
          <select
            value={filters.value || ''}
            onChange={(e) => setFilters(prev => ({ ...prev, value: e.target.value }))}
            className="w-full px-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200 bg-white"
          >
            <option value="">Todos os Values</option>
            {values.map(value => (
              <option key={value} value={value}>{value}</option>
            ))}
          </select>

          {/* Search */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" size={18} />
            <input
              type="text"
              placeholder="Buscar em todas as colunas..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200"
            />
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
        {isEditMode && (
          <>
            <div className="bg-orange-50 border-b border-orange-200 p-3 text-center">
              <p className="text-sm text-orange-800 font-medium">
                📝 Modo de Edição Ativo - Todos os componentes podem ser editados
              </p>
            </div>
            <div className="p-4 bg-blue-50 border-b border-blue-200">
              <p className="text-sm text-blue-800 mb-2">
                <strong>Nota:</strong> Para editar Grupo, Device e Value dos componentes, use a edição individual clicando no botão editar da página de consulta.
              </p>
            </div>
          </>
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
                      onClick={handleSelectAll}
                      className="text-gray-600 hover:text-gray-800"
                    >
                      {selectedComponents.size === filteredComponents.length ? 
                        <CheckSquare size={20} /> : 
                        <Square size={20} />
                      }
                    </button>
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Id
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Nome
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Característica
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
                    Quantidade em Estoque
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    QT MIN
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
                    NCM
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    NVE
                  </th>
                  {/* Hidden columns for functionality but not displayed */}
                  <th className="hidden">Grupo</th>
                  <th className="hidden">Device</th>
                  <th className="hidden">Value</th>
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
                        {component.id}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        {isBeingEdited ? (
                          <input
                            type="text"
                            value={componentData.name}
                            onChange={(e) => handleComponentEdit(component.id, 'name', e.target.value)}
                            className="w-full px-2 py-1 border border-gray-300 rounded-lg focus:border-blue-500 focus:ring-1 focus:ring-blue-200"
                          />
                        ) : (
                          component.name
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
                      <td className="px-6 py-4 whitespace-nowrap">
                        {isBeingEdited ? (
                          <input
                            type="number"
                            value={componentData.quantityInStock}
                            onChange={(e) => handleComponentEdit(component.id, 'quantityInStock', Number(e.target.value))}
                            className="w-24 px-2 py-1 border border-gray-300 rounded-lg focus:border-blue-500 focus:ring-1 focus:ring-blue-200"
                          />
                        ) : (
                          <p className="text-sm font-medium text-gray-900">{component.quantityInStock}</p>
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
                          component.minimumQuantity
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
                            component.environment === 'laboratorio' 
                              ? 'bg-purple-100 text-purple-800' 
                              : 'bg-green-100 text-green-800'
                          }`}>
                            {component.environment === 'laboratorio' ? 'Laboratório' : 'Estoque'}
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
                      {/* Hidden fields for functionality */}
                      <td className="hidden">
                        {isBeingEdited && (
                          <>
                            <input type="hidden" value={componentData.group} />
                            <input type="hidden" value={componentData.device || ''} />
                            <input type="hidden" value={componentData.value || ''} />
                          </>
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