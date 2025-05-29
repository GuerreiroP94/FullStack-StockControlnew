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
  Package,
  FileSpreadsheet,
  X,
  Save,
  CheckSquare,
  Square,
  ShoppingBag,
  Upload
} from 'lucide-react';
import componentsService from '../../services/components.service';
import exportService from '../../services/export.service';
import { Component, ComponentFilter, ComponentStockEntry } from '../../types';
import { COMPONENT_GROUPS, PAGINATION, COMPONENT_ENVIRONMENTS } from '../../utils/constants';
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
  const [deleteModal, setDeleteModal] = useState<{ show: boolean; components: Component[] }>({ show: false, components: [] });
  
  // Estados de edição
  const [isEditMode, setIsEditMode] = useState(false);
  const [selectedComponents, setSelectedComponents] = useState<Set<number>>(new Set());
  const [stockEntries, setStockEntries] = useState<Map<number, ComponentStockEntry>>(new Map());
  
  // Estado de importação
  const [showImportModal, setShowImportModal] = useState(false);
  const [importFile, setImportFile] = useState<File | null>(null);
  const [importing, setImporting] = useState(false);
  
  // Dropdowns de grupos
  const [groups, setGroups] = useState<string[]>(COMPONENT_GROUPS);
  const [devices, setDevices] = useState<string[]>([]);
  const [packages, setPackages] = useState<string[]>([]);
  const [values, setValues] = useState<string[]>([]);
  
  // Modais para novos itens
  const [showNewGroup, setShowNewGroup] = useState(false);
  const [showNewDevice, setShowNewDevice] = useState(false);
  const [showNewPackage, setShowNewPackage] = useState(false);
  const [showNewValue, setShowNewValue] = useState(false);
  
  // Valores dos novos itens
  const [newGroupName, setNewGroupName] = useState('');
  const [newDeviceName, setNewDeviceName] = useState('');
  const [newPackageName, setNewPackageName] = useState('');
  const [newValueName, setNewValueName] = useState('');
  
  // Filtros
  const [filters, setFilters] = useState<ComponentFilter & {
    device?: string;
    package?: string;
    value?: string;
    searchTerm?: string;
  }>({
    name: '',
    group: '',
    device: '',
    package: '',
    value: '',
    searchTerm: '',
    pageNumber: 1,
    pageSize: PAGINATION.DEFAULT_PAGE_SIZE
  });

  // Estado para controlar se deve fazer a busca
  const [shouldSearch, setShouldSearch] = useState(true);

  useEffect(() => {
    if (shouldSearch) {
      fetchComponents();
      setShouldSearch(false);
    }
  }, [shouldSearch, filters]);

  const fetchComponents = async () => {
    try {
      setLoading(true);
      const data = await componentsService.getAll(filters);
      setComponents(data);
      
      // Extrair valores únicos para os dropdowns
      const uniqueGroups = Array.from(new Set(data.map(c => c.group).filter(Boolean)));
      const uniqueDevices = Array.from(new Set(data.map(c => c.device).filter(Boolean)));
      const uniquePackages = Array.from(new Set(data.map(c => c.package).filter(Boolean)));
      const uniqueValues = Array.from(new Set(data.map(c => c.value).filter(Boolean)));

      setFilterOptions({
        groups: uniqueGroups as string[],
        devices: uniqueDevices as string[],
        packages: uniquePackages as string[],
        values: uniqueValues as string[]
      });
    } catch (error) {
      setError('Erro ao carregar componentes');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = () => {
    setShouldSearch(true);
  };

  const handleSelectAll = () => {
    if (selectedComponents.size === components.length) {
      setSelectedComponents(new Set());
    } else {
      setSelectedComponents(new Set(components.map(c => c.id)));
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

  const handleSaveChanges = async () => {
    try {
      // Aqui você implementaria a lógica para salvar as alterações
      // incluindo as movimentações de estoque
      
      setSuccess('Alterações salvas com sucesso!');
      setIsEditMode(false);
      setStockEntries(new Map());
      fetchComponents();
    } catch (error) {
      setError('Erro ao salvar alterações');
    }
  };

  const handleDelete = async () => {
    try {
      // Implementar lógica de exclusão múltipla
      const selectedIds = Array.from(selectedComponents);
      // await componentsService.deleteMultiple(selectedIds);
      
      setSuccess('Componentes excluídos com sucesso!');
      setSelectedComponents(new Set());
      fetchComponents();
      setDeleteModal({ show: false, components: [] });
    } catch (error) {
      setError('Erro ao excluir componentes');
    }
  };

  const handleExport = () => {
    const selectedData = components.filter(c => selectedComponents.has(c.id));
    if (selectedData.length > 0) {
      exportService.exportComponentsToExcel(selectedData, `componentes_${new Date().toISOString().split('T')[0]}.csv`);
      setSuccess(`${selectedData.length} componentes exportados com sucesso!`);
    } else {
      setError('Nenhum componente selecionado para exportar');
    }
  };

  const handleCreateProduct = () => {
    const selectedData = components.filter(c => selectedComponents.has(c.id));
    navigate('/products/new', { state: { selectedComponents: selectedData } });
  };

  const handleAddNewGroup = () => {
    if (newGroupName && !groups.includes(newGroupName)) {
      setGroups([...groups, newGroupName]);
      setNewGroupName('');
      setShowNewGroup(false);
    }
  };

  const handleAddNewDevice = () => {
    if (newDeviceName && !devices.includes(newDeviceName)) {
      setDevices([...devices, newDeviceName]);
      setNewDeviceName('');
      setShowNewDevice(false);
    }
  };

  const handleAddNewPackage = () => {
    if (newPackageName && !packages.includes(newPackageName)) {
      setPackages([...packages, newPackageName]);
      setNewPackageName('');
      setShowNewPackage(false);
    }
  };

  const handleAddNewValue = () => {
    if (newValueName && !values.includes(newValueName)) {
      setValues([...values, newValueName]);
      setNewValueName('');
      setShowNewValue(false);
    }
  };

  const handleImportFile = async () => {
    if (!importFile) {
      setError('Selecione um arquivo para importar');
      return;
    }

    try {
      setImporting(true);
      const componentsData = await exportService.processImportFile(importFile);
      
      // Aqui você faria a chamada para a API para salvar os componentes
      // await componentsService.bulkCreate(componentsData);
      
      setSuccess(`${componentsData.length} componentes importados com sucesso!`);
      setShowImportModal(false);
      setImportFile(null);
      fetchComponents();
    } catch (error: any) {
      setError(`Erro ao importar arquivo: ${error.message}`);
    } finally {
      setImporting(false);
    }
  };

  const handleDownloadTemplate = () => {
    exportService.downloadImportTemplate();
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
          <div className="flex items-center gap-2 flex-wrap">
            <button
              onClick={() => navigate('/components/new')}
              className="flex items-center gap-2 px-4 py-2.5 bg-gradient-to-r from-blue-500 to-blue-600 text-white rounded-lg hover:from-blue-600 hover:to-blue-700 transition-all duration-200 shadow-sm"
            >
              <Plus size={18} />
              <span className="font-medium">Novo Componente</span>
            </button>
            
            <button
              onClick={() => setShowImportModal(true)}
              className="flex items-center gap-2 px-4 py-2.5 bg-gradient-to-r from-indigo-500 to-indigo-600 text-white rounded-lg hover:from-indigo-600 hover:to-indigo-700 transition-all duration-200 shadow-sm"
            >
              <Upload size={18} />
              <span className="font-medium">Importar</span>
            </button>
            
            {selectedComponents.size > 0 && (
              <>
                <button
                  onClick={handleCreateProduct}
                  className="flex items-center gap-2 px-4 py-2.5 bg-gradient-to-r from-green-500 to-green-600 text-white rounded-lg hover:from-green-600 hover:to-green-700 transition-all duration-200"
                >
                  <ShoppingBag size={18} />
                  <span className="font-medium">Criar Produto</span>
                </button>
                
                <button
                  onClick={() => setIsEditMode(!isEditMode)}
                  className="flex items-center gap-2 px-4 py-2.5 bg-gray-600 text-white rounded-lg hover:bg-gray-700 transition-all duration-200"
                >
                  <Pencil size={18} />
                  <span className="font-medium">Editar</span>
                </button>
                
                <button
                  onClick={() => setDeleteModal({ show: true, components: components.filter(c => selectedComponents.has(c.id)) })}
                  className="flex items-center gap-2 px-4 py-2.5 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-all duration-200"
                >
                  <Trash2 size={18} />
                  <span className="font-medium">Deletar</span>
                </button>
                
                <button
                  onClick={handleExport}
                  className="flex items-center gap-2 px-4 py-2.5 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-all duration-200"
                >
                  <FileSpreadsheet size={18} />
                  <span className="font-medium">Exportar</span>
                </button>
                
                <button
                  onClick={() => setSelectedComponents(new Set())}
                  className="flex items-center gap-2 px-4 py-2.5 bg-gray-400 text-white rounded-lg hover:bg-gray-500 transition-all duration-200"
                >
                  <X size={18} />
                  <span className="font-medium">Cancelar Seleção</span>
                </button>
              </>
            )}
            
            {isEditMode && (
              <button
                onClick={handleSaveChanges}
                className="flex items-center gap-2 px-4 py-2.5 bg-gradient-to-r from-green-500 to-green-600 text-white rounded-lg hover:from-green-600 hover:to-green-700 transition-all duration-200"
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
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
        <div className="flex items-center gap-3 mb-4">
          <Filter size={20} className="text-gray-500" />
          <h2 className="text-lg font-semibold text-gray-800">Filtros</h2>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 xl:grid-cols-5 gap-4">
          {/* Grupo */}
          <div className="relative">
            <select
              value={filters.group || ''}
              onChange={(e) => setFilters(prev => ({ ...prev, group: e.target.value }))}
              className="w-full px-4 py-2.5 pr-10 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200 bg-white"
            >
              <option value="">Todos os Grupos</option>
              {groups.map(group => (
                <option key={group} value={group}>{group}</option>
              ))}
            </select>
            <button
              onClick={() => setShowNewGroup(true)}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-blue-600 hover:text-blue-700"
              title="Novo Grupo"
            >
              <Plus size={18} />
            </button>
          </div>

          {/* Device */}
          <div className="relative">
            <select
              value={filters.device || ''}
              onChange={(e) => setFilters(prev => ({ ...prev, device: e.target.value }))}
              className="w-full px-4 py-2.5 pr-10 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200 bg-white"
            >
              <option value="">Todos os Devices</option>
              {devices.map(device => (
                <option key={device} value={device}>{device}</option>
              ))}
            </select>
            <button
              onClick={() => setShowNewDevice(true)}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-blue-600 hover:text-blue-700"
              title="Novo Device"
            >
              <Plus size={18} />
            </button>
          </div>

          {/* Package */}
          <div className="relative">
            <select
              value={filters.package || ''}
              onChange={(e) => setFilters(prev => ({ ...prev, package: e.target.value }))}
              className="w-full px-4 py-2.5 pr-10 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200 bg-white"
            >
              <option value="">Todos os Packages</option>
              {packages.map(pkg => (
                <option key={pkg} value={pkg}>{pkg}</option>
              ))}
            </select>
            <button
              onClick={() => setShowNewPackage(true)}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-blue-600 hover:text-blue-700"
              title="Novo Package"
            >
              <Plus size={18} />
            </button>
          </div>

          {/* Value */}
          <div className="relative">
            <select
              value={filters.value || ''}
              onChange={(e) => setFilters(prev => ({ ...prev, value: e.target.value }))}
              className="w-full px-4 py-2.5 pr-10 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200 bg-white"
            >
              <option value="">Todos os Values</option>
              {values.map(value => (
                <option key={value} value={value}>{value}</option>
              ))}
            </select>
            <button
              onClick={() => setShowNewValue(true)}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-blue-600 hover:text-blue-700"
              title="Novo Value"
            >
              <Plus size={18} />
            </button>
          </div>

          {/* Search */}
          <div className="flex gap-2">
            <input
              type="text"
              placeholder="Buscar em todas as colunas..."
              value={filters.searchTerm}
              onChange={(e) => setFilters(prev => ({ ...prev, searchTerm: e.target.value }))}
              onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
              className="flex-1 px-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200"
            />
            <button
              onClick={handleSearch}
              className="px-4 py-2.5 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-all duration-200"
            >
              <Search size={18} />
            </button>
          </div>
        </div>

        {/* Pagination Controls */}
        <div className="flex items-center justify-between mt-4">
          <select
            value={filters.pageSize}
            onChange={(e) => setFilters(prev => ({ ...prev, pageSize: Number(e.target.value), pageNumber: 1 }))}
            className="px-4 py-2 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200 bg-white"
          >
            {PAGINATION.PAGE_SIZE_OPTIONS.map(size => (
              <option key={size} value={size}>{size} por página</option>
            ))}
          </select>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setFilters(prev => ({ ...prev, pageNumber: Math.max(1, prev.pageNumber - 1) }))}
              disabled={filters.pageNumber === 1}
              className="px-3 py-1.5 border border-gray-300 rounded-lg hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Anterior
            </button>
            <span className="px-4 py-1.5 text-sm text-gray-600">
              Página {filters.pageNumber}
            </span>
            <button
              onClick={() => setFilters(prev => ({ ...prev, pageNumber: prev.pageNumber + 1 }))}
              disabled={components.length < filters.pageSize}
              className="px-3 py-1.5 border border-gray-300 rounded-lg hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Próxima
            </button>
          </div>
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
              {filters.searchTerm || filters.group || filters.device || filters.package || filters.value
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
                      {selectedComponents.size === components.length ? 
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
                    Características
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Código Interno
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Gaveta
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Divisão
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Quantidade em Estoque
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Data de Entrada
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Preço
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
                  <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Ambiente
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Status
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {components.map((component) => {
                  const status = getStockStatus(component.quantityInStock, component.minimumQuantity);
                  const isSelected = selectedComponents.has(component.id);
                  
                  return (
                    <tr 
                      key={component.id} 
                      className={`hover:bg-gray-50 transition-colors duration-150 ${isSelected ? 'bg-blue-50' : ''}`}
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
                        {component.group}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        {component.device || '-'}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        {component.value || '-'}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        {component.package || '-'}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        {component.characteristics || '-'}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        {component.internalCode || '-'}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        {component.drawer || '-'}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        {component.division || '-'}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <p className="text-sm font-medium text-gray-900">{component.quantityInStock}</p>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        {component.createdAt ? new Date(component.createdAt).toLocaleDateString('pt-BR') : '-'}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        {component.price ? `R$ ${component.price.toFixed(2)}` : '-'}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        {isEditMode ? (
                          <input
                            type="number"
                            min="0"
                            value={stockEntries.get(component.id)?.entryQuantity || ''}
                            onChange={(e) => handleStockEntry(component.id, 'entry', e.target.value)}
                            className="w-20 px-2 py-1 border border-gray-300 rounded-lg focus:border-blue-500 focus:ring-1 focus:ring-blue-200"
                            placeholder="0"
                          />
                        ) : '-'}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        {isEditMode ? (
                          <input
                            type="number"
                            min="0"
                            max={component.quantityInStock}
                            value={stockEntries.get(component.id)?.exitQuantity || ''}
                            onChange={(e) => handleStockEntry(component.id, 'exit', e.target.value)}
                            className="w-20 px-2 py-1 border border-gray-300 rounded-lg focus:border-blue-500 focus:ring-1 focus:ring-blue-200"
                            placeholder="0"
                          />
                        ) : '-'}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        {component.ncm || '-'}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        {component.nve || '-'}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`inline-flex px-2 py-1 text-xs font-medium rounded-md ${
                          component.environment === 'laboratorio' 
                            ? 'bg-purple-100 text-purple-800' 
                            : 'bg-green-100 text-green-800'
                        }`}>
                          {component.environment === 'laboratorio' ? 'Laboratório' : 'Estoque'}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ${getStockStatusColor(status)}`}>
                          {status === 'critical' && <AlertCircle size={12} />}
                          {status === 'critical' ? 'Crítico' : status === 'low' ? 'Baixo' : 'Normal'}
                        </span>
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

      {/* Modais para novos itens */}
      {/* Modal Novo Grupo */}
      {showNewGroup && (
        <div className="fixed inset-0 bg-black bg-opacity-30 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl shadow-xl w-full max-w-md p-6">
            <h3 className="text-lg font-semibold text-gray-800 mb-4">Novo Grupo</h3>
            <input
              type="text"
              value={newGroupName}
              onChange={(e) => setNewGroupName(e.target.value)}
              placeholder="Nome do grupo"
              className="w-full px-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 mb-4"
              autoFocus
            />
            <div className="flex justify-end gap-3">
              <button
                onClick={() => {
                  setShowNewGroup(false);
                  setNewGroupName('');
                }}
                className="px-4 py-2 text-gray-600 hover:text-gray-800 hover:bg-gray-100 rounded-lg"
              >
                Cancelar
              </button>
              <button
                onClick={handleAddNewGroup}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
              >
                Adicionar
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal Novo Device */}
      {showNewDevice && (
        <div className="fixed inset-0 bg-black bg-opacity-30 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl shadow-xl w-full max-w-md p-6">
            <h3 className="text-lg font-semibold text-gray-800 mb-4">Novo Device</h3>
            <input
              type="text"
              value={newDeviceName}
              onChange={(e) => setNewDeviceName(e.target.value)}
              placeholder="Nome do device"
              className="w-full px-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 mb-4"
              autoFocus
            />
            <div className="flex justify-end gap-3">
              <button
                onClick={() => {
                  setShowNewDevice(false);
                  setNewDeviceName('');
                }}
                className="px-4 py-2 text-gray-600 hover:text-gray-800 hover:bg-gray-100 rounded-lg"
              >
                Cancelar
              </button>
              <button
                onClick={handleAddNewDevice}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
              >
                Adicionar
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal Novo Package */}
      {showNewPackage && (
        <div className="fixed inset-0 bg-black bg-opacity-30 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl shadow-xl w-full max-w-md p-6">
            <h3 className="text-lg font-semibold text-gray-800 mb-4">Novo Package</h3>
            <input
              type="text"
              value={newPackageName}
              onChange={(e) => setNewPackageName(e.target.value)}
              placeholder="Nome do package"
              className="w-full px-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 mb-4"
              autoFocus
            />
            <div className="flex justify-end gap-3">
              <button
                onClick={() => {
                  setShowNewPackage(false);
                  setNewPackageName('');
                }}
                className="px-4 py-2 text-gray-600 hover:text-gray-800 hover:bg-gray-100 rounded-lg"
              >
                Cancelar
              </button>
              <button
                onClick={handleAddNewPackage}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
              >
                Adicionar
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal Novo Value */}
      {showNewValue && (
        <div className="fixed inset-0 bg-black bg-opacity-30 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl shadow-xl w-full max-w-md p-6">
            <h3 className="text-lg font-semibold text-gray-800 mb-4">Novo Value</h3>
            <input
              type="text"
              value={newValueName}
              onChange={(e) => setNewValueName(e.target.value)}
              placeholder="Nome do value"
              className="w-full px-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 mb-4"
              autoFocus
            />
            <div className="flex justify-end gap-3">
              <button
                onClick={() => {
                  setShowNewValue(false);
                  setNewValueName('');
                }}
                className="px-4 py-2 text-gray-600 hover:text-gray-800 hover:bg-gray-100 rounded-lg"
              >
                Cancelar
              </button>
              <button
                onClick={handleAddNewValue}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
              >
                Adicionar
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal de Importação */}
      {showImportModal && (
        <div className="fixed inset-0 bg-black bg-opacity-30 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl shadow-xl w-full max-w-lg p-6">
            <h3 className="text-lg font-semibold text-gray-800 mb-4">Importar Componentes</h3>
            
            <div className="mb-4">
              <p className="text-sm text-gray-600 mb-3">
                Faça upload de um arquivo CSV com os componentes para importar.
              </p>
              
              <button
                onClick={handleDownloadTemplate}
                className="text-blue-600 hover:text-blue-700 text-sm underline mb-4"
              >
                Baixar template de importação
              </button>
              
              <div className="border-2 border-dashed border-gray-300 rounded-lg p-6 text-center">
                <input
                  type="file"
                  accept=".csv"
                  onChange={(e) => setImportFile(e.target.files?.[0] || null)}
                  className="hidden"
                  id="import-file"
                />
                <label
                  htmlFor="import-file"
                  className="cursor-pointer"
                >
                  <Upload className="mx-auto mb-3 text-gray-400" size={40} />
                  <p className="text-sm text-gray-600">
                    {importFile ? importFile.name : 'Clique para selecionar arquivo CSV'}
                  </p>
                </label>
              </div>
            </div>
            
            <div className="flex justify-end gap-3">
              <button
                onClick={() => {
                  setShowImportModal(false);
                  setImportFile(null);
                }}
                className="px-4 py-2 text-gray-600 hover:text-gray-800 hover:bg-gray-100 rounded-lg"
              >
                Cancelar
              </button>
              <button
                onClick={handleImportFile}
                disabled={!importFile || importing}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed flex items-center gap-2"
              >
                {importing && <LoadingSpinner size="sm" />}
                Importar
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ComponentsListPage;