import React, { useEffect, useState } from 'react';
import { useNavigate, useParams, useLocation } from 'react-router-dom';
import { 
  ArrowLeft, 
  Save, 
  Package, 
  Plus, 
  Trash2, 
  Search, 
  Cpu,
  Calculator,
  FileSpreadsheet,
  AlertCircle,
  X,
  GripVertical,
  Check,
  Filter,
  User,
  Calendar,
  Info,
  MapPin
} from 'lucide-react';
import productsService from '../../services/products.service';
import componentsService from '../../services/components.service';
import exportService from '../../services/export.service';
import { ProductCreate, Component, ProductComponentCreate, ComponentFilter } from '../../types';
import { useAuth } from '../../contexts/AuthContext';
import { COMPONENT_GROUPS } from '../../utils/constants';
import { formatCurrency } from '../../utils/helpers';
import LoadingSpinner from '../../components/common/LoadingSpinner';
import ErrorMessage from '../../components/common/ErrorMessage';
import SuccessMessage from '../../components/common/SuccessMessage';

interface ProductionCalculation {
  componentId: number;
  componentName: string;
  device?: string;
  value?: string;
  package?: string;
  characteristics?: string;
  internalCode?: string;
  drawer?: string;
  division?: string;
  quantityPerUnit: number;
  totalRequired: number;
  currentStock: number;
  suggestedPurchase: number;
  unitPrice: number;
  totalPrice: number;
}

// Modal de Exportação (mantido igual)
const ExportModal: React.FC<{
  isOpen: boolean;
  onClose: () => void;
  product: { name: string; components: ProductComponentCreate[] };
  components: Component[];
  productOrder: number[];
  onUpdateOrder: (order: number[]) => void;
  onConfirmExport: () => void;
}> = ({ isOpen, onClose, product, components, productOrder, onUpdateOrder, onConfirmExport }) => {
  const [localOrder, setLocalOrder] = useState<number[]>(productOrder);
  const [isDragging, setIsDragging] = useState<number | null>(null);
  const [orderInputs, setOrderInputs] = useState<{ [key: number]: number }>({});

  useEffect(() => {
    setLocalOrder(productOrder);
    const initialInputs: { [key: number]: number } = {};
    productOrder.forEach((compId, index) => {
      initialInputs[compId] = index + 1;
    });
    setOrderInputs(initialInputs);
  }, [productOrder]);

  if (!isOpen) return null;

  const handleDragStart = (index: number) => {
    setIsDragging(index);
  };

  const handleDragOver = (e: React.DragEvent, index: number) => {
    e.preventDefault();
    if (isDragging === null || isDragging === index) return;

    const newOrder = [...localOrder];
    const draggedItem = newOrder[isDragging];
    newOrder.splice(isDragging, 1);
    newOrder.splice(index, 0, draggedItem);

    setLocalOrder(newOrder);
    setIsDragging(index);
    
    updateOrderInputsFromArray(newOrder);
  };

  const handleDragEnd = () => {
    setIsDragging(null);
    onUpdateOrder(localOrder);
  };

  const updateOrderInputsFromArray = (orderArray: number[]) => {
    const newInputs: { [key: number]: number } = {};
    orderArray.forEach((compId, index) => {
      newInputs[compId] = index + 1;
    });
    setOrderInputs(newInputs);
  };

  const handleOrderInputChange = (componentId: number, value: string) => {
    const numValue = parseInt(value) || 1;
    setOrderInputs(prev => ({
      ...prev,
      [componentId]: numValue
    }));
  };

  const handleSortByInputs = () => {
    const componentsWithOrder = localOrder.map(compId => ({
      componentId: compId,
      order: orderInputs[compId] || 999
    }));

    componentsWithOrder.sort((a, b) => a.order - b.order);

    const newOrder = componentsWithOrder.map(item => item.componentId);
    
    setLocalOrder(newOrder);
    onUpdateOrder(newOrder);
    
    updateOrderInputsFromArray(newOrder);
  };

  const getComponentDetails = (componentId: number) => {
    return components.find(c => c.id === componentId);
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-30 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-xl shadow-xl w-full max-w-6xl max-h-[90vh] overflow-hidden flex flex-col">
        <div className="p-6 border-b border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-xl font-bold text-gray-800">{product.name}</h2>
              <p className="text-sm text-gray-500">Defina a ordem dos componentes para exportação</p>
            </div>
            <button onClick={onClose} className="text-gray-400 hover:text-gray-600">
              <X size={24} />
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto p-6">
          <div className="mb-4 flex justify-end">
            <button
              onClick={handleSortByInputs}
              className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16V4m0 0L3 8m4-4l4 4m6 0v12m0 0l4-4m-4 4l-4-4" />
              </svg>
              Ordenar
            </button>
          </div>

          <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
            <table className="min-w-full">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Ordem</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Qtd</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Qtd. Total</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Device</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Value</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Package</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Característica</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Cód.</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Gaveta</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Divisão</th>
                  <th className="px-4 py-3 text-center text-xs font-medium text-gray-500 uppercase">Qtd. Estoque</th>
                  <th className="px-4 py-3 text-center text-xs font-medium text-gray-500 uppercase">Qtd. Compra</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200">
                {localOrder.map((compId, index) => {
                  const pc = product.components.find(c => c.componentId === compId);
                  if (!pc) return null;
                  
                  const component = getComponentDetails(pc.componentId);
                  if (!component) return null;

                  const needToBuy = Math.max(0, pc.quantity - component.quantityInStock);

                  return (
                    <tr
                      key={compId}
                      draggable
                      onDragStart={() => handleDragStart(index)}
                      onDragOver={(e) => handleDragOver(e, index)}
                      onDragEnd={handleDragEnd}
                      className={`cursor-move hover:bg-gray-50 ${isDragging === index ? 'opacity-50' : ''}`}
                    >
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <GripVertical size={16} className="text-gray-400" />
                          <input
                            type="number"
                            value={orderInputs[compId] || ''}
                            onChange={(e) => handleOrderInputChange(compId, e.target.value)}
                            className="w-16 px-2 py-1 text-center border border-gray-300 rounded focus:border-blue-500 focus:ring-1 focus:ring-blue-200"
                            min="1"
                            onClick={(e) => e.stopPropagation()}
                            onMouseDown={(e) => e.stopPropagation()}
                          />
                        </div>
                      </td>
                      <td className="px-4 py-3 text-sm">{pc.quantity}</td>
                      <td className="px-4 py-3 text-sm">{pc.quantity}</td>
                      <td className="px-4 py-3 text-sm">{component.device || '-'}</td>
                      <td className="px-4 py-3 text-sm">{component.value || '-'}</td>
                      <td className="px-4 py-3 text-sm">{component.package || '-'}</td>
                      <td className="px-4 py-3 text-sm">{component.characteristics || '-'}</td>
                      <td className="px-4 py-3 text-sm">{component.internalCode || '-'}</td>
                      <td className="px-4 py-3 text-sm">{component.drawer || '-'}</td>
                      <td className="px-4 py-3 text-sm">{component.division || '-'}</td>
                      <td className="px-4 py-3 text-sm text-center">{component.quantityInStock}</td>
                      <td className={`px-4 py-3 text-sm text-center font-medium ${needToBuy > 0 ? 'text-red-600' : 'text-green-600'}`}>
                        {needToBuy || '0'}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          <div className="mt-4 p-4 bg-blue-50 rounded-lg">
            <p className="text-sm text-blue-700">
              <strong>Dica:</strong> Você pode ordenar os componentes de duas formas:
            </p>
            <ul className="text-sm text-blue-600 mt-2 space-y-1">
              <li>• <strong>Arrastar e soltar:</strong> Clique e arraste as linhas para reordenar</li>
              <li>• <strong>Digitar números:</strong> Digite a ordem desejada nos campos e clique em "Ordenar"</li>
            </ul>
          </div>
        </div>

        <div className="p-6 border-t border-gray-200 flex justify-end gap-3">
          <button
            onClick={onClose}
            className="px-4 py-2 text-gray-600 hover:text-gray-800 hover:bg-gray-100 rounded-lg"
          >
            Cancelar
          </button>
          <button
            onClick={onConfirmExport}
            className="flex items-center gap-2 px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700"
          >
            <Check size={18} />
            Confirmar e Exportar
          </button>
        </div>
      </div>
    </div>
  );
};

const ProductFormPage: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { id } = useParams();
  const { user } = useAuth();
  const isEditing = !!id;

  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  
  const [availableComponents, setAvailableComponents] = useState<Component[]>([]);
  const [filteredComponents, setFilteredComponents] = useState<Component[]>([]);
  
  // Estados para filtros
  const [searchTerm, setSearchTerm] = useState('');
  const [groups, setGroups] = useState<string[]>(COMPONENT_GROUPS);
  const [devices, setDevices] = useState<string[]>([]);
  const [packages, setPackages] = useState<string[]>([]);
  const [values, setValues] = useState<string[]>([]);
  
  const [filters, setFilters] = useState<ComponentFilter>({
    name: '',
    group: '',
    device: '',
    package: '',
    value: '',
    searchTerm: '',
    pageNumber: 1,
    pageSize: 1000
  });
  
  // Estados para cálculo de produção
  const [productionQuantity, setProductionQuantity] = useState(1);
  const [productionCalc, setProductionCalc] = useState<ProductionCalculation[]>([]);
  const [showProductionReport, setShowProductionReport] = useState(false);
  
  // Estados para o modal de exportação
  const [exportModalOpen, setExportModalOpen] = useState(false);
  const [componentOrder, setComponentOrder] = useState<number[]>([]);
  
  const [formData, setFormData] = useState<ProductCreate>({
    name: '',
    description: '',
    createdBy: user?.name || '',
    components: []
  });

  useEffect(() => {
    fetchComponents();
    
    // Verificar se vieram componentes pré-selecionados
    const state = location.state as { selectedComponents?: Component[] };
    if (state?.selectedComponents) {
      const preSelected = state.selectedComponents.map(comp => ({
        componentId: comp.id,
        quantity: 1
      }));
      setFormData(prev => ({ ...prev, components: preSelected }));
    }
    
    if (isEditing && id) {
      fetchProduct(Number(id));
    }
  }, [id, isEditing, location.state]);

  useEffect(() => {
    // Filtrar componentes baseado em todos os filtros
    let filtered = availableComponents;

    // Filtro por grupo
    if (filters.group) {
      filtered = filtered.filter(comp => comp.group === filters.group);
    }

    // Filtro por device
    if (filters.device) {
      filtered = filtered.filter(comp => comp.device === filters.device);
    }

    // Filtro por package
    if (filters.package) {
      filtered = filtered.filter(comp => comp.package === filters.package);
    }

    // Filtro por value
    if (filters.value) {
      filtered = filtered.filter(comp => comp.value === filters.value);
    }

    // Filtro por busca
    if (searchTerm) {
      filtered = filtered.filter(comp =>
        comp.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        (comp.internalCode && comp.internalCode.toLowerCase().includes(searchTerm.toLowerCase())) ||
        (comp.characteristics && comp.characteristics.toLowerCase().includes(searchTerm.toLowerCase())) ||
        (comp.drawer && comp.drawer.toLowerCase().includes(searchTerm.toLowerCase())) ||
        (comp.division && comp.division.toLowerCase().includes(searchTerm.toLowerCase()))
      );
    }

    setFilteredComponents(filtered);
  }, [searchTerm, filters, availableComponents]);

  useEffect(() => {
    // Calcular produção sempre que mudar quantidade ou componentes
    calculateProduction();
  }, [productionQuantity, formData.components, availableComponents]);

  const fetchComponents = async () => {
    try {
      const components = await componentsService.getAll();
      setAvailableComponents(components);
      setFilteredComponents(components);
      
      // Extrair valores únicos para os dropdowns
      const uniqueGroups = Array.from(new Set(components.map(c => c.group).filter(Boolean)));
      const uniqueDevices = Array.from(new Set(components.map(c => c.device).filter(Boolean)));
      const uniquePackages = Array.from(new Set(components.map(c => c.package).filter(Boolean)));
      const uniqueValues = Array.from(new Set(components.map(c => c.value).filter(Boolean)));

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
      console.error('Error fetching components:', error);
    }
  };

  const fetchProduct = async (productId: number) => {
    try {
      setLoading(true);
      const product = await productsService.getById(productId);
      setFormData({
        name: product.name,
        description: product.description || '',
        createdBy: product.createdBy || user?.name || '',
        components: product.components.map(c => ({
          componentId: c.componentId,
          quantity: c.quantity
        }))
      });
    } catch (error) {
      setError('Erro ao carregar produto');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    
    // Validations
    if (!formData.name) {
      setError('Nome é obrigatório');
      return;
    }
    
    if (formData.components.length === 0) {
      setError('Adicione pelo menos um componente ao produto');
      return;
    }

    try {
      setSaving(true);
      
      if (isEditing && id) {
        await productsService.update(Number(id), formData);
      } else {
        await productsService.create(formData);
      }
      
      setSuccess('Produto salvo com sucesso!');
      setTimeout(() => navigate('/products'), 1500);
    } catch (error) {
      setError('Erro ao salvar produto');
      console.error(error);
    } finally {
      setSaving(false);
    }
  };

  const addComponent = (component: Component) => {
    const existing = formData.components.find(c => c.componentId === component.id);
    if (existing) {
      setError('Componente já adicionado ao produto');
      return;
    }
    
    setFormData(prev => ({
      ...prev,
      components: [...prev.components, { componentId: component.id, quantity: 1 }]
    }));
    setError('');
  };

  const removeComponent = (componentId: number) => {
    setFormData(prev => ({
      ...prev,
      components: prev.components.filter(c => c.componentId !== componentId)
    }));
  };

  const updateComponentQuantity = (componentId: number, quantity: number) => {
    if (quantity <= 0) return;
    
    setFormData(prev => ({
      ...prev,
      components: prev.components.map(c =>
        c.componentId === componentId ? { ...c, quantity } : c
      )
    }));
  };

  const getComponent = (componentId: number): Component | undefined => {
    return availableComponents.find(c => c.id === componentId);
  };

  const calculateProduction = () => {
    const calculations: ProductionCalculation[] = formData.components.map(comp => {
      const component = getComponent(comp.componentId);
      if (!component) return null;

      const totalRequired = comp.quantity * productionQuantity;
      const suggestedPurchase = Math.max(0, totalRequired - component.quantityInStock);
      const totalPrice = (component.price || 0) * totalRequired;

      return {
        componentId: component.id,
        componentName: component.name,
        device: component.device,
        value: component.value,
        package: component.package,
        characteristics: component.characteristics,
        internalCode: component.internalCode,
        drawer: component.drawer,
        division: component.division,
        quantityPerUnit: comp.quantity,
        totalRequired,
        currentStock: component.quantityInStock,
        suggestedPurchase,
        unitPrice: component.price || 0,
        totalPrice
      };
    }).filter(Boolean) as ProductionCalculation[];

    setProductionCalc(calculations);
  };

  const getTotalCost = () => {
    return productionCalc.reduce((sum, calc) => sum + calc.totalPrice, 0);
  };

  const handleExportClick = () => {
    if (formData.components.length === 0) {
      setError('Adicione ao menos um componente antes de exportar');
      return;
    }
    
    setComponentOrder(formData.components.map(c => c.componentId));
    setExportModalOpen(true);
  };

  const handleConfirmExport = () => {
    const orderedComponents = componentOrder.map(compId => {
      const pc = formData.components.find(c => c.componentId === compId);
      const component = availableComponents.find(c => c.id === compId);
      
      if (!pc || !component) return null;

      return {
        componentName: component.name,
        device: component.device,
        value: component.value,
        package: component.package,
        characteristics: component.characteristics,
        internalCode: component.internalCode,
        drawer: component.drawer,
        division: component.division,
        quantityPerUnit: pc.quantity,
        totalQuantityNeeded: pc.quantity * productionQuantity,
        quantityInStock: component.quantityInStock,
        suggestedPurchase: Math.max(0, (pc.quantity * productionQuantity) - component.quantityInStock),
        unitPrice: component.price,
        totalPrice: (component.price || 0) * pc.quantity * productionQuantity
      };
    }).filter(Boolean);

    const exportData = {
      productName: formData.name || 'Novo Produto',
      unitsToManufacture: productionQuantity,
      components: orderedComponents as any[]
    };

    exportService.exportProductionReport(exportData);
    setSuccess('Relatório exportado com sucesso!');
    setExportModalOpen(false);
  };

  const clearFilters = () => {
    setFilters({
      name: '',
      group: '',
      device: '',
      package: '',
      value: '',
      searchTerm: '',
      pageNumber: 1,
      pageSize: 1000
    });
    setSearchTerm('');
  };

  if (loading) {
    return (
      <div className="p-6">
        <LoadingSpinner fullScreen message="Carregando produto..." />
      </div>
    );
  }

  return (
    <div className="p-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <button
              onClick={() => navigate('/products')}
              className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
            >
              <ArrowLeft size={20} />
            </button>
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-gradient-to-br from-green-500 to-green-600 rounded-xl flex items-center justify-center shadow-lg">
                <Package className="text-white" size={20} />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-gray-800">
                  {isEditing ? 'Editar Produto' : 'Novo Produto'}
                </h1>
                <p className="text-sm text-gray-500">
                  {isEditing ? 'Atualize as informações do produto' : 'Crie um novo produto com componentes'}
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {error && <ErrorMessage message={error} onClose={() => setError('')} className="mb-6" />}
      {success && <SuccessMessage message={success} onClose={() => setSuccess('')} className="mb-6" />}

      <form onSubmit={handleSubmit}>
        {/* Informações do Produto */}
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
          <h2 className="text-lg font-semibold text-gray-800 mb-4 flex items-center gap-2">
            <Info size={20} />
            Informações do Produto
          </h2>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Nome do Produto *
              </label>
              <input
                type="text"
                value={formData.name}
                onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
                className="w-full px-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200"
                placeholder="Ex: Placa Controladora v2.0"
                required
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Criado por
              </label>
              <div className="relative">
                <User className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" size={18} />
                <input
                  type="text"
                  value={formData.createdBy}
                  readOnly
                  className="w-full pl-10 pr-4 py-2.5 rounded-lg border border-gray-300 bg-gray-50 text-gray-600 cursor-not-allowed"
                />
              </div>
            </div>

            <div className="md:col-span-2">
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Descrição
              </label>
              <textarea
                value={formData.description}
                onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
                className="w-full px-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200"
                placeholder="Descrição detalhada do produto"
                rows={3}
              />
            </div>
          </div>
        </div>

        {/* Seleção de Componentes */}
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
          <h2 className="text-lg font-semibold text-gray-800 mb-4 flex items-center gap-2">
            <Search size={20} />
            Adicionar Componentes
          </h2>

          {/* Filtros */}
          <div className="mb-6">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-3">
                <Filter size={20} className="text-gray-500" />
                <h3 className="text-base font-medium text-gray-700">Filtros de Busca</h3>
              </div>
              <button
                type="button"
                onClick={clearFilters}
                className="text-sm text-blue-600 hover:text-blue-700"
              >
                Limpar filtros
              </button>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
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
                  placeholder="Buscar componentes..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full pl-10 pr-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200"
                />
              </div>
            </div>
          </div>

          {/* Lista de Componentes Disponíveis */}
          <div className="border border-gray-200 rounded-lg overflow-hidden">
            <div className="bg-gray-50 px-4 py-2 border-b border-gray-200">
              <p className="text-sm text-gray-600">
                {filteredComponents.length} componentes encontrados
              </p>
            </div>
            <div className="max-h-96 overflow-y-auto">
              {filteredComponents.length === 0 ? (
                <p className="p-6 text-center text-gray-500">Nenhum componente encontrado com os filtros aplicados</p>
              ) : (
                <div className="divide-y divide-gray-100">
                  {filteredComponents.map((component) => {
                    const isAdded = formData.components.some(c => c.componentId === component.id);
                    
                    return (
                      <div
                        key={component.id}
                        className={`p-4 hover:bg-gray-50 transition-colors ${isAdded ? 'bg-green-50' : ''}`}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex-1">
                            <div className="flex items-center gap-3">
                              <Cpu className="text-gray-400 flex-shrink-0" size={20} />
                              <div className="flex-1">
                                <p className="text-sm font-medium text-gray-900">
                                  {component.name}
                                  {component.internalCode && (
                                    <span className="text-gray-500 ml-2">({component.internalCode})</span>
                                  )}
                                </p>
                                <div className="flex flex-wrap gap-2 mt-1">
                                  <span className="text-xs px-2 py-1 bg-gray-100 text-gray-600 rounded">
                                    {component.group}
                                  </span>
                                  {component.device && (
                                    <span className="text-xs px-2 py-1 bg-blue-100 text-blue-600 rounded">
                                      {component.device}
                                    </span>
                                  )}
                                  {component.value && (
                                    <span className="text-xs px-2 py-1 bg-purple-100 text-purple-600 rounded">
                                      {component.value}
                                    </span>
                                  )}
                                  {component.package && (
                                    <span className="text-xs px-2 py-1 bg-orange-100 text-orange-600 rounded">
                                      {component.package}
                                    </span>
                                  )}
                                  <span className={`text-xs px-2 py-1 rounded flex items-center gap-1 ${
                                    component.quantityInStock <= component.minimumQuantity
                                      ? 'bg-red-100 text-red-600'
                                      : 'bg-green-100 text-green-600'
                                  }`}>
                                    <Package size={12} />
                                    Estoque: {component.quantityInStock}
                                  </span>
                                  {component.drawer && component.division && (
                                    <span className="text-xs px-2 py-1 bg-gray-100 text-gray-600 rounded flex items-center gap-1">
                                      <MapPin size={12} />
                                      {component.drawer}/{component.division}
                                    </span>
                                  )}
                                </div>
                                {component.characteristics && (
                                  <p className="text-xs text-gray-500 mt-1">{component.characteristics}</p>
                                )}
                              </div>
                            </div>
                          </div>
                          <button
                            type="button"
                            onClick={() => addComponent(component)}
                            disabled={isAdded}
                            className={`ml-4 px-3 py-1.5 rounded-lg transition-all duration-200 flex items-center gap-2 ${
                              isAdded
                                ? 'bg-green-600 text-white cursor-not-allowed'
                                : 'bg-blue-600 text-white hover:bg-blue-700'
                            }`}
                          >
                            {isAdded ? (
                              <>
                                <Check size={16} />
                                Adicionado
                              </>
                            ) : (
                              <>
                                <Plus size={16} />
                                Adicionar
                              </>
                            )}
                          </button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Componentes Selecionados */}
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-gray-800 flex items-center gap-2">
              <Cpu size={20} />
              Componentes do Produto ({formData.components.length})
            </h2>
            {formData.components.length > 0 && (
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setShowProductionReport(!showProductionReport)}
                  className="flex items-center gap-2 px-3 py-1.5 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700"
                >
                  <Calculator size={16} />
                  {showProductionReport ? 'Ocultar' : 'Mostrar'} Cálculo
                </button>
                <button
                  type="button"
                  onClick={handleExportClick}
                  className="flex items-center gap-2 px-3 py-1.5 text-sm bg-purple-600 text-white rounded-lg hover:bg-purple-700"
                >
                  <FileSpreadsheet size={16} />
                  Exportar Excel
                </button>
              </div>
            )}
          </div>
          
          {formData.components.length === 0 ? (
            <div className="text-center py-12">
              <Package className="mx-auto mb-3 text-gray-400" size={48} />
              <p className="text-gray-500">Nenhum componente selecionado</p>
              <p className="text-sm text-gray-400 mt-1">Adicione componentes usando os filtros acima</p>
            </div>
          ) : (
            <div className="space-y-3">
              {formData.components.map((comp) => {
                const component = getComponent(comp.componentId);
                if (!component) return null;
                
                return (
                  <div
                    key={comp.componentId}
                    className="flex items-center justify-between p-4 bg-gray-50 rounded-lg border border-gray-200"
                  >
                    <div className="flex-1">
                      <div className="flex items-start gap-3">
                        <Cpu className="text-gray-400 mt-1 flex-shrink-0" size={20} />
                        <div className="flex-1">
                          <p className="font-medium text-gray-900">
                            {component.name}
                            {component.internalCode && (
                              <span className="text-gray-500 ml-2">({component.internalCode})</span>
                            )}
                          </p>
                          <div className="flex flex-wrap gap-2 mt-1">
                            <span className="text-xs px-2 py-1 bg-gray-100 text-gray-600 rounded">
                              {component.group}
                            </span>
                            {component.device && (
                              <span className="text-xs px-2 py-1 bg-blue-100 text-blue-600 rounded">
                                Device: {component.device}
                              </span>
                            )}
                            {component.value && (
                              <span className="text-xs px-2 py-1 bg-purple-100 text-purple-600 rounded">
                                Value: {component.value}
                              </span>
                            )}
                            {component.package && (
                              <span className="text-xs px-2 py-1 bg-orange-100 text-orange-600 rounded">
                                Package: {component.package}
                              </span>
                            )}
                            {component.drawer && component.division && (
                              <span className="text-xs px-2 py-1 bg-gray-100 text-gray-600 rounded flex items-center gap-1">
                                <MapPin size={12} />
                                {component.drawer}/{component.division}
                              </span>
                            )}
                          </div>
                          <div className="flex items-center gap-4 mt-2 text-xs text-gray-500">
                            <span>Estoque atual: {component.quantityInStock}</span>
                            <span>Mínimo: {component.minimumQuantity}</span>
                            {component.price && <span>Preço: {formatCurrency(component.price)}</span>}
                          </div>
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-3 ml-4">
                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          onClick={() => updateComponentQuantity(comp.componentId, comp.quantity - 1)}
                          className="w-8 h-8 rounded-lg border border-gray-300 hover:bg-gray-100 flex items-center justify-center"
                        >
                          -
                        </button>
                        <input
                          type="number"
                          value={comp.quantity}
                          onChange={(e) => updateComponentQuantity(comp.componentId, Number(e.target.value))}
                          className="w-16 text-center px-2 py-1 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200"
                          min="1"
                        />
                        <button
                          type="button"
                          onClick={() => updateComponentQuantity(comp.componentId, comp.quantity + 1)}
                          className="w-8 h-8 rounded-lg border border-gray-300 hover:bg-gray-100 flex items-center justify-center"
                        >
                          +
                        </button>
                      </div>
                      <button
                        type="button"
                        onClick={() => removeComponent(comp.componentId)}
                        className="p-2 text-red-600 hover:bg-red-50 rounded-lg transition-colors"
                      >
                        <Trash2 size={18} />
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Production Report */}
        {showProductionReport && productionCalc.length > 0 && (
          <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
            <div className="flex items-center justify-between mb-6">
              <div>
                <h2 className="text-lg font-semibold text-gray-800">Relatório de Produção</h2>
                <p className="text-sm text-gray-500">Análise de componentes necessários</p>
              </div>
              <div className="flex items-center gap-2">
                <label className="text-sm font-medium text-gray-700">
                  Quantidade a produzir:
                </label>
                <input
                  type="number"
                  value={productionQuantity}
                  onChange={(e) => setProductionQuantity(Math.max(1, Number(e.target.value)))}
                  className="w-20 px-3 py-1.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200"
                  min="1"
                />
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="min-w-full">
                <thead className="bg-gray-50 border-b border-gray-200">
                  <tr>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Componente</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Device/Value</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Cód. Interno</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Localização</th>
                    <th className="px-4 py-3 text-right text-xs font-medium text-gray-500 uppercase">Qtd/Un</th>
                    <th className="px-4 py-3 text-right text-xs font-medium text-gray-500 uppercase">Total</th>
                    <th className="px-4 py-3 text-right text-xs font-medium text-gray-500 uppercase">Estoque</th>
                    <th className="px-4 py-3 text-right text-xs font-medium text-gray-500 uppercase">Comprar</th>
                    <th className="px-4 py-3 text-right text-xs font-medium text-gray-500 uppercase">Preço Unit.</th>
                    <th className="px-4 py-3 text-right text-xs font-medium text-gray-500 uppercase">Total</th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {productionCalc.map((calc) => (
                    <tr key={calc.componentId}>
                      <td className="px-4 py-3 text-sm font-medium text-gray-900">
                        {calc.componentName}
                      </td>
                      <td className="px-4 py-3 text-sm text-gray-600">
                        {[calc.device, calc.value].filter(Boolean).join(' / ') || '-'}
                      </td>
                      <td className="px-4 py-3 text-sm text-gray-600">
                        {calc.internalCode || '-'}
                      </td>
                      <td className="px-4 py-3 text-sm text-gray-600">
                        {calc.drawer && calc.division ? `${calc.drawer}/${calc.division}` : '-'}
                      </td>
                      <td className="px-4 py-3 text-sm text-right">{calc.quantityPerUnit}</td>
                      <td className="px-4 py-3 text-sm text-right font-medium">{calc.totalRequired}</td>
                      <td className="px-4 py-3 text-sm text-right">{calc.currentStock}</td>
                      <td className={`px-4 py-3 text-sm text-right font-medium ${
                        calc.suggestedPurchase > 0 ? 'text-red-600' : 'text-green-600'
                      }`}>
                        {calc.suggestedPurchase > 0 ? calc.suggestedPurchase : 'OK'}
                      </td>
                      <td className="px-4 py-3 text-sm text-right">
                        {formatCurrency(calc.unitPrice)}
                      </td>
                      <td className="px-4 py-3 text-sm text-right font-medium">
                        {formatCurrency(calc.totalPrice)}
                      </td>
                    </tr>
                  ))}
                </tbody>
                <tfoot className="bg-gray-50">
                  <tr>
                    <td colSpan={9} className="px-4 py-3 text-sm font-medium text-right">
                      Total Geral:
                    </td>
                    <td className="px-4 py-3 text-sm font-bold text-right">
                      {formatCurrency(getTotalCost())}
                    </td>
                  </tr>
                </tfoot>
              </table>
            </div>
          </div>
        )}

        {/* Actions */}
        <div className="flex justify-end gap-3">
          <button
            type="button"
            onClick={() => navigate('/products')}
            className="px-4 py-2 text-gray-600 hover:text-gray-800 hover:bg-gray-100 rounded-lg transition-all duration-200"
          >
            Cancelar
          </button>
          <button
            type="submit"
            disabled={saving}
            className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-green-500 to-green-600 text-white rounded-lg hover:from-green-600 hover:to-green-700 disabled:from-gray-300 disabled:to-gray-400 disabled:cursor-not-allowed transition-all duration-200"
          >
            {saving ? (
              <>
                <LoadingSpinner size="sm" />
                Salvando...
              </>
            ) : (
              <>
                <Save size={18} />
                {isEditing ? 'Atualizar' : 'Criar'} Produto
              </>
            )}
          </button>
        </div>
      </form>

      {/* Export Modal */}
      <ExportModal
        isOpen={exportModalOpen}
        onClose={() => setExportModalOpen(false)}
        product={{ name: formData.name, components: formData.components }}
        components={availableComponents}
        productOrder={componentOrder}
        onUpdateOrder={setComponentOrder}
        onConfirmExport={handleConfirmExport}
      />
    </div>
  );
};

export default ProductFormPage;