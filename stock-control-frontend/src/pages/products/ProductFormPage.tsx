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
  AlertCircle
} from 'lucide-react';
import productsService from '../../services/products.service';
import componentsService from '../../services/components.service';
import exportService from '../../services/export.service';
import { ProductCreate, Component, ProductComponentCreate } from '../../types';
import { useAuth } from '../../contexts/AuthContext';
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
  const [searchTerm, setSearchTerm] = useState('');
  
  const [availableComponents, setAvailableComponents] = useState<Component[]>([]);
  const [filteredComponents, setFilteredComponents] = useState<Component[]>([]);
  
  // Estados para cálculo de produção
  const [productionQuantity, setProductionQuantity] = useState(1);
  const [productionCalc, setProductionCalc] = useState<ProductionCalculation[]>([]);
  const [unitsToManufacture, setUnitsToManufacture] = useState(1);
  const [showProductionReport, setShowProductionReport] = useState(false);
  
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
    // Filter components based on search
    const filtered = availableComponents.filter(comp =>
      comp.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      comp.group.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (comp.device && comp.device.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (comp.value && comp.value.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (comp.package && comp.package.toLowerCase().includes(searchTerm.toLowerCase()))
    );
    setFilteredComponents(filtered);
  }, [searchTerm, availableComponents]);

  useEffect(() => {
    // Calcular produção sempre que mudar quantidade ou componentes
    calculateProduction();
  }, [productionQuantity, formData.components, availableComponents]);

  const fetchComponents = async () => {
    try {
      const components = await componentsService.getAll();
      setAvailableComponents(components);
      setFilteredComponents(components);
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
        createdBy: product.createdBy || '',
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

 const exportProductionReport = () => {
  try {
    // Usar productionCalc que já está calculado
    const reportData = {
      productName: formData.name,
      unitsToManufacture: productionQuantity, // Usar productionQuantity ao invés de unitsToManufacture
      components: productionCalc.map(calc => ({
        componentName: calc.componentName,
        device: calc.device,
        value: calc.value,
        package: calc.package,
        characteristics: calc.characteristics,
        internalCode: calc.internalCode,
        drawer: calc.drawer,
        division: calc.division,
        quantityPerUnit: calc.quantityPerUnit,
        totalQuantityNeeded: calc.totalRequired,
        quantityInStock: calc.currentStock,
        suggestedPurchase: calc.suggestedPurchase,
        unitPrice: calc.unitPrice,
        totalPrice: calc.totalPrice
      }))
    };

    exportService.exportProductionReport(reportData);
    setSuccess('Relatório exportado com sucesso!');
  } catch (error) {
    setError('Erro ao exportar relatório');
    console.error(error);
  }
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
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Product Info */}
          <div className="lg:col-span-2 space-y-6">
            <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
              <h2 className="text-lg font-semibold text-gray-800 mb-4">Informações do Produto</h2>
              
              <div className="space-y-4">
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
                    Descrição
                  </label>
                  <textarea
                    value={formData.description}
                    onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
                    className="w-full px-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200"
                    placeholder="Descrição detalhada do produto"
                    rows={4}
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Criado por
                  </label>
                  <input
                    type="text"
                    value={formData.createdBy}
                    onChange={(e) => setFormData(prev => ({ ...prev, createdBy: e.target.value }))}
                    className="w-full px-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200"
                    placeholder="Nome do responsável"
                  />
                </div>
              </div>
            </div>

            {/* Selected Components */}
            <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-lg font-semibold text-gray-800">
                  Componentes do Produto ({formData.components.length})
                </h2>
                {formData.components.length > 0 && (
                  <button
                    type="button"
                    onClick={() => setShowProductionReport(!showProductionReport)}
                    className="flex items-center gap-2 px-3 py-1.5 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700"
                  >
                    <Calculator size={16} />
                    Calcular Produção
                  </button>
                )}
              </div>
              
              {formData.components.length === 0 ? (
                <div className="text-center py-8">
                  <Cpu className="mx-auto mb-3 text-gray-400" size={40} />
                  <p className="text-gray-500">Nenhum componente selecionado</p>
                  <p className="text-sm text-gray-400 mt-1">Adicione componentes da lista ao lado</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {formData.components.map((comp) => {
                    const component = getComponent(comp.componentId);
                    if (!component) return null;
                    
                    return (
                      <div
                        key={comp.componentId}
                        className="flex items-center justify-between p-3 bg-gray-50 rounded-lg"
                      >
                        <div className="flex-1">
                          <div className="flex items-center gap-3">
                            <Cpu className="text-gray-400" size={18} />
                            <div>
                              <p className="text-sm font-medium text-gray-900">
                                {component.name}
                              </p>
                              <p className="text-xs text-gray-500">
                                {[component.device, component.value, component.package]
                                  .filter(Boolean)
                                  .join(' • ')}
                              </p>
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center gap-3">
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
                            className="p-1.5 text-red-600 hover:bg-red-50 rounded-lg transition-colors"
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
          </div>

          {/* Components Selection */}
          <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 h-fit">
            <h2 className="text-lg font-semibold text-gray-800 mb-4">Componentes Disponíveis</h2>
            
            {/* Search */}
            <div className="relative mb-4">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" size={18} />
              <input
                type="text"
                placeholder="Buscar componentes..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200"
              />
            </div>

            {/* Components List */}
            <div className="max-h-96 overflow-y-auto border border-gray-200 rounded-lg">
              {filteredComponents.length === 0 ? (
                <p className="p-4 text-center text-gray-500">Nenhum componente encontrado</p>
              ) : (
                filteredComponents.map((component) => (
                  <button
                    key={component.id}
                    type="button"
                    onClick={() => addComponent(component)}
                    className="w-full p-3 border-b border-gray-100 hover:bg-gray-50 transition-colors text-left"
                  >
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium text-gray-900">{component.name}</p>
                        <p className="text-xs text-gray-500">
                          {component.group} • Estoque: {component.quantityInStock}
                        </p>
                      </div>
                      <Plus size={18} className="text-gray-400" />
                    </div>
                  </button>
                ))
              )}
            </div>
          </div>
        </div>

        {/* Production Report */}
        {showProductionReport && productionCalc.length > 0 && (
          <div className="mt-6 bg-white rounded-xl shadow-sm border border-gray-200 p-6">
            <div className="flex items-center justify-between mb-6">
              <div>
                <h2 className="text-lg font-semibold text-gray-800">Relatório de Produção</h2>
                <p className="text-sm text-gray-500">Análise de componentes necessários</p>
              </div>
              <div className="flex items-center gap-4">
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
                <button
                  type="button"
                  onClick={exportProductionReport}
                  className="flex items-center gap-2 px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700"
                >
                  <FileSpreadsheet size={18} />
                  Exportar Excel
                </button>
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
                        {calc.suggestedPurchase > 0 ? (
                          <span className="flex items-center justify-end gap-1">
                            <AlertCircle size={14} />
                            {calc.suggestedPurchase}
                          </span>
                        ) : (
                          'OK'
                        )}
                      </td>
                      <td className="px-4 py-3 text-sm text-right">
                        R$ {calc.unitPrice.toFixed(2)}
                      </td>
                      <td className="px-4 py-3 text-sm text-right font-medium">
                        R$ {calc.totalPrice.toFixed(2)}
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
                      R$ {getTotalCost().toFixed(2)}
                    </td>
                  </tr>
                </tfoot>
              </table>
            </div>
          </div>
        )}

        {/* Actions */}
        <div className="flex justify-end gap-3 mt-6">
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
    </div>
  );
};

export default ProductFormPage;