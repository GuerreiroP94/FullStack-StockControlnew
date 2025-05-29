import React, { useEffect, useState } from 'react';
import { useNavigate, useParams, useLocation } from 'react-router-dom';
import { ArrowLeft, Save, Package, Plus, Trash2, Search, Cpu, Calculator, FileSpreadsheet } from 'lucide-react';
import productsService from '../../services/products.service';
import componentsService from '../../services/components.service';
import exportService from '../../services/export.service';
import { ProductCreate, Component, ProductComponentCreate } from '../../types';
import { useAuth } from '../../contexts/AuthContext';
import LoadingSpinner from '../../components/common/LoadingSpinner';
import ErrorMessage from '../../components/common/ErrorMessage';
import SuccessMessage from '../../components/common/SuccessMessage';

const ProductFormPage: React.FC = () => {
  const navigate = useNavigate();
  const { id } = useParams();
  const location = useLocation();
  const { user } = useAuth();
  const isEditing = !!id;

  // Componentes pré-selecionados vindos da tela de componentes
  const preSelectedComponents = location.state?.selectedComponents || [];

  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [showCalculator, setShowCalculator] = useState(false);
  const [unitsToManufacture, setUnitsToManufacture] = useState(1);
  
  const [availableComponents, setAvailableComponents] = useState<Component[]>([]);
  const [filteredComponents, setFilteredComponents] = useState<Component[]>([]);
  
  const [formData, setFormData] = useState<ProductCreate>({
    name: '',
    description: '',
    createdBy: user?.name || '',
    components: []
  });

  useEffect(() => {
    fetchComponents();
    if (isEditing && id) {
      fetchProduct(Number(id));
    } else if (preSelectedComponents.length > 0) {
      // Se tem componentes pré-selecionados, adiciona automaticamente
      const componentsToAdd = preSelectedComponents.map((comp: Component) => ({
  componentId: comp.id,
  quantity: 1
}));
      setFormData(prev => ({
        ...prev,
        components: componentsToAdd
      }));
    }
  }, [id, isEditing]);

  useEffect(() => {
    // Filter components based on search
    const filtered = availableComponents.filter(comp =>
      comp.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      comp.group.toLowerCase().includes(searchTerm.toLowerCase()) ||
      comp.device?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      comp.value?.toLowerCase().includes(searchTerm.toLowerCase())
    );
    setFilteredComponents(filtered);
  }, [searchTerm, availableComponents]);

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
        setSuccess('Produto atualizado com sucesso!');
      } else {
        await productsService.create(formData);
        setSuccess('Produto criado com sucesso!');
      }
      
      setTimeout(() => {
        navigate('/products');
      }, 1500);
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

  const getComponentDetails = (componentId: number) => {
    return availableComponents.find(c => c.id === componentId);
  };

  const calculateProductionReport = () => {
    const report = formData.components.map(comp => {
      const component = getComponentDetails(comp.componentId);
      if (!component) return null;

      const totalQuantity = comp.quantity * unitsToManufacture;
      const suggestedPurchase = Math.max(0, totalQuantity - component.quantityInStock);

      return {
        ...component,
        quantityPerUnit: comp.quantity,
        totalQuantityNeeded: totalQuantity,
        suggestedPurchase,
        totalPrice: (component.price || 0) * suggestedPurchase
      };
    }).filter(Boolean);

    return report;
  };

  const exportProductionReport = async () => {
    try {
      const report = calculateProductionReport();
      const reportData = {
        productName: formData.name,
        unitsToManufacture,
        components: report
      };

      await exportService.exportProductionReport(reportData);
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
    <div className="p-6 max-w-6xl mx-auto">
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

          {/* Botão Calculadora */}
          {formData.components.length > 0 && (
            <button
              type="button"
              onClick={() => setShowCalculator(!showCalculator)}
              className="flex items-center gap-2 px-4 py-2 bg-blue-100 text-blue-700 rounded-lg hover:bg-blue-200 transition-colors"
            >
              <Calculator size={18} />
              Calcular Produção
            </button>
          )}
        </div>
      </div>

      {error && <ErrorMessage message={error} onClose={() => setError('')} className="mb-6" />}
      {success && <SuccessMessage message={success} onClose={() => setSuccess('')} className="mb-6" />}

      {/* Calculadora de Produção */}
      {showCalculator && (
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
          <h2 className="text-lg font-semibold text-gray-800 mb-4">Calculadora de Produção</h2>
          
          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Quantidade de unidades a fabricar
            </label>
            <input
              type="number"
              value={unitsToManufacture}
              onChange={(e) => setUnitsToManufacture(Number(e.target.value))}
              className="w-32 px-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200"
              min="1"
            />
          </div>

          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Componente</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Qtd/Unidade</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Total Necessário</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Em Estoque</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Comprar</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Preço Total</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {calculateProductionReport().map((item: any) => (
                  <tr key={item.id}>
                    <td className="px-4 py-3 text-sm text-gray-900">{item.name}</td>
                    <td className="px-4 py-3 text-sm text-gray-900">{item.quantityPerUnit}</td>
                    <td className="px-4 py-3 text-sm text-gray-900">{item.totalQuantityNeeded}</td>
                    <td className="px-4 py-3 text-sm text-gray-900">{item.quantityInStock}</td>
                    <td className="px-4 py-3 text-sm font-medium text-red-600">{item.suggestedPurchase}</td>
                    <td className="px-4 py-3 text-sm text-gray-900">
                      R$ {item.totalPrice.toFixed(2).replace('.', ',')}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="mt-4 flex justify-end">
            <button
              type="button"
              onClick={exportProductionReport}
              className="flex items-center gap-2 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors"
            >
              <FileSpreadsheet size={18} />
              Exportar Relatório
            </button>
          </div>
        </div>
      )}

      <form onSubmit={handleSubmit}>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Product Info */}
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

          {/* Components Selection */}
          <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
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
                          {[component.group, component.device, component.value, component.package]
                            .filter(Boolean)
                            .join(' • ')} 
                          • Estoque: {component.quantityInStock}
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

        {/* Selected Components */}
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mt-6">
          <h2 className="text-lg font-semibold text-gray-800 mb-4">
            Componentes do Produto ({formData.components.length})
          </h2>
          
          {formData.components.length === 0 ? (
            <div className="text-center py-8">
              <Cpu className="mx-auto mb-3 text-gray-400" size={40} />
              <p className="text-gray-500">Nenhum componente selecionado</p>
              <p className="text-sm text-gray-400 mt-1">Adicione componentes da lista acima</p>
            </div>
          ) : (
            <div className="space-y-2">
              {formData.components.map((comp) => {
                const component = getComponentDetails(comp.componentId);
                return (
                  <div
                    key={comp.componentId}
                    className="flex items-center justify-between p-3 bg-gray-50 rounded-lg"
                  >
                    <div className="flex items-center gap-3">
                      <Cpu className="text-gray-400" size={18} />
                      <div>
                        <span className="text-sm font-medium text-gray-900">
                          {component?.name || `Componente #${comp.componentId}`}
                        </span>
                        {component && (
                          <p className="text-xs text-gray-500">
                            {[component.device, component.value].filter(Boolean).join(' - ')}
                          </p>
                        )}
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