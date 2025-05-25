import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowLeft, Save, TrendingUp, TrendingDown, Search } from 'lucide-react';
import movementsService from '../../services/movements.service';
import componentsService from '../../services/components.service';
import { StockMovementCreate, Component } from '../../types';
import { MOVEMENT_TYPES } from '../../utils/constants';
import { useAuth } from '../../contexts/AuthContext';
import LoadingSpinner from '../../components/common/LoadingSpinner';
import ErrorMessage from '../../components/common/ErrorMessage';
import SuccessMessage from '../../components/common/SuccessMessage';

const MovementFormPage: React.FC = () => {
  const navigate = useNavigate();
  const { user } = useAuth();
  
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  
  const [components, setComponents] = useState<Component[]>([]);
  const [filteredComponents, setFilteredComponents] = useState<Component[]>([]);
  const [selectedComponent, setSelectedComponent] = useState<Component | null>(null);
  
  const [formData, setFormData] = useState<StockMovementCreate>({
    componentId: 0,
    movementType: MOVEMENT_TYPES.ENTRADA,
    quantity: 1,
    performedBy: user?.name || ''
  });

  useEffect(() => {
    fetchComponents();
  }, []);

  useEffect(() => {
    // Filter components based on search
    const filtered = components.filter(comp =>
      comp.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      comp.group.toLowerCase().includes(searchTerm.toLowerCase())
    );
    setFilteredComponents(filtered);
  }, [searchTerm, components]);

  const fetchComponents = async () => {
    try {
      setLoading(true);
      const data = await componentsService.getAll();
      setComponents(data);
      setFilteredComponents(data);
    } catch (error) {
      setError('Erro ao carregar componentes');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    
    // Validations
    if (!selectedComponent) {
      setError('Selecione um componente');
      return;
    }
    
    if (formData.quantity <= 0) {
      setError('A quantidade deve ser maior que zero');
      return;
    }
    
    // Check if there's enough stock for withdrawal
    if (formData.movementType === MOVEMENT_TYPES.SAIDA && formData.quantity > selectedComponent.quantityInStock) {
      setError(`Estoque insuficiente. Disponível: ${selectedComponent.quantityInStock} unidades`);
      return;
    }

    try {
      setSaving(true);
      
      await movementsService.create({
        ...formData,
        componentId: selectedComponent.id
      });
      
      setSuccess('Movimentação registrada com sucesso!');
      
      // Reset form
      setTimeout(() => {
        navigate('/movements');
      }, 1500);
    } catch (error) {
      setError('Erro ao registrar movimentação');
      console.error(error);
    } finally {
      setSaving(false);
    }
  };

  const selectComponent = (component: Component) => {
    setSelectedComponent(component);
    setFormData(prev => ({ ...prev, componentId: component.id }));
    setSearchTerm('');
  };

  const getNewStockLevel = () => {
    if (!selectedComponent) return 0;
    
    if (formData.movementType === MOVEMENT_TYPES.ENTRADA) {
      return selectedComponent.quantityInStock + formData.quantity;
    } else {
      return selectedComponent.quantityInStock - formData.quantity;
    }
  };

  const isStockCritical = () => {
    const newLevel = getNewStockLevel();
    return newLevel < (selectedComponent?.minimumQuantity || 0);
  };

  return (
    <div className="p-6 max-w-4xl mx-auto">
      {/* Header */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <button
              onClick={() => navigate('/movements')}
              className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
            >
              <ArrowLeft size={20} />
            </button>
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-gradient-to-br from-purple-500 to-purple-600 rounded-xl flex items-center justify-center shadow-lg">
                <TrendingUp className="text-white" size={20} />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-gray-800">Nova Movimentação</h1>
                <p className="text-sm text-gray-500">Registre uma entrada ou saída de estoque</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Messages */}
      {error && <ErrorMessage message={error} onClose={() => setError('')} className="mb-6" />}
      {success && <SuccessMessage message={success} onClose={() => setSuccess('')} className="mb-6" />}

      {/* Form */}
      <form onSubmit={handleSubmit}>
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
          {/* Movement Type */}
          <div className="mb-6">
            <label className="block text-sm font-medium text-gray-700 mb-3">
              Tipo de Movimentação
            </label>
            <div className="grid grid-cols-2 gap-4">
              <button
                type="button"
                onClick={() => setFormData(prev => ({ ...prev, movementType: MOVEMENT_TYPES.ENTRADA }))}
                className={`p-4 rounded-lg border-2 transition-all duration-200 ${
                  formData.movementType === MOVEMENT_TYPES.ENTRADA
                    ? 'border-green-500 bg-green-50'
                    : 'border-gray-300 hover:border-gray-400'
                }`}
              >
                <div className="flex flex-col items-center gap-2">
                  <div className={`w-12 h-12 rounded-full flex items-center justify-center ${
                    formData.movementType === MOVEMENT_TYPES.ENTRADA
                      ? 'bg-green-500 text-white'
                      : 'bg-gray-200 text-gray-600'
                  }`}>
                    <TrendingUp size={24} />
                  </div>
                  <span className={`font-medium ${
                    formData.movementType === MOVEMENT_TYPES.ENTRADA
                      ? 'text-green-700'
                      : 'text-gray-700'
                  }`}>
                    Entrada
                  </span>
                  <span className="text-xs text-gray-500">Adicionar ao estoque</span>
                </div>
              </button>

              <button
                type="button"
                onClick={() => setFormData(prev => ({ ...prev, movementType: MOVEMENT_TYPES.SAIDA }))}
                className={`p-4 rounded-lg border-2 transition-all duration-200 ${
                  formData.movementType === MOVEMENT_TYPES.SAIDA
                    ? 'border-red-500 bg-red-50'
                    : 'border-gray-300 hover:border-gray-400'
                }`}
              >
                <div className="flex flex-col items-center gap-2">
                  <div className={`w-12 h-12 rounded-full flex items-center justify-center ${
                    formData.movementType === MOVEMENT_TYPES.SAIDA
                      ? 'bg-red-500 text-white'
                      : 'bg-gray-200 text-gray-600'
                  }`}>
                    <TrendingDown size={24} />
                  </div>
                  <span className={`font-medium ${
                    formData.movementType === MOVEMENT_TYPES.SAIDA
                      ? 'text-red-700'
                      : 'text-gray-700'
                  }`}>
                    Saída
                  </span>
                  <span className="text-xs text-gray-500">Retirar do estoque</span>
                </div>
              </button>
            </div>
          </div>

          {/* Component Selection */}
          <div className="mb-6">
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Componente *
            </label>
            
            {selectedComponent ? (
              <div className="p-4 bg-blue-50 border border-blue-200 rounded-lg">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="font-medium text-gray-900">{selectedComponent.name}</p>
                    <p className="text-sm text-gray-600">
                      {selectedComponent.group} • Estoque atual: {selectedComponent.quantityInStock} unidades
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => {
                      setSelectedComponent(null);
                      setFormData(prev => ({ ...prev, componentId: 0 }));
                    }}
                    className="text-blue-600 hover:text-blue-700 text-sm"
                  >
                    Alterar
                  </button>
                </div>
              </div>
            ) : (
              <>
                <div className="relative mb-3">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" size={18} />
                  <input
                    type="text"
                    placeholder="Buscar componente..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="w-full pl-10 pr-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200"
                  />
                </div>

                {loading ? (
                  <div className="p-8 text-center">
                    <LoadingSpinner message="Carregando componentes..." />
                  </div>
                ) : (
                  <div className="max-h-60 overflow-y-auto border border-gray-200 rounded-lg">
                    {filteredComponents.length === 0 ? (
                      <p className="p-4 text-center text-gray-500">Nenhum componente encontrado</p>
                    ) : (
                      filteredComponents.map((component) => (
                        <button
                          key={component.id}
                          type="button"
                          onClick={() => selectComponent(component)}
                          className="w-full p-3 border-b border-gray-100 hover:bg-gray-50 transition-colors text-left"
                        >
                          <p className="font-medium text-gray-900">{component.name}</p>
                          <p className="text-sm text-gray-600">
                            {component.group} • Estoque: {component.quantityInStock} • Mínimo: {component.minimumQuantity}
                          </p>
                        </button>
                      ))
                    )}
                  </div>
                )}
              </>
            )}
          </div>

          {/* Quantity */}
          <div className="mb-6">
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Quantidade *
            </label>
            <input
              type="number"
              value={formData.quantity}
              onChange={(e) => setFormData(prev => ({ ...prev, quantity: Number(e.target.value) }))}
              className="w-full px-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200"
              min="1"
              max={formData.movementType === MOVEMENT_TYPES.SAIDA ? selectedComponent?.quantityInStock : undefined}
              required
            />
          </div>

          {/* Stock Preview */}
          {selectedComponent && formData.quantity > 0 && (
            <div className="mb-6 p-4 bg-gray-50 rounded-lg">
              <h3 className="text-sm font-medium text-gray-700 mb-2">Prévia do Estoque</h3>
              <div className="grid grid-cols-3 gap-4 text-sm">
                <div>
                  <p className="text-gray-500">Estoque Atual</p>
                  <p className="font-medium">{selectedComponent.quantityInStock}</p>
                </div>
                <div>
                  <p className="text-gray-500">Após Movimentação</p>
                  <p className={`font-medium ${isStockCritical() ? 'text-red-600' : 'text-gray-900'}`}>
                    {getNewStockLevel()}
                  </p>
                </div>
                <div>
                  <p className="text-gray-500">Estoque Mínimo</p>
                  <p className="font-medium">{selectedComponent.minimumQuantity}</p>
                </div>
              </div>
              {isStockCritical() && (
                <p className="mt-2 text-xs text-red-600">
                  ⚠️ Atenção: O estoque ficará abaixo do mínimo após esta movimentação
                </p>
              )}
            </div>
          )}

          {/* Actions */}
          <div className="flex justify-end gap-3 pt-6 border-t border-gray-200">
            <button
              type="button"
              onClick={() => navigate('/movements')}
              className="px-4 py-2 text-gray-600 hover:text-gray-800 hover:bg-gray-100 rounded-lg transition-all duration-200"
            >
              Cancelar
            </button>
            <button
              type="submit"
              disabled={saving || !selectedComponent}
              className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-purple-500 to-purple-600 text-white rounded-lg hover:from-purple-600 hover:to-purple-700 disabled:from-gray-300 disabled:to-gray-400 disabled:cursor-not-allowed transition-all duration-200"
            >
              {saving ? (
                <>
                  <LoadingSpinner size="sm" />
                  Registrando...
                </>
              ) : (
                <>
                  <Save size={18} />
                  Registrar Movimentação
                </>
              )}
            </button>
          </div>
        </div>
      </form>
    </div>
  );
};

export default MovementFormPage;