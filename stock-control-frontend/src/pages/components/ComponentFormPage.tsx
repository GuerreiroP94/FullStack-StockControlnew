import React, { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { ArrowLeft, Save, Cpu } from 'lucide-react';
import componentsService from '../../services/components.service';
import { ComponentCreate } from '../../types';
import { COMPONENT_GROUPS } from '../../utils/constants';
import LoadingSpinner from '../../components/common/LoadingSpinner';
import ErrorMessage from '../../components/common/ErrorMessage';

const ComponentFormPage: React.FC = () => {
  const navigate = useNavigate();
  const { id } = useParams();
  const isEditing = !!id;

  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  
  const [formData, setFormData] = useState<ComponentCreate>({
    name: '',
    description: '',
    group: '',
    quantityInStock: 0,
    minimumQuantity: 0
  });

  useEffect(() => {
    if (isEditing && id) {
      fetchComponent(Number(id));
    }
  }, [id, isEditing]);

  const fetchComponent = async (componentId: number) => {
    try {
      setLoading(true);
      const component = await componentsService.getById(componentId);
      setFormData({
        name: component.name,
        description: component.description || '',
        group: component.group,
        quantityInStock: component.quantityInStock,
        minimumQuantity: component.minimumQuantity
      });
    } catch (error) {
      setError('Erro ao carregar componente');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    
    // Validations
    if (!formData.name || !formData.group) {
      setError('Nome e grupo são obrigatórios');
      return;
    }
    
    if (formData.quantityInStock < 0 || formData.minimumQuantity < 0) {
      setError('As quantidades não podem ser negativas');
      return;
    }

    try {
      setSaving(true);
      
      if (isEditing && id) {
        await componentsService.update(Number(id), formData);
      } else {
        await componentsService.create(formData);
      }
      
      navigate('/components');
    } catch (error) {
      setError('Erro ao salvar componente');
      console.error(error);
    } finally {
      setSaving(false);
    }
  };

  const handleChange = (field: keyof ComponentCreate, value: string | number) => {
    setFormData(prev => ({ ...prev, [field]: value }));
  };

  if (loading) {
    return (
      <div className="p-6">
        <LoadingSpinner fullScreen message="Carregando componente..." />
      </div>
    );
  }

  return (
    <div className="p-6 max-w-4xl mx-auto">
      {/* Header */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <button
              onClick={() => navigate('/components')}
              className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
            >
              <ArrowLeft size={20} />
            </button>
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-gradient-to-br from-blue-500 to-blue-600 rounded-xl flex items-center justify-center shadow-lg">
                <Cpu className="text-white" size={20} />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-gray-800">
                  {isEditing ? 'Editar Componente' : 'Novo Componente'}
                </h1>
                <p className="text-sm text-gray-500">
                  {isEditing ? 'Atualize as informações do componente' : 'Adicione um novo componente ao estoque'}
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Form */}
      <form onSubmit={handleSubmit}>
        {error && <ErrorMessage message={error} onClose={() => setError('')} className="mb-6" />}

        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Name */}
            <div className="md:col-span-2">
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Nome do Componente *
              </label>
              <input
                type="text"
                value={formData.name}
                onChange={(e) => handleChange('name', e.target.value)}
                className="w-full px-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200"
                placeholder="Ex: Resistor 10K Ohm"
                required
              />
            </div>

            {/* Description */}
            <div className="md:col-span-2">
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Descrição
              </label>
              <textarea
                value={formData.description}
                onChange={(e) => handleChange('description', e.target.value)}
                className="w-full px-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200"
                placeholder="Descrição detalhada do componente (opcional)"
                rows={3}
              />
            </div>

            {/* Group */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Grupo *
              </label>
              <select
                value={formData.group}
                onChange={(e) => handleChange('group', e.target.value)}
                className="w-full px-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200 bg-white"
                required
              >
                <option value="">Selecione um grupo</option>
                {COMPONENT_GROUPS.map(group => (
                  <option key={group} value={group}>{group}</option>
                ))}
              </select>
            </div>

            {/* Quantity in Stock */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Quantidade em Estoque *
              </label>
              <input
                type="number"
                value={formData.quantityInStock}
                onChange={(e) => handleChange('quantityInStock', Number(e.target.value))}
                className="w-full px-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200"
                min="0"
                required
              />
            </div>

            {/* Minimum Quantity */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Quantidade Mínima *
              </label>
              <input
                type="number"
                value={formData.minimumQuantity}
                onChange={(e) => handleChange('minimumQuantity', Number(e.target.value))}
                className="w-full px-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200"
                min="0"
                required
              />
              <p className="text-xs text-gray-500 mt-1">
                Alerta será gerado quando o estoque ficar abaixo deste valor
              </p>
            </div>
          </div>

          {/* Actions */}
          <div className="flex justify-end gap-3 mt-6 pt-6 border-t border-gray-200">
            <button
              type="button"
              onClick={() => navigate('/components')}
              className="px-4 py-2 text-gray-600 hover:text-gray-800 hover:bg-gray-100 rounded-lg transition-all duration-200"
            >
              Cancelar
            </button>
            <button
              type="submit"
              disabled={saving}
              className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-blue-500 to-blue-600 text-white rounded-lg hover:from-blue-600 hover:to-blue-700 disabled:from-gray-300 disabled:to-gray-400 disabled:cursor-not-allowed transition-all duration-200"
            >
              {saving ? (
                <>
                  <LoadingSpinner size="sm" />
                  Salvando...
                </>
              ) : (
                <>
                  <Save size={18} />
                  {isEditing ? 'Atualizar' : 'Criar'} Componente
                </>
              )}
            </button>
          </div>
        </div>
      </form>
    </div>
  );
};

export default ComponentFormPage;