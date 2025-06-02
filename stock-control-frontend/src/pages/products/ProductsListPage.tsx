import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  Plus, 
  Search, 
  Pencil, 
  Trash2, 
  Package,
  Cpu,
  Calendar,
  ChevronDown,
  ChevronUp,
  FileSpreadsheet,
  Calculator,
  DollarSign,
  AlertCircle,
  Check,
  X,
  GripVertical,
  Eye,
  ArrowUp,
  ArrowDown
} from 'lucide-react';
import productsService from '../../services/products.service';
import componentsService from '../../services/components.service';
import exportService from '../../services/export.service';
import { Product, ProductQueryParameters, Component, ProductWithPriority, ProductCalculation, ProductionPlanRow } from '../../types';
import { PAGINATION } from '../../utils/constants';
import { formatDate, formatCurrency } from '../../utils/helpers';
import LoadingSpinner from '../../components/common/LoadingSpinner';
import ConfirmModal from '../../components/common/ConfirmModal';
import ErrorMessage from '../../components/common/ErrorMessage';
import SuccessMessage from '../../components/common/SuccessMessage';
import ProductPreview from '../products/ProductPreview';


const ProductsListPage: React.FC = () => {
  const navigate = useNavigate();
  const [products, setProducts] = useState<ProductWithPriority[]>([]);
  const [components, setComponents] = useState<Component[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [deleteModal, setDeleteModal] = useState<{ show: boolean; product?: Product }>({ show: false });
  
  // Estados para funcionalidades novas
  const [expandedProductId, setExpandedProductId] = useState<number | null>(null);
  const [isPriorityMode, setIsPriorityMode] = useState(false);
  const [showExportModal, setShowExportModal] = useState(false);
  const [recalculatingProduct, setRecalculatingProduct] = useState<number | null>(null);
  const [exportQuantities, setExportQuantities] = useState<Map<number, number>>(new Map());
  
  // Filters
  const [queryParams, setQueryParams] = useState<ProductQueryParameters>({
    name: '',
    pageNumber: 1,
    pageSize: PAGINATION.DEFAULT_PAGE_SIZE
  });

  useEffect(() => {
    fetchProducts();
    fetchComponents();
  }, [queryParams]);

  const fetchProducts = async () => {
  try {
    setLoading(true);
    const data = await productsService.getAll(queryParams);
    
    // Carregar dados adicionais salvos no localStorage
    const savedPriorities = localStorage.getItem('productPriorities');
    const savedCalculations = localStorage.getItem('productCalculations');
    
    const priorities = savedPriorities ? JSON.parse(savedPriorities) : {};
    const calculations = savedCalculations ? JSON.parse(savedCalculations) : {};
    
    const enhancedProducts: ProductWithPriority[] = data.map(product => {
      const calculation = calculations[product.id];
      
      return {
        ...product,
        priority: priorities[product.id] || null,
        fixedCalculation: calculation ? {
          id: calculation.id,
          calculatedAt: calculation.calculatedAt,
          totalCost: calculation.totalCost,
          componentsSnapshot: calculation.componentsSnapshot
        } : null,
        calculationHistory: calculation?.calculationHistory || []
      };
    });
    
    setProducts(enhancedProducts);
  } catch (error) {
    setError('Erro ao carregar produtos');
    console.error(error);
  } finally {
    setLoading(false);
  }
};

  const fetchComponents = async () => {
    try {
      const data = await componentsService.getAll();
      setComponents(data);
    } catch (error) {
      console.error('Erro ao carregar componentes:', error);
    }
  };

  const handleDelete = async () => {
    if (!deleteModal.product) return;
    
    try {
      await productsService.delete(deleteModal.product.id);
      setSuccess('Produto excluído com sucesso!');
      fetchProducts();
      setDeleteModal({ show: false });
    } catch (error) {
      setError('Erro ao excluir produto');
    }
  };

  const handleSearch = (value: string) => {
    setQueryParams(prev => ({ ...prev, name: value, pageNumber: 1 }));
  };

  const toggleProductExpansion = (productId: number) => {
    setExpandedProductId(expandedProductId === productId ? null : productId);
  };

  const moveProduct = (fromIndex: number, direction: 'up' | 'down') => {
    const items = [...products];
    const toIndex = direction === 'up' ? fromIndex - 1 : fromIndex + 1;
    
    if (toIndex < 0 || toIndex >= items.length) return;
    
    // Trocar posições
    [items[fromIndex], items[toIndex]] = [items[toIndex], items[fromIndex]];
    
    // Atualizar prioridades
    const updatedProducts = items.map((product, index) => ({
      ...product,
      priority: index + 1
    }));

    setProducts(updatedProducts);

    // Salvar prioridades no localStorage (temporário)
    const priorities = updatedProducts.reduce((acc, product) => ({
      ...acc,
      [product.id]: product.priority
    }), {});
    localStorage.setItem('productPriorities', JSON.stringify(priorities));
  };

  const togglePriorityMode = () => {
    setIsPriorityMode(!isPriorityMode);
    
    if (!isPriorityMode && products.every(p => !p.priority)) {
      // Se entrando no modo de prioridade e nenhum produto tem prioridade, atribuir automaticamente
      const updatedProducts = products.map((product, index) => ({
        ...product,
        priority: index + 1
      }));
      setProducts(updatedProducts);
      
      const priorities = updatedProducts.reduce((acc, product) => ({
        ...acc,
        [product.id]: product.priority
      }), {});
      localStorage.setItem('productPriorities', JSON.stringify(priorities));
    }
  };

  const calculateProduction = (product: ProductWithPriority): ProductCalculation => {
  const componentsSnapshot = product.components.map(comp => {
    const component = components.find(c => c.id === comp.componentId);
    if (!component) return null;

    return {
      componentId: comp.componentId,
      name: comp.componentName,
      quantity: comp.quantity,
      unitPrice: component.price || 0,
      totalPrice: (component.price || 0) * comp.quantity
    };
  }).filter((item): item is ProductCalculation['componentsSnapshot'][0] => item !== null);

  const totalCost = componentsSnapshot.reduce((sum, item) => sum + item.totalPrice, 0);

  return {
    id: Date.now().toString(), // Adicione um ID único
    totalCost,
    calculatedAt: new Date().toISOString(),
    componentsSnapshot
  };
};

  const handleRecalculateProduction = async (product: ProductWithPriority) => {
  setRecalculatingProduct(product.id);
  
  try {
    const newCalculation = calculateProduction(product);
    
    if (product.fixedCalculation && 
        Math.abs(newCalculation.totalCost - product.fixedCalculation.totalCost) < 0.01) {
      setSuccess('Não houve alteração nos preços. Nada será alterado.');
      setRecalculatingProduct(null);
      return;
    }

    // Mostrar modal de confirmação
    const confirmed = window.confirm(
      `O valor da produção mudou de ${formatCurrency(product.fixedCalculation?.totalCost || 0)} ` +
      `para ${formatCurrency(newCalculation.totalCost)}.\n\n` +
      `Deseja confirmar o recálculo? Isso criará um novo histórico.`
    );

    if (confirmed) {
      // Salvar novo cálculo
      const calculations = JSON.parse(localStorage.getItem('productCalculations') || '{}');
      
      // Estruturar o histórico corretamente
      const productCalc = calculations[product.id] || {
        ...newCalculation,
        calculationHistory: []
      };

      // Se já existe um cálculo fixado, adicionar ao histórico
      if (product.fixedCalculation) {
        productCalc.calculationHistory = [
          ...(productCalc.calculationHistory || []),
          product.fixedCalculation
        ];
      }

      // Atualizar com o novo cálculo
      calculations[product.id] = {
        ...newCalculation,
        calculationHistory: productCalc.calculationHistory
      };

      localStorage.setItem('productCalculations', JSON.stringify(calculations));
      
      // Atualizar estado local
      setProducts(prevProducts => 
        prevProducts.map(p => 
          p.id === product.id 
            ? { 
                ...p, 
                fixedCalculation: newCalculation,
                calculationHistory: calculations[product.id].calculationHistory
              }
            : p
        )
      );

      setSuccess('Produção recalculada com sucesso!');
    }
  } catch (error) {
    setError('Erro ao recalcular produção');
    console.error(error);
  } finally {
    setRecalculatingProduct(null);
  }
};

  const handleExportToExcel = () => {
    const productsToExport = products
      .filter(p => p.priority)
      .sort((a, b) => (a.priority || 0) - (b.priority || 0));

    if (productsToExport.length === 0) {
      setError('Defina a ordem de prioridade de pelo menos um produto antes de exportar.');
      return;
    }

    setShowExportModal(true);
  };

 const confirmExport = () => {
  const productsToExport = products
    .filter(p => p.priority)
    .sort((a, b) => (a.priority || 0) - (b.priority || 0));

  const exportData: ProductionPlanRow[] = productsToExport.flatMap(product => {
    const quantity = exportQuantities.get(product.id) || 1;
    
    return product.components.map(comp => {
      const component = components.find(c => c.id === comp.componentId);
      if (!component) return null;

      const totalNeeded = comp.quantity * quantity;
      const toBuy = Math.max(0, totalNeeded - component.quantityInStock);

      return {
        qtdFabricar: quantity,
        qtdTotal: comp.quantity,
        device: component.device || '',
        value: component.value || '',
        package: component.package || '',
        caracteristicas: component.characteristics || '',
        codigo: component.internalCode || '',
        gaveta: component.drawer || '',
        divisao: component.division || '',
        qtdEstoque: component.quantityInStock,
        qtdCompra: toBuy
      };
    }).filter((item): item is ProductionPlanRow => item !== null);
  });

  exportService.exportProductionPlan(exportData);
  setShowExportModal(false);
  setSuccess('Planilha de produção exportada com sucesso!');
};

  const productsWithPriority = products.filter(p => p.priority).length;

  return (
    <div className="p-6">
      {/* Header */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className="w-10 h-10 bg-gradient-to-br from-green-500 to-green-600 rounded-xl flex items-center justify-center shadow-lg">
              <Package className="text-white" size={20} />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-gray-800">Produtos</h1>
              <p className="text-sm text-gray-500">Gerencie os produtos montados</p>
            </div>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <button
              onClick={() => navigate('/products/new')}
              className="flex items-center gap-2 px-4 py-2.5 bg-gradient-to-r from-green-500 to-green-600 text-white rounded-lg hover:from-green-600 hover:to-green-700 transition-all duration-200 shadow-sm"
            >
              <Plus size={18} />
              <span className="font-medium">Novo Produto</span>
            </button>
            
            <button
              onClick={togglePriorityMode}
              className={`flex items-center gap-2 px-4 py-2.5 rounded-lg transition-all duration-200 ${
                isPriorityMode 
                  ? 'bg-orange-600 text-white hover:bg-orange-700' 
                  : 'bg-gray-600 text-white hover:bg-gray-700'
              }`}
            >
              <GripVertical size={18} />
              <span className="font-medium">
                {isPriorityMode ? 'Salvar Ordem' : 'Definir Ordem'}
              </span>
            </button>
            
            <button
              onClick={handleExportToExcel}
              className={`flex items-center gap-2 px-4 py-2.5 rounded-lg transition-all duration-200 ${
                productsWithPriority > 0
                  ? 'bg-purple-600 text-white hover:bg-purple-700'
                  : 'bg-gray-300 text-gray-500 cursor-not-allowed'
              }`}
              disabled={productsWithPriority === 0}
            >
              <FileSpreadsheet size={18} />
              <span className="font-medium">Exportar Produção</span>
            </button>
          </div>
        </div>
      </div>

      {/* Messages */}
      {error && <ErrorMessage message={error} onClose={() => setError('')} className="mb-6" />}
      {success && <SuccessMessage message={success} onClose={() => setSuccess('')} className="mb-6" />}

      {/* Filters */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Search */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" size={18} />
            <input
              type="text"
              placeholder="Buscar por nome..."
              value={queryParams.name}
              onChange={(e) => handleSearch(e.target.value)}
              className="w-full pl-10 pr-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200"
            />
          </div>

          {/* Page Size */}
          <select
            value={queryParams.pageSize}
            onChange={(e) => setQueryParams(prev => ({ ...prev, pageSize: Number(e.target.value), pageNumber: 1 }))}
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
            <LoadingSpinner size="lg" message="Carregando produtos..." />
          </div>
        ) : products.length === 0 ? (
          <div className="p-12 text-center">
            <Package className="mx-auto mb-4 text-gray-400" size={48} />
            <p className="text-lg font-medium text-gray-600">Nenhum produto encontrado</p>
            <p className="text-sm text-gray-500 mt-1">
              {queryParams.name 
                ? "Tente ajustar os filtros de busca" 
                : "Adicione novos produtos ao sistema"}
            </p>
          </div>
        ) : (
          <table className="min-w-full">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                {isPriorityMode && (
                  <th className="px-6 py-4 text-center text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Ordem
                  </th>
                )}
                <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Produto
                </th>
                <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Componentes
                </th>
                <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Valor Fixado
                </th>
                <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Criado em
                </th>
                <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Criado por
                </th>
                <th className="px-6 py-4 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Ações
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {products.map((product, index) => (
                <React.Fragment key={product.id}>
                  <tr className={`hover:bg-gray-50 transition-colors duration-150 ${
                    product.priority ? 'border-l-4 border-green-500' : ''
                  }`}>
                    {isPriorityMode && (
                      <td className="px-6 py-4 whitespace-nowrap text-center">
                        <div className="flex items-center justify-center gap-2">
                          <div className="flex flex-col gap-1">
                            <button
                              onClick={() => moveProduct(index, 'up')}
                              disabled={index === 0}
                              className="p-1 hover:bg-gray-200 rounded disabled:opacity-30"
                            >
                              <ArrowUp size={16} />
                            </button>
                            <button
                              onClick={() => moveProduct(index, 'down')}
                              disabled={index === products.length - 1}
                              className="p-1 hover:bg-gray-200 rounded disabled:opacity-30"
                            >
                              <ArrowDown size={16} />
                            </button>
                          </div>
                          <span className="text-lg font-bold text-gray-700">
                            {product.priority || '-'}
                          </span>
                        </div>
                      </td>
                    )}
                    <td 
                      className="px-6 py-4 whitespace-nowrap cursor-pointer"
                      onClick={() => toggleProductExpansion(product.id)}
                    >
                      <div className="flex items-center gap-2">
                        <button className="text-gray-500 hover:text-gray-700">
                          {expandedProductId === product.id ? 
                            <ChevronUp size={18} /> : 
                            <ChevronDown size={18} />
                          }
                        </button>
                        <div>
                          <p className="text-sm font-medium text-gray-900">{product.name}</p>
                          {product.description && (
                            <p className="text-xs text-gray-500">{product.description}</p>
                          )}
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex flex-wrap gap-1">
                        {product.components.length === 0 ? (
                          <span className="text-sm text-gray-500">Nenhum componente</span>
                        ) : (
                          product.components.slice(0, 3).map((comp, index) => (
                            <span
                              key={index}
                              className="inline-flex items-center gap-1 px-2 py-1 text-xs bg-blue-100 text-blue-800 rounded-md"
                            >
                              <Cpu size={12} />
                              {comp.componentName} x{comp.quantity}
                            </span>
                          ))
                        )}
                        {product.components.length > 3 && (
                          <span className="text-xs text-gray-500">
                            +{product.components.length - 3} mais
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      {product.fixedCalculation ? (
                        <div className="flex items-center gap-2">
                          <DollarSign size={16} className="text-green-600" />
                          <span className="text-sm font-medium text-gray-900">
                            {formatCurrency(product.fixedCalculation.totalCost)}
                          </span>
                        </div>
                      ) : (
                        <button
                          onClick={() => handleRecalculateProduction(product)}
                          className="text-sm text-blue-600 hover:text-blue-700"
                        >
                          Calcular
                        </button>
                      )}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center gap-2 text-sm text-gray-600">
                        <Calendar size={14} />
                        {formatDate(product.createdAt)}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <p className="text-sm text-gray-600">{product.createdBy || 'Sistema'}</p>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => handleRecalculateProduction(product)}
                          disabled={recalculatingProduct === product.id}
                          className="p-2 text-purple-600 hover:bg-purple-50 rounded-lg transition-all duration-200"
                          title="Recalcular Produção"
                        >
                          {recalculatingProduct === product.id ? (
                            <LoadingSpinner size="sm" />
                          ) : (
                            <Calculator size={18} />
                          )}
                        </button>
                        <button
                          onClick={() => navigate(`/products/${product.id}/edit`)}
                          className="p-2 text-blue-600 hover:bg-blue-50 rounded-lg transition-all duration-200"
                          title="Editar"
                        >
                          <Pencil size={18} />
                        </button>
                        <button
                          onClick={() => setDeleteModal({ show: true, product })}
                          className="p-2 text-red-600 hover:bg-red-50 rounded-lg transition-all duration-200"
                          title="Excluir"
                        >
                          <Trash2 size={18} />
                        </button>
                      </div>
                    </td>
                  </tr>
                  
                  {/* Linha expandida com prévia do produto */}
                  {expandedProductId === product.id && (
                    <tr>
                      <td colSpan={isPriorityMode ? 7 : 6} className="p-0">
                        <ProductPreview 
                          product={product} 
                          components={components}
                          onClose={() => setExpandedProductId(null)}
                        />
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Delete Modal */}
      <ConfirmModal
        isOpen={deleteModal.show}
        onClose={() => setDeleteModal({ show: false })}
        onConfirm={handleDelete}
        title="Excluir Produto"
        message={`Tem certeza que deseja excluir o produto "${deleteModal.product?.name}"? Esta ação não pode ser desfeita.`}
        confirmText="Excluir"
        type="danger"
      />

      {/* Export Modal */}
      {showExportModal && (
        <div className="fixed inset-0 bg-black bg-opacity-30 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl shadow-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
            <div className="p-6">
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-xl font-bold text-gray-800">Confirmar Exportação</h2>
                <button
                  onClick={() => setShowExportModal(false)}
                  className="text-gray-400 hover:text-gray-600"
                >
                  <X size={24} />
                </button>
              </div>

              <p className="text-sm text-gray-600 mb-4">
                Defina as quantidades para fabricação de cada produto:
              </p>

              <div className="space-y-3 mb-6">
                {products
                  .filter(p => p.priority)
                  .sort((a, b) => (a.priority || 0) - (b.priority || 0))
                  .map(product => (
                    <div key={product.id} className="flex items-center gap-4 p-3 bg-gray-50 rounded-lg">
                      <span className="text-sm font-medium text-gray-700 flex-1">
                        {product.priority}. {product.name}
                      </span>
                      <div className="flex items-center gap-2">
                        <label className="text-sm text-gray-600">Qtd:</label>
                        <input
                          type="number"
                          min="1"
                          value={exportQuantities.get(product.id) || 1}
                          onChange={(e) => {
                            const newMap = new Map(exportQuantities);
                            newMap.set(product.id, parseInt(e.target.value) || 1);
                            setExportQuantities(newMap);
                          }}
                          className="w-20 px-3 py-1.5 border border-gray-300 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-200"
                        />
                      </div>
                    </div>
                  ))}
              </div>

              <div className="flex justify-end gap-3">
                <button
                  onClick={() => setShowExportModal(false)}
                  className="px-4 py-2 text-gray-600 hover:text-gray-800 hover:bg-gray-100 rounded-lg transition-all duration-200"
                >
                  Cancelar
                </button>
                <button
                  onClick={confirmExport}
                  className="flex items-center gap-2 px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-all duration-200"
                >
                  <FileSpreadsheet size={18} />
                  Confirmar Exportação
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ProductsListPage;