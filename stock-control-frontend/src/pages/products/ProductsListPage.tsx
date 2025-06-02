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
  GripVertical,
  ArrowUp,
  ArrowDown,
  History,
  RefreshCw,
  ArrowRight,
  X  // Adicionado import do X
} from 'lucide-react';
import productsService from '../../services/products.service';
import componentsService from '../../services/components.service';
import exportService from '../../services/export.service';
import { Product, ProductQueryParameters, Component, ProductWithPriority, ProductCalculation, ProductionPlanRow } from '../../types';
import { PAGINATION } from '../../utils/constants';
import { formatDate, formatCurrency, formatDateTime } from '../../utils/helpers';
import LoadingSpinner from '../../components/common/LoadingSpinner';
import ConfirmModal from '../../components/common/ConfirmModal';
import ErrorMessage from '../../components/common/ErrorMessage';
import SuccessMessage from '../../components/common/SuccessMessage';

const ProductsListPage: React.FC = () => {
  const navigate = useNavigate();
  const [products, setProducts] = useState<ProductWithPriority[]>([]);
  const [components, setComponents] = useState<Component[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [deleteModal, setDeleteModal] = useState<{ show: boolean; product?: Product }>({ show: false });
  
  // Estados para funcionalidades
  const [expandedProductId, setExpandedProductId] = useState<number | null>(null);
  const [isPriorityMode, setIsPriorityMode] = useState(false);
  const [showExportModal, setShowExportModal] = useState(false);
  const [recalculatingProduct, setRecalculatingProduct] = useState<number | null>(null);
  const [exportQuantities, setExportQuantities] = useState<Map<number, number>>(new Map());
  const [productOrder, setProductOrder] = useState<number[]>([]);
  
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
      const savedCalculations = localStorage.getItem('productCalculations');
      const calculations = savedCalculations ? JSON.parse(savedCalculations) : {};
      
      const enhancedProducts: ProductWithPriority[] = data.map(product => {
        const calculation = calculations[product.id];
        
        return {
          ...product,
          fixedCalculation: calculation ? {
            id: calculation.id,
            calculatedAt: calculation.calculatedAt,
            totalCost: calculation.totalCost,
            componentsSnapshot: calculation.componentsSnapshot
          } : undefined,
          calculationHistory: calculation?.calculationHistory || []
        };
      });
      
      setProducts(enhancedProducts);
      
      // Definir ordem inicial dos produtos
      setProductOrder(enhancedProducts.map(p => p.id));
      
      // Se algum produto não tem cálculo inicial, calcular automaticamente
      enhancedProducts.forEach(product => {
        if (!product.fixedCalculation && product.components.length > 0) {
          // Calcular e salvar automaticamente o valor inicial
          const initialCalc = calculateProduction(product);
          saveProductCalculation(product.id, initialCalc, false);
        }
      });
      
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
      
      // Remover cálculos salvos do produto
      const calculations = JSON.parse(localStorage.getItem('productCalculations') || '{}');
      delete calculations[deleteModal.product.id];
      localStorage.setItem('productCalculations', JSON.stringify(calculations));
      
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

  const moveProduct = (productId: number, direction: 'up' | 'down') => {
    const currentIndex = productOrder.indexOf(productId);
    if (currentIndex === -1) return;
    
    const newIndex = direction === 'up' ? currentIndex - 1 : currentIndex + 1;
    if (newIndex < 0 || newIndex >= productOrder.length) return;
    
    const newOrder = [...productOrder];
    [newOrder[currentIndex], newOrder[newIndex]] = [newOrder[newIndex], newOrder[currentIndex]];
    setProductOrder(newOrder);
  };

  const togglePriorityMode = () => {
    if (isPriorityMode) {
      // Resetar ordem ao sair do modo de prioridade
      setProductOrder(products.map(p => p.id));
    }
    setIsPriorityMode(!isPriorityMode);
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
      id: Date.now().toString(),
      totalCost,
      calculatedAt: new Date().toISOString(),
      componentsSnapshot
    };
  };

  const saveProductCalculation = (productId: number, calculation: ProductCalculation, addToHistory: boolean = true) => {
    const calculations = JSON.parse(localStorage.getItem('productCalculations') || '{}');
    
    // Se deve adicionar ao histórico e já existe um cálculo
    if (addToHistory && calculations[productId]) {
      const history = calculations[productId].calculationHistory || [];
      history.push({
        id: calculations[productId].id,
        calculatedAt: calculations[productId].calculatedAt,
        totalCost: calculations[productId].totalCost,
        componentsSnapshot: calculations[productId].componentsSnapshot
      });
      // Salvando o histórico no objeto de cálculos
      calculations[productId].calculationHistory = history;
    }
    
    // Atualizando o cálculo atual
    calculations[productId] = {
      ...calculation,
      calculationHistory: calculations[productId]?.calculationHistory || []
    };
    
    localStorage.setItem('productCalculations', JSON.stringify(calculations));
  };

  const handleRecalculateProduction = async (product: ProductWithPriority) => {
    setRecalculatingProduct(product.id);
    
    try {
      const newCalculation = calculateProduction(product);
      
      // Se não há mudança no valor, informar
      if (product.fixedCalculation && 
          Math.abs(newCalculation.totalCost - product.fixedCalculation.totalCost) < 0.01) {
        setSuccess('Os preços não foram alterados. O valor permanece o mesmo.');
        setRecalculatingProduct(null);
        return;
      }

      // Salvar novo cálculo com histórico
      saveProductCalculation(product.id, newCalculation, true);
      
      // Recarregar dados para atualizar o estado
      await fetchProducts();

      setSuccess('Valor do produto recalculado com sucesso!');
    } catch (error) {
      setError('Erro ao recalcular produção');
      console.error(error);
    } finally {
      setRecalculatingProduct(null);
    }
  };

  const handleExportToExcel = () => {
    if (products.length === 0) {
      setError('Não há produtos para exportar.');
      return;
    }

    // Resetar quantidades e usar ordem padrão
    const resetQuantities = new Map<number, number>();
    productOrder.forEach(productId => {
      resetQuantities.set(productId, 1);
    });
    setExportQuantities(resetQuantities);
    
    setShowExportModal(true);
  };

  const confirmExport = () => {
    const orderedProducts = productOrder
      .map(id => products.find(p => p.id === id))
      .filter((p): p is ProductWithPriority => p !== undefined);

    const exportData: ProductionPlanRow[] = orderedProducts.flatMap(product => {
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

  const getProductStatus = (product: ProductWithPriority) => {
    if (!product.fixedCalculation) return 'no-calc';
    
    const currentCalc = calculateProduction(product);
    const difference = currentCalc.totalCost - product.fixedCalculation.totalCost;
    
    if (Math.abs(difference) < 0.01) return 'updated';
    if (difference > 0) return 'increased';
    return 'decreased';
  };

  const renderProductHistory = (product: ProductWithPriority) => {
    const history = product.calculationHistory || [];
    if (history.length === 0) return null;

    return (
      <div className="mt-4 p-4 bg-gray-50 rounded-lg">
        <h4 className="text-sm font-semibold text-gray-700 flex items-center gap-2 mb-3">
          <History size={16} />
          Histórico de Valores
        </h4>
        <div className="space-y-2">
          {history.slice(-5).reverse().map((calc, index) => (
            <div key={calc.id} className="flex items-center justify-between text-sm">
              <span className="text-gray-600">
                {formatDateTime(calc.calculatedAt)}
              </span>
              <span className="font-medium text-gray-900">
                {formatCurrency(calc.totalCost)}
              </span>
            </div>
          ))}
          {history.length > 5 && (
            <p className="text-xs text-gray-500 text-center">
              ... e mais {history.length - 5} registros
            </p>
          )}
        </div>
      </div>
    );
  };

  const sortedProducts = isPriorityMode 
    ? productOrder.map(id => products.find(p => p.id === id)).filter(Boolean) as ProductWithPriority[]
    : products;

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
                {isPriorityMode ? 'Salvar Ordem' : 'Ordenar para Exportar'}
              </span>
            </button>
            
            <button
              onClick={handleExportToExcel}
              className="flex items-center gap-2 px-4 py-2.5 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-all duration-200"
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
        <div className="relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" size={18} />
          <input
            type="text"
            placeholder="Buscar produtos por nome..."
            value={queryParams.name}
            onChange={(e) => handleSearch(e.target.value)}
            className="w-full pl-10 pr-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200"
          />
        </div>
      </div>

      {/* Products Grid */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200">
        {loading ? (
          <div className="p-12 text-center">
            <LoadingSpinner size="lg" message="Carregando produtos..." />
          </div>
        ) : sortedProducts.length === 0 ? (
          <div className="p-12 text-center">
            <Package className="mx-auto mb-4 text-gray-400" size={48} />
            <p className="text-lg font-medium text-gray-600">Nenhum produto encontrado</p>
            <p className="text-sm text-gray-500 mt-1">
              {queryParams.name 
                ? "Tente ajustar sua busca" 
                : "Crie seu primeiro produto clicando no botão acima"}
            </p>
          </div>
        ) : (
          <div className="divide-y divide-gray-200">
            {sortedProducts.map((product, index) => {
              const status = getProductStatus(product);
              const currentCalc = calculateProduction(product);
              const priceDiff = product.fixedCalculation 
                ? currentCalc.totalCost - product.fixedCalculation.totalCost 
                : 0;
              
              return (
                <div key={product.id} className="p-6 hover:bg-gray-50 transition-colors">
                  <div className="flex items-start justify-between gap-4">
                    {/* Order Controls */}
                    {isPriorityMode && (
                      <div className="flex items-center gap-2">
                        <div className="flex flex-col gap-1">
                          <button
                            onClick={() => moveProduct(product.id, 'up')}
                            disabled={index === 0}
                            className="p-1 hover:bg-gray-200 rounded disabled:opacity-30 disabled:cursor-not-allowed"
                          >
                            <ArrowUp size={14} />
                          </button>
                          <button
                            onClick={() => moveProduct(product.id, 'down')}
                            disabled={index === sortedProducts.length - 1}
                            className="p-1 hover:bg-gray-200 rounded disabled:opacity-30 disabled:cursor-not-allowed"
                          >
                            <ArrowDown size={14} />
                          </button>
                        </div>
                        <span className="text-lg font-bold text-gray-700 w-8 text-center">
                          {index + 1}
                        </span>
                      </div>
                    )}

                    {/* Product Info */}
                    <div className="flex-1">
                      <div className="flex items-start justify-between">
                        <div>
                          <h3 className="text-lg font-semibold text-gray-900">{product.name}</h3>
                          {product.description && (
                            <p className="text-sm text-gray-600 mt-1">{product.description}</p>
                          )}
                          
                          {/* Components Info */}
                          <div className="mt-3 flex flex-wrap gap-2">
                            {product.components.slice(0, 3).map((comp, idx) => (
                              <span
                                key={idx}
                                className="inline-flex items-center gap-1 px-2.5 py-1 text-xs bg-blue-50 text-blue-700 rounded-md"
                              >
                                <Cpu size={12} />
                                {comp.componentName} x{comp.quantity}
                              </span>
                            ))}
                            {product.components.length > 3 && (
                              <span className="text-xs text-gray-500 flex items-center">
                                +{product.components.length - 3} componentes
                              </span>
                            )}
                          </div>

                          {/* Product Value */}
                          <div className="mt-4 flex items-center gap-4">
                            <div>
                              <p className="text-xs text-gray-500">Valor Fixado</p>
                              <p className="text-xl font-bold text-gray-900">
                                {product.fixedCalculation 
                                  ? formatCurrency(product.fixedCalculation.totalCost)
                                  : '-'}
                              </p>
                            </div>
                            
                            {status !== 'updated' && status !== 'no-calc' && (
                              <div className="flex items-center gap-2">
                                <ArrowRight size={16} className="text-gray-400" />
                                <div>
                                  <p className="text-xs text-gray-500">Valor Atual</p>
                                  <p className={`text-lg font-semibold ${
                                    status === 'increased' ? 'text-red-600' : 'text-green-600'
                                  }`}>
                                    {formatCurrency(currentCalc.totalCost)}
                                    <span className="text-xs ml-1">
                                      ({priceDiff > 0 ? '+' : ''}{formatCurrency(priceDiff)})
                                    </span>
                                  </p>
                                </div>
                              </div>
                            )}
                          </div>

                          {/* Meta Info */}
                          <div className="mt-3 flex items-center gap-4 text-xs text-gray-500">
                            <div className="flex items-center gap-1">
                              <Calendar size={12} />
                              Criado em {formatDate(product.createdAt)}
                            </div>
                            {product.createdBy && (
                              <div>Por {product.createdBy}</div>
                            )}
                          </div>
                        </div>

                        {/* Actions */}
                        <div className="flex items-center gap-2">
                          {status !== 'updated' && status !== 'no-calc' && (
                            <button
                              onClick={() => handleRecalculateProduction(product)}
                              disabled={recalculatingProduct === product.id}
                              className="flex items-center gap-2 px-3 py-1.5 bg-orange-100 text-orange-700 rounded-lg hover:bg-orange-200 transition-all duration-200"
                              title="Recalcular valor do produto"
                            >
                              {recalculatingProduct === product.id ? (
                                <LoadingSpinner size="sm" />
                              ) : (
                                <>
                                  <RefreshCw size={14} />
                                  <span className="text-sm font-medium">Atualizar Valor</span>
                                </>
                              )}
                            </button>
                          )}
                          
                          <button
                            onClick={() => navigate(`/products/${product.id}/edit`)}
                            className="p-2 text-blue-600 hover:bg-blue-50 rounded-lg transition-all duration-200"
                            title="Editar produto"
                          >
                            <Pencil size={18} />
                          </button>
                          
                          <button
                            onClick={() => setDeleteModal({ show: true, product })}
                            className="p-2 text-red-600 hover:bg-red-50 rounded-lg transition-all duration-200"
                            title="Excluir produto"
                          >
                            <Trash2 size={18} />
                          </button>
                        </div>
                      </div>

                      {/* Expansion Toggle */}
                      {product.calculationHistory && product.calculationHistory.length > 0 && (
                        <button
                          onClick={() => toggleProductExpansion(product.id)}
                          className="mt-4 text-sm text-blue-600 hover:text-blue-700 flex items-center gap-1"
                        >
                          {expandedProductId === product.id ? (
                            <>
                              <ChevronUp size={16} />
                              Ocultar histórico
                            </>
                          ) : (
                            <>
                              <ChevronDown size={16} />
                              Ver histórico ({product.calculationHistory.length})
                            </>
                          )}
                        </button>
                      )}

                      {/* History */}
                      {expandedProductId === product.id && renderProductHistory(product)}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
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
          <div className="bg-white rounded-xl shadow-xl w-full max-w-2xl max-h-[90vh] overflow-hidden flex flex-col">
            <div className="p-6 border-b border-gray-200">
              <div className="flex items-center justify-between">
                <h2 className="text-xl font-bold text-gray-800">Exportar Plano de Produção</h2>
                <button
                  onClick={() => setShowExportModal(false)}
                  className="text-gray-400 hover:text-gray-600"
                >
                  <X size={24} />
                </button>
              </div>
            </div>

            <div className="flex-1 overflow-y-auto p-6">
              <p className="text-sm text-gray-600 mb-6">
                Defina a quantidade de unidades para produção de cada produto:
              </p>

              <div className="space-y-3">
                {productOrder
                  .map((productId, index) => {
                    const product = products.find(p => p.id === productId);
                    if (!product) return null;
                    
                    return (
                      <div key={product.id} className="flex items-center gap-4 p-4 bg-gray-50 rounded-lg">
                        <span className="text-lg font-bold text-gray-500 w-8">
                          {index + 1}.
                        </span>
                        <span className="flex-1 font-medium text-gray-700">
                          {product.name}
                        </span>
                        <div className="flex items-center gap-2">
                          <label className="text-sm text-gray-600">Quantidade:</label>
                          <input
                            type="number"
                            min="1"
                            value={exportQuantities.get(product.id) || 1}
                            onChange={(e) => {
                              const value = Math.max(1, parseInt(e.target.value) || 1);
                              const newMap = new Map(exportQuantities);
                              newMap.set(product.id, value);
                              setExportQuantities(newMap);
                            }}
                            className="w-20 px-3 py-1.5 border border-gray-300 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-200"
                          />
                        </div>
                      </div>
                    );
                  })
                  .filter(Boolean)}
              </div>

              <div className="mt-6 p-4 bg-blue-50 rounded-lg">
                <p className="text-sm text-blue-700">
                  <strong>Nota:</strong> A planilha exportada conterá duas abas:
                </p>
                <ul className="text-sm text-blue-600 mt-2 space-y-1">
                  <li>• <strong>Plano de Produção:</strong> Lista completa dos componentes necessários</li>
                  <li>• <strong>Lista de Compras:</strong> Apenas componentes que precisam ser comprados</li>
                </ul>
              </div>
            </div>

            <div className="p-6 border-t border-gray-200 flex justify-end gap-3">
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
                Exportar Excel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ProductsListPage;