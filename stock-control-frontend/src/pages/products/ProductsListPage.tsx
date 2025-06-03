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
  X,
  GripVertical,
  Check
} from 'lucide-react';
import productsService from '../../services/products.service';
import componentsService from '../../services/components.service';
import exportService from '../../services/export.service';
import { Product, Component, ProductWithPriority } from '../../types';
import { formatDate, formatCurrency } from '../../utils/helpers';
import LoadingSpinner from '../../components/common/LoadingSpinner';
import ConfirmModal from '../../components/common/ConfirmModal';
import ErrorMessage from '../../components/common/ErrorMessage';
import SuccessMessage from '../../components/common/SuccessMessage';

// Componente de Relatório de Produção
const ProductionReport: React.FC<{
  product: Product;
  components: Component[];
  onExport: () => void;
}> = ({ product, components, onExport }) => {
  const [quantity, setQuantity] = useState(1);

  const getComponentDetails = (componentId: number) => {
    return components.find(c => c.id === componentId);
  };

  const calculateTotal = () => {
    return product.components.reduce((sum, pc) => {
      const component = getComponentDetails(pc.componentId);
      const price = component?.price || 0;
      return sum + (price * pc.quantity * quantity);
    }, 0);
  };

  return (
    <div className="p-6 bg-gray-50 border-t border-gray-200">
      <div className="mb-6">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-lg font-semibold text-gray-800">Relatório de Produção</h3>
            <p className="text-sm text-gray-500">Análise de componentes necessários</p>
          </div>
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <label className="text-sm font-medium text-gray-700">Quantidade a produzir:</label>
              <input
                type="number"
                value={quantity}
                onChange={(e) => setQuantity(Math.max(1, parseInt(e.target.value) || 1))}
                className="w-20 px-3 py-1.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200"
                min="1"
              />
            </div>
            <button
              onClick={onExport}
              className="flex items-center gap-2 px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700"
            >
              <FileSpreadsheet size={18} />
              Exportar Excel
            </button>
          </div>
        </div>

        <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
          <table className="min-w-full">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Componente</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Device/Value</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Cód. Interno</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Localização</th>
                <th className="px-4 py-3 text-center text-xs font-medium text-gray-500 uppercase">Qtd/Un</th>
                <th className="px-4 py-3 text-center text-xs font-medium text-gray-500 uppercase">Total</th>
                <th className="px-4 py-3 text-center text-xs font-medium text-gray-500 uppercase">Estoque</th>
                <th className="px-4 py-3 text-center text-xs font-medium text-gray-500 uppercase">Comprar</th>
                <th className="px-4 py-3 text-right text-xs font-medium text-gray-500 uppercase">Preço Unit.</th>
                <th className="px-4 py-3 text-right text-xs font-medium text-gray-500 uppercase">Total</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {product.components.map((pc, index) => {
                const component = getComponentDetails(pc.componentId);
                if (!component) return null;

                const totalNeeded = pc.quantity * quantity;
                const needToBuy = Math.max(0, totalNeeded - component.quantityInStock);
                const totalPrice = (component.price || 0) * pc.quantity * quantity;

                return (
                  <tr key={index}>
                    <td className="px-4 py-3 text-sm font-medium text-gray-900">{pc.componentName}</td>
                    <td className="px-4 py-3 text-sm text-gray-600">
                      {component.device && component.value ? `${component.device} / ${component.value}` : '-'}
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-600">{component.internalCode || '-'}</td>
                    <td className="px-4 py-3 text-sm text-gray-600">
                      {component.drawer && component.division ? `${component.drawer}/${component.division}` : '-'}
                    </td>
                    <td className="px-4 py-3 text-sm text-center">{pc.quantity}</td>
                    <td className="px-4 py-3 text-sm text-center font-medium">{totalNeeded}</td>
                    <td className="px-4 py-3 text-sm text-center">{component.quantityInStock}</td>
                    <td className="px-4 py-3 text-sm text-center">
                      {needToBuy > 0 ? (
                        <span className="text-red-600 font-medium">{needToBuy}</span>
                      ) : (
                        <span className="text-green-600 font-medium">OK</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-sm text-right">{formatCurrency(component.price || 0)}</td>
                    <td className="px-4 py-3 text-sm text-right font-medium">{formatCurrency(totalPrice)}</td>
                  </tr>
                );
              })}
            </tbody>
            <tfoot className="bg-gray-50">
              <tr>
                <td colSpan={9} className="px-4 py-3 text-sm font-medium text-right">Total Geral:</td>
                <td className="px-4 py-3 text-sm font-bold text-right">{formatCurrency(calculateTotal())}</td>
              </tr>
            </tfoot>
          </table>
        </div>
      </div>
    </div>
  );
};

// Modal de Exportação Atualizado
const ExportModal: React.FC<{
  isOpen: boolean;
  onClose: () => void;
  product: Product;
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
    // Inicializar inputs de ordem
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
    
    // Atualizar inputs após drag & drop
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
    // Criar array de componentes com suas ordens
    const componentsWithOrder = localOrder.map(compId => ({
      componentId: compId,
      order: orderInputs[compId] || 999
    }));

    // Ordenar pelo número de ordem
    componentsWithOrder.sort((a, b) => a.order - b.order);

    // Extrair nova ordem de IDs
    const newOrder = componentsWithOrder.map(item => item.componentId);
    
    setLocalOrder(newOrder);
    onUpdateOrder(newOrder);
    
    // Atualizar inputs para refletir a nova ordem
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
          {/* Botão Ordenar */}
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

const ProductsListPage: React.FC = () => {
  const navigate = useNavigate();
  const [products, setProducts] = useState<Product[]>([]);
  const [components, setComponents] = useState<Component[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [deleteModal, setDeleteModal] = useState<{ show: boolean; product?: Product }>({ show: false });
  const [searchTerm, setSearchTerm] = useState('');
  const [expandedProductId, setExpandedProductId] = useState<number | null>(null);
  const [exportModalOpen, setExportModalOpen] = useState(false);
  const [selectedProduct, setSelectedProduct] = useState<Product | null>(null);
  const [componentOrder, setComponentOrder] = useState<number[]>([]);

  useEffect(() => {
    fetchProducts();
    fetchComponents();
  }, []);

  const fetchProducts = async () => {
    try {
      setLoading(true);
      const data = await productsService.getAll();
      setProducts(data);
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

  const toggleProductExpansion = (productId: number) => {
    setExpandedProductId(expandedProductId === productId ? null : productId);
  };

  const handleExportClick = (product: Product) => {
    setSelectedProduct(product);
    setComponentOrder(product.components.map(c => c.componentId));
    setExportModalOpen(true);
  };

  const handleConfirmExport = () => {
    if (!selectedProduct) return;

    // Preparar dados para exportação com ordem customizada
    const orderedComponents = componentOrder.map(compId => {
      const pc = selectedProduct.components.find(c => c.componentId === compId);
      const component = components.find(c => c.id === compId);
      
      if (!pc || !component) return null;

      return {
        componentName: pc.componentName,
        device: component.device,
        value: component.value,
        package: component.package,
        characteristics: component.characteristics,
        internalCode: component.internalCode,
        drawer: component.drawer,
        division: component.division,
        quantityPerUnit: pc.quantity,
        totalQuantityNeeded: pc.quantity,
        quantityInStock: component.quantityInStock,
        suggestedPurchase: Math.max(0, pc.quantity - component.quantityInStock),
        unitPrice: component.price,
        totalPrice: (component.price || 0) * pc.quantity
      };
    }).filter(Boolean);

    const exportData = {
      productName: selectedProduct.name,
      unitsToManufacture: 1,
      components: orderedComponents as any[]
    };

    exportService.exportProductionReport(exportData);
    setSuccess('Relatório exportado com sucesso!');
    setExportModalOpen(false);
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

  const calculateProductTotal = (product: Product) => {
    return product.components.reduce((sum, pc) => {
      const component = components.find(c => c.id === pc.componentId);
      const price = component?.price || 0;
      return sum + (price * pc.quantity);
    }, 0);
  };

  const filteredProducts = products.filter(p =>
    p.name.toLowerCase().includes(searchTerm.toLowerCase())
  );

  if (loading) {
    return (
      <div className="p-6">
        <LoadingSpinner fullScreen message="Carregando produtos..." />
      </div>
    );
  }

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
          <button
            onClick={() => navigate('/products/new')}
            className="flex items-center gap-2 px-4 py-2.5 bg-gradient-to-r from-green-500 to-green-600 text-white rounded-lg hover:from-green-600 hover:to-green-700 transition-all duration-200 shadow-sm"
          >
            <Plus size={18} />
            <span className="font-medium">Novo Produto</span>
          </button>
        </div>
      </div>

      {/* Messages */}
      {error && <ErrorMessage message={error} onClose={() => setError('')} className="mb-6" />}
      {success && <SuccessMessage message={success} onClose={() => setSuccess('')} className="mb-6" />}

      {/* Search */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" size={18} />
          <input
            type="text"
            placeholder="Buscar produtos por nome..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200"
          />
        </div>
      </div>

      {/* Products List */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200">
        {filteredProducts.length === 0 ? (
          <div className="p-12 text-center">
            <Package className="mx-auto mb-4 text-gray-400" size={48} />
            <p className="text-lg font-medium text-gray-600">Nenhum produto encontrado</p>
            <p className="text-sm text-gray-500 mt-1">
              {searchTerm 
                ? "Tente ajustar sua busca" 
                : "Crie seu primeiro produto clicando no botão acima"}
            </p>
          </div>
        ) : (
          <div className="divide-y divide-gray-200">
            {filteredProducts.map((product) => (
              <div key={product.id}>
                {/* Produto Linha Compacta */}
                <div
                  onClick={() => toggleProductExpansion(product.id)}
                  className="p-4 hover:bg-gray-50 cursor-pointer transition-colors"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4">
                      <ChevronDown 
                        size={20} 
                        className={`text-gray-400 transition-transform ${
                          expandedProductId === product.id ? 'rotate-180' : ''
                        }`}
                      />
                      <div>
                        <h3 className="font-semibold text-gray-900">{product.name}</h3>
                        <p className="text-sm text-gray-500">{product.description}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-6">
                      <div className="flex items-center gap-2 text-sm text-gray-500">
                        <Cpu size={16} />
                        <span>{product.components.length} componentes</span>
                      </div>
                      <div className="text-right">
                        <p className="text-xs text-gray-500">Valor Fixado</p>
                        <p className="font-semibold text-gray-900">{formatCurrency(calculateProductTotal(product))}</p>
                      </div>
                      <div className="flex items-center gap-2">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            navigate(`/products/${product.id}/edit`);
                          }}
                          className="p-2 text-blue-600 hover:bg-blue-50 rounded-lg"
                        >
                          <Pencil size={18} />
                        </button>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setDeleteModal({ show: true, product });
                          }}
                          className="p-2 text-red-600 hover:bg-red-50 rounded-lg"
                        >
                          <Trash2 size={18} />
                        </button>
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-4 mt-2 text-xs text-gray-500">
                    <div className="flex items-center gap-1">
                      <Calendar size={12} />
                      Criado em {formatDate(product.createdAt)}
                    </div>
                    {product.createdBy && <span>Por {product.createdBy}</span>}
                  </div>
                </div>

                {/* Dropdown Expandido */}
                {expandedProductId === product.id && (
                  <ProductionReport
                    product={product}
                    components={components}
                    onExport={() => handleExportClick(product)}
                  />
                )}
              </div>
            ))}
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
      {selectedProduct && (
        <ExportModal
          isOpen={exportModalOpen}
          onClose={() => setExportModalOpen(false)}
          product={selectedProduct}
          components={components}
          productOrder={componentOrder}
          onUpdateOrder={setComponentOrder}
          onConfirmExport={handleConfirmExport}
        />
      )}
    </div>
  );
};

export default ProductsListPage;