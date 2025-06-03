import React, { useState, useEffect } from 'react';
import { X, GripVertical, Check } from 'lucide-react';
import BaseModal from '../common/BaseModal';
import { Component, Product, ProductComponentCreate } from '../../types';

interface ExportModalProps {
  isOpen: boolean;
  onClose: () => void;
  product: Product | { name: string; components: ProductComponentCreate[] };
  components: Component[];
  productOrder: number[];
  onUpdateOrder: (order: number[]) => void;
  onConfirmExport: () => void;
}

const ExportModal: React.FC<ExportModalProps> = ({
  isOpen,
  onClose,
  product,
  components,
  productOrder,
  onUpdateOrder,
  onConfirmExport
}) => {
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

  // Type guard to check if product has proper components structure
  const getProductComponents = () => {
    if ('components' in product && Array.isArray(product.components)) {
      return product.components;
    }
    return [];
  };

  return (
    <BaseModal 
  isOpen={isOpen} 
  onClose={onClose}
  title={product.name}
  size="xl"
  className=""
>
      <div className="flex-1 overflow-y-auto p-6">
        <p className="text-sm text-gray-500 mb-4">Defina a ordem dos componentes para exportação</p>
        
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
                const productComponents = getProductComponents();
                const pc = productComponents.find((c: any) => c.componentId === compId);
                if (!pc) return null;
                
                const component = getComponentDetails(pc.componentId);
                if (!component) return null;

                const quantity = 'quantity' in pc ? pc.quantity : 0;
                const needToBuy = Math.max(0, quantity - component.quantityInStock);

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
                    <td className="px-4 py-3 text-sm">{quantity}</td>
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
    </BaseModal>
  );
};

export default ExportModal;