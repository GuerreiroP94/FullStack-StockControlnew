import React from 'react';
import {
  X,
  Package,
  DollarSign,
  Calendar,
  AlertCircle,
  TrendingUp,
  TrendingDown,
  History,
  Cpu,
  Calculator
} from 'lucide-react';
import { Component } from '../../types';
import { formatCurrency, formatDateTime } from '../../utils/helpers';

interface ProductPreviewProps {
  product: any; // ProductWithPriority
  components: Component[];
  onClose: () => void;
}

const ProductPreview: React.FC<ProductPreviewProps> = ({ product, components, onClose }) => {
  const getComponentDetails = (componentId: number) => {
    return components.find(c => c.id === componentId);
  };

  const calculateCurrentProduction = () => {
    const calculation = product.components.map((comp: any) => {
      const component = getComponentDetails(comp.componentId);
      if (!component) return null;

      const totalPrice = (component.price || 0) * comp.quantity;
      return {
        ...comp,
        component,
        unitPrice: component.price || 0,
        totalPrice,
        currentStock: component.quantityInStock,
        status: component.quantityInStock < comp.quantity ? 'insufficient' : 'ok'
      };
    }).filter(Boolean);

    const totalCost = calculation.reduce((sum: number, item: any) => sum + item.totalPrice, 0);
    
    return { calculation, totalCost };
  };

  const currentProduction = calculateCurrentProduction();
  const hasFixedCalculation = !!product.fixedCalculation;
  const priceDifference = hasFixedCalculation 
    ? currentProduction.totalCost - product.fixedCalculation.totalCost 
    : 0;

  return (
    <div className="bg-gray-50 border-t-4 border-blue-500">
      <div className="p-6">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-lg font-semibold text-gray-800 flex items-center gap-2">
            <Package size={20} />
            Detalhes do Produto: {product.name}
          </h3>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600"
          >
            <X size={20} />
          </button>
        </div>

        {/* Informações Gerais */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          <div className="bg-white rounded-lg p-4 border border-gray-200">
            <p className="text-sm text-gray-500 mb-1">Criado em</p>
            <p className="text-sm font-medium text-gray-900">
              {formatDateTime(product.createdAt)}
            </p>
          </div>
          <div className="bg-white rounded-lg p-4 border border-gray-200">
            <p className="text-sm text-gray-500 mb-1">Criado por</p>
            <p className="text-sm font-medium text-gray-900">
              {product.createdBy || 'Sistema'}
            </p>
          </div>
          <div className="bg-white rounded-lg p-4 border border-gray-200">
            <p className="text-sm text-gray-500 mb-1">Total de Componentes</p>
            <p className="text-sm font-medium text-gray-900">
              {product.components.length} componentes
            </p>
          </div>
        </div>

        {/* Valores de Produção */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
          {/* Cálculo Fixado */}
          {hasFixedCalculation && (
            <div className="bg-white rounded-lg p-4 border border-gray-200">
              <div className="flex items-center justify-between mb-2">
                <h4 className="text-sm font-semibold text-gray-700 flex items-center gap-2">
                  <DollarSign size={16} />
                  Valor Fixado (Inicial)
                </h4>
                <span className="text-xs text-gray-500">
                  {formatDateTime(product.fixedCalculation.calculatedAt)}
                </span>
              </div>
              <p className="text-2xl font-bold text-green-600">
                {formatCurrency(product.fixedCalculation.totalCost)}
              </p>
            </div>
          )}

          {/* Cálculo Atual */}
          <div className="bg-white rounded-lg p-4 border border-gray-200">
            <div className="flex items-center justify-between mb-2">
              <h4 className="text-sm font-semibold text-gray-700 flex items-center gap-2">
                <Calculator size={16} />
                Valor Atual
              </h4>
              {priceDifference !== 0 && (
                <span className={`text-xs font-medium flex items-center gap-1 ${
                  priceDifference > 0 ? 'text-red-600' : 'text-green-600'
                }`}>
                  {priceDifference > 0 ? <TrendingUp size={14} /> : <TrendingDown size={14} />}
                  {priceDifference > 0 ? '+' : ''}{formatCurrency(priceDifference)}
                </span>
              )}
            </div>
            <p className="text-2xl font-bold text-gray-900">
              {formatCurrency(currentProduction.totalCost)}
            </p>
          </div>
        </div>

        {/* Tabela de Componentes */}
        <div className="bg-white rounded-lg border border-gray-200 overflow-hidden mb-6">
          <div className="px-4 py-3 bg-gray-50 border-b border-gray-200">
            <h4 className="text-sm font-semibold text-gray-700 flex items-center gap-2">
              <Cpu size={16} />
              Componentes Utilizados
            </h4>
          </div>
          <div className="overflow-x-auto">
            <table className="min-w-full">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">
                    Componente
                  </th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">
                    Device / Value
                  </th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">
                    Package
                  </th>
                  <th className="px-4 py-2 text-right text-xs font-medium text-gray-500 uppercase">
                    Qtd/Un
                  </th>
                  <th className="px-4 py-2 text-right text-xs font-medium text-gray-500 uppercase">
                    Preço Unit.
                  </th>
                  <th className="px-4 py-2 text-right text-xs font-medium text-gray-500 uppercase">
                    Total
                  </th>
                  <th className="px-4 py-2 text-right text-xs font-medium text-gray-500 uppercase">
                    Estoque
                  </th>
                  <th className="px-4 py-2 text-center text-xs font-medium text-gray-500 uppercase">
                    Status
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200">
                {currentProduction.calculation.map((item: any, index: number) => (
                  <tr key={index} className="hover:bg-gray-50">
                    <td className="px-4 py-3 text-sm font-medium text-gray-900">
                      {item.componentName}
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-600">
                      {item.component.device} / {item.component.value}
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-600">
                      {item.component.package || '-'}
                    </td>
                    <td className="px-4 py-3 text-sm text-right">
                      {item.quantity}
                    </td>
                    <td className="px-4 py-3 text-sm text-right">
                      {formatCurrency(item.unitPrice)}
                    </td>
                    <td className="px-4 py-3 text-sm text-right font-medium">
                      {formatCurrency(item.totalPrice)}
                    </td>
                    <td className="px-4 py-3 text-sm text-right">
                      <span className={`font-medium ${
                        item.currentStock < item.quantity ? 'text-red-600' : 'text-gray-900'
                      }`}>
                        {item.currentStock}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-center">
                      {item.status === 'insufficient' ? (
                        <span className="inline-flex items-center gap-1 px-2 py-1 text-xs bg-red-100 text-red-800 rounded-full">
                          <AlertCircle size={12} />
                          Insuficiente
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2 py-1 text-xs bg-green-100 text-green-800 rounded-full">
                          OK
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
              <tfoot className="bg-gray-50">
                <tr>
                  <td colSpan={5} className="px-4 py-3 text-sm font-medium text-right">
                    Total Geral:
                  </td>
                  <td className="px-4 py-3 text-sm font-bold text-right">
                    {formatCurrency(currentProduction.totalCost)}
                  </td>
                  <td colSpan={2}></td>
                </tr>
              </tfoot>
            </table>
          </div>
        </div>

        {/* Histórico de Cálculos */}
        {product.calculationHistory && product.calculationHistory.length > 0 && (
          <div className="bg-white rounded-lg border border-gray-200 p-4">
            <h4 className="text-sm font-semibold text-gray-700 flex items-center gap-2 mb-3">
              <History size={16} />
              Histórico de Recálculos
            </h4>
            <div className="space-y-2">
              {product.calculationHistory.map((history: any) => (
                <div key={history.id} className="flex items-center justify-between p-2 bg-gray-50 rounded">
                  <span className="text-sm text-gray-600">
                    {formatDateTime(history.calculatedAt)}
                  </span>
                  <span className="text-sm font-medium text-gray-900">
                    {formatCurrency(history.totalCost)}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ProductPreview;