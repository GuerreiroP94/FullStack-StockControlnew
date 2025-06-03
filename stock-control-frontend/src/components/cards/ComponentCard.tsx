import React from 'react';
import { Cpu, Package, MapPin, AlertCircle } from 'lucide-react';
import { Component } from '../../types';
import { formatCurrency } from '../../utils/helpers';

interface ComponentCardProps {
  component: Component;
  onClick?: () => void;
  selected?: boolean;
  showActions?: boolean;
  onActionClick?: (action: 'edit' | 'delete' | 'view') => void;
  compact?: boolean;
}

const ComponentCard: React.FC<ComponentCardProps> = ({
  component,
  onClick,
  selected = false,
  showActions = false,
  onActionClick,
  compact = false
}) => {
  const isLowStock = component.quantityInStock <= component.minimumQuantity;
  const isOutOfStock = component.quantityInStock === 0;

  const getStockStatus = () => {
    if (isOutOfStock) return { color: 'red', text: 'Sem Estoque' };
    if (isLowStock) return { color: 'yellow', text: 'Estoque Baixo' };
    return { color: 'green', text: 'Em Estoque' };
  };

  const stockStatus = getStockStatus();

  if (compact) {
    return (
      <div
        onClick={onClick}
        className={`p-3 border rounded-lg cursor-pointer transition-all ${
          selected ? 'border-blue-500 bg-blue-50' : 'border-gray-200 hover:border-gray-300'
        }`}
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Cpu className="text-gray-400" size={16} />
            <div>
              <p className="text-sm font-medium text-gray-900">{component.name}</p>
              <p className="text-xs text-gray-500">{component.group}</p>
            </div>
          </div>
          <span className={`text-xs px-2 py-1 rounded-full bg-${stockStatus.color}-100 text-${stockStatus.color}-800`}>
            {component.quantityInStock}
          </span>
        </div>
      </div>
    );
  }

  return (
    <div
      onClick={onClick}
      className={`p-4 border rounded-lg transition-all ${
        selected 
          ? 'border-blue-500 bg-blue-50 shadow-md' 
          : 'border-gray-200 hover:border-gray-300 hover:shadow-sm'
      } ${onClick ? 'cursor-pointer' : ''}`}
    >
      {/* Header */}
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-start gap-3">
          <div className="w-10 h-10 bg-gray-100 rounded-lg flex items-center justify-center">
            <Cpu className="text-gray-600" size={20} />
          </div>
          <div className="flex-1">
            <h3 className="font-medium text-gray-900">{component.name}</h3>
            {component.internalCode && (
              <p className="text-xs text-gray-500">Código: {component.internalCode}</p>
            )}
          </div>
        </div>
        {showActions && (
          <div className="flex gap-1">
            <button
              onClick={(e) => {
                e.stopPropagation();
                onActionClick?.('view');
              }}
              className="p-1 text-gray-400 hover:text-gray-600"
            >
              👁️
            </button>
            <button
              onClick={(e) => {
                e.stopPropagation();
                onActionClick?.('edit');
              }}
              className="p-1 text-gray-400 hover:text-gray-600"
            >
              ✏️
            </button>
            <button
              onClick={(e) => {
                e.stopPropagation();
                onActionClick?.('delete');
              }}
              className="p-1 text-gray-400 hover:text-red-600"
            >
              🗑️
            </button>
          </div>
        )}
      </div>

      {/* Tags */}
      <div className="flex flex-wrap gap-2 mb-3">
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
      </div>

      {/* Info Grid */}
      <div className="grid grid-cols-2 gap-2 text-xs">
        <div className="flex items-center gap-1">
          <Package size={14} className="text-gray-400" />
          <span className={`font-medium ${
            isOutOfStock ? 'text-red-600' : isLowStock ? 'text-yellow-600' : 'text-gray-600'
          }`}>
            Estoque: {component.quantityInStock}
          </span>
        </div>
        <div className="flex items-center gap-1">
          <AlertCircle size={14} className="text-gray-400" />
          <span className="text-gray-600">Mín: {component.minimumQuantity}</span>
        </div>
        {component.drawer && component.division && (
          <div className="flex items-center gap-1 col-span-2">
            <MapPin size={14} className="text-gray-400" />
            <span className="text-gray-600">
              {component.drawer}/{component.division}
            </span>
          </div>
        )}
        {component.price !== undefined && component.price > 0 && (
          <div className="col-span-2 text-gray-600">
            Preço: {formatCurrency(component.price)}
          </div>
        )}
      </div>

      {/* Status Badge */}
      <div className="mt-3 pt-3 border-t border-gray-100">
        <span className={`inline-flex items-center gap-1 text-xs px-2 py-1 rounded-full bg-${stockStatus.color}-100 text-${stockStatus.color}-800`}>
          <div className={`w-2 h-2 rounded-full bg-${stockStatus.color}-500`} />
          {stockStatus.text}
        </span>
      </div>
    </div>
  );
};

export default ComponentCard;