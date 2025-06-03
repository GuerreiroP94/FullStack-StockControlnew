import React from 'react';
import { Package, AlertTriangle, XCircle } from 'lucide-react';

interface StockIndicatorProps {
  current: number;
  minimum: number;
  showLabel?: boolean;
  size?: 'sm' | 'md' | 'lg';
}

const StockIndicator: React.FC<StockIndicatorProps> = ({
  current,
  minimum,
  showLabel = true,
  size = 'md'
}) => {
  const getStatus = () => {
    if (current === 0) return 'critical';
    if (current <= minimum) return 'low';
    return 'normal';
  };

  const status = getStatus();

  const config = {
    critical: {
      icon: XCircle,
      color: 'red',
      bgColor: 'bg-red-100',
      textColor: 'text-red-800',
      iconColor: 'text-red-600',
      label: 'Sem Estoque'
    },
    low: {
      icon: AlertTriangle,
      color: 'yellow',
      bgColor: 'bg-yellow-100',
      textColor: 'text-yellow-800',
      iconColor: 'text-yellow-600',
      label: 'Estoque Baixo'
    },
    normal: {
      icon: Package,
      color: 'green',
      bgColor: 'bg-green-100',
      textColor: 'text-green-800',
      iconColor: 'text-green-600',
      label: 'Em Estoque'
    }
  };

  const { icon: Icon, bgColor, textColor, iconColor, label } = config[status];

  const sizeClasses = {
    sm: 'text-xs px-2 py-1',
    md: 'text-sm px-2.5 py-1.5',
    lg: 'text-base px-3 py-2'
  };

  return (
    <div className={`inline-flex items-center gap-1.5 ${bgColor} ${textColor} rounded-full ${sizeClasses[size]}`}>
      <Icon className={iconColor} size={size === 'sm' ? 14 : size === 'md' ? 16 : 18} />
      <span className="font-medium">{current}</span>
      {showLabel && <span>• {label}</span>}
    </div>
  );
};

export default StockIndicator;