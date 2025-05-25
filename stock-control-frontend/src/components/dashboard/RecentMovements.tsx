import React from 'react';
import { TrendingUp, TrendingDown, ChevronRight, Package } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { StockMovement } from '../../types';
import { formatDateTime } from '../../utils/helpers';

interface RecentMovementsProps {
  movements: StockMovement[];
  loading?: boolean;
  limit?: number;
}

const RecentMovements: React.FC<RecentMovementsProps> = ({ movements, loading = false, limit = 5 }) => {
  const navigate = useNavigate();
  const displayMovements = limit ? movements.slice(0, limit) : movements;

  if (loading) {
    return (
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
        <div className="animate-pulse">
          <div className="h-6 bg-gray-200 rounded w-40 mb-4"></div>
          <div className="space-y-3">
            {[1, 2, 3, 4, 5].map((i) => (
              <div key={i} className="h-12 bg-gray-100 rounded"></div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-xl shadow-sm border border-gray-200">
      <div className="p-6 border-b border-gray-200">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-blue-100 rounded-xl flex items-center justify-center">
              <TrendingUp className="text-blue-600" size={20} />
            </div>
            <h2 className="text-lg font-semibold text-gray-800">Movimentações Recentes</h2>
          </div>
          <button
            onClick={() => navigate('/movements')}
            className="text-sm text-blue-600 hover:text-blue-700 flex items-center gap-1"
          >
            Ver todas
            <ChevronRight size={16} />
          </button>
        </div>
      </div>

      <div className="divide-y divide-gray-200">
        {displayMovements.length === 0 ? (
          <div className="p-6 text-center">
            <Package className="mx-auto mb-3 text-gray-400" size={40} />
            <p className="text-gray-500">Nenhuma movimentação registrada</p>
          </div>
        ) : (
          displayMovements.map((movement) => (
            <div
              key={movement.id}
              className="p-4 hover:bg-gray-50 transition-colors cursor-pointer"
              onClick={() => navigate('/movements')}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className={`w-8 h-8 rounded-full flex items-center justify-center ${
                    movement.movementType === 'Entrada' 
                      ? 'bg-green-100' 
                      : 'bg-red-100'
                  }`}>
                    {movement.movementType === 'Entrada' ? (
                      <TrendingUp className="text-green-600" size={16} />
                    ) : (
                      <TrendingDown className="text-red-600" size={16} />
                    )}
                  </div>
                  <div>
                    <p className="text-sm font-medium text-gray-800">
                      Componente #{movement.componentId}
                    </p>
                    <p className="text-xs text-gray-500">
                      Por {movement.performedBy} • {formatDateTime(movement.movementDate)}
                    </p>
                  </div>
                </div>
                <div className={`text-sm font-medium ${
                  movement.movementType === 'Entrada' 
                    ? 'text-green-600' 
                    : 'text-red-600'
                }`}>
                  {movement.movementType === 'Entrada' ? '+' : '-'}{movement.quantity}
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default RecentMovements;