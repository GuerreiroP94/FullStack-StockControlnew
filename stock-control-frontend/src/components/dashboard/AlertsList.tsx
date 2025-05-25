import React from 'react';
import { AlertCircle, ChevronRight, Package } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { StockAlert } from '../../types';
import { formatDateTime } from '../../utils/helpers';

interface AlertsListProps {
  alerts: StockAlert[];
  loading?: boolean;
  limit?: number;
}

const AlertsList: React.FC<AlertsListProps> = ({ alerts, loading = false, limit = 5 }) => {
  const navigate = useNavigate();
  const displayAlerts = limit ? alerts.slice(0, limit) : alerts;

  if (loading) {
    return (
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
        <div className="animate-pulse">
          <div className="h-6 bg-gray-200 rounded w-32 mb-4"></div>
          <div className="space-y-3">
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-16 bg-gray-100 rounded"></div>
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
            <div className="w-10 h-10 bg-red-100 rounded-xl flex items-center justify-center">
              <AlertCircle className="text-red-600" size={20} />
            </div>
            <h2 className="text-lg font-semibold text-gray-800">Alertas de Estoque</h2>
          </div>
          <button
            onClick={() => navigate('/alerts')}
            className="text-sm text-blue-600 hover:text-blue-700 flex items-center gap-1"
          >
            Ver todos
            <ChevronRight size={16} />
          </button>
        </div>
      </div>

      <div className="p-6">
        {displayAlerts.length === 0 ? (
          <div className="text-center py-8">
            <Package className="mx-auto mb-3 text-gray-400" size={40} />
            <p className="text-gray-500">Nenhum alerta de estoque no momento</p>
          </div>
        ) : (
          <div className="space-y-3">
            {displayAlerts.map((alert) => (
              <div
                key={alert.id}
                className="p-4 bg-red-50 border border-red-200 rounded-lg hover:bg-red-100 transition-colors cursor-pointer"
                onClick={() => navigate(`/components`)}
              >
                <p className="text-sm font-medium text-red-800">{alert.message}</p>
                <p className="text-xs text-red-600 mt-1">{formatDateTime(alert.createdAt)}</p>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default AlertsList;