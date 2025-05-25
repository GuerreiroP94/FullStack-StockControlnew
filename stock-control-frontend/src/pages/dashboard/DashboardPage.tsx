import React, { useEffect, useState } from 'react';
import { Package, AlertCircle, TrendingUp, Users, ArrowUp, ArrowDown } from 'lucide-react';
import StatsCard from '../../components/dashboard/StatsCard';
import AlertsList from '../../components/dashboard/AlertsList';
import RecentMovements from '../../components/dashboard/RecentMovements';
import componentsService from '../../services/components.service';
import productsService from '../../services/products.service';
import movementsService from '../../services/movements.service';
import alertsService from '../../services/alerts.service';
import { StockAlert, StockMovement, Component, Product } from '../../types';
import { useAuth } from '../../contexts/AuthContext';

interface DashboardStats {
  totalComponents: number;
  totalProducts: number;
  lowStockItems: number;
  todayMovements: number;
  totalUsers?: number;
}

const DashboardPage: React.FC = () => {
  const { user, isAdmin } = useAuth();
  const [stats, setStats] = useState<DashboardStats>({
    totalComponents: 0,
    totalProducts: 0,
    lowStockItems: 0,
    todayMovements: 0,
    totalUsers: 0
  });
  const [alerts, setAlerts] = useState<StockAlert[]>([]);
  const [movements, setMovements] = useState<StockMovement[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      
      // Fetch all data in parallel
      const [componentsData, productsData, alertsData, movementsData] = await Promise.all([
        componentsService.getAll(),
        productsService.getAll(),
        alertsService.getAll({ page: 1, pageSize: 10 }),
        movementsService.getAll({ page: 1, pageSize: 10 })
      ]);

      // Calculate stats
      const lowStock = componentsData.filter((c: Component) => 
        c.quantityInStock <= c.minimumQuantity
      ).length;

      const today = new Date().toDateString();
      const todayMovs = movementsData.filter((m: StockMovement) => 
        new Date(m.movementDate).toDateString() === today
      ).length;

      setStats({
        totalComponents: componentsData.length,
        totalProducts: productsData.length,
        lowStockItems: lowStock,
        todayMovements: todayMovs,
        totalUsers: isAdmin ? 5 : undefined // Mock for now
      });

      setAlerts(alertsData);
      setMovements(movementsData);
    } catch (error) {
      console.error('Error fetching dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-6">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-800">Dashboard</h1>
        <p className="text-gray-600">Bem-vindo de volta, {user?.name}!</p>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-6">
        <StatsCard
          title="Total de Componentes"
          value={stats.totalComponents}
          icon={Package}
          iconBgColor="bg-blue-100"
          iconColor="text-blue-600"
        />
        
        <StatsCard
          title="Total de Produtos"
          value={stats.totalProducts}
          icon={Package}
          iconBgColor="bg-green-100"
          iconColor="text-green-600"
        />
        
        <StatsCard
          title="Estoque Baixo"
          value={stats.lowStockItems}
          subtitle="Itens abaixo do mínimo"
          icon={AlertCircle}
          iconBgColor="bg-red-100"
          iconColor="text-red-600"
        />
        
        <StatsCard
          title="Movimentações Hoje"
          value={stats.todayMovements}
          icon={TrendingUp}
          iconBgColor="bg-purple-100"
          iconColor="text-purple-600"
        />
      </div>

      {/* Alerts and Movements */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <AlertsList alerts={alerts} loading={loading} />
        <RecentMovements movements={movements} loading={loading} />
      </div>

      {/* Admin Stats */}
      {isAdmin && (
        <div className="mt-6 grid grid-cols-1 md:grid-cols-3 gap-6">
          <StatsCard
            title="Usuários Ativos"
            value={stats.totalUsers || 0}
            icon={Users}
            iconBgColor="bg-indigo-100"
            iconColor="text-indigo-600"
          />
          
          <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
            <h3 className="text-lg font-semibold text-gray-800 mb-4">Atividade do Sistema</h3>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">Entradas hoje</span>
                <span className="text-sm font-medium text-green-600 flex items-center gap-1">
                  <ArrowUp size={16} />
                  12
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">Saídas hoje</span>
                <span className="text-sm font-medium text-red-600 flex items-center gap-1">
                  <ArrowDown size={16} />
                  8
                </span>
              </div>
            </div>
          </div>
          
          <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
            <h3 className="text-lg font-semibold text-gray-800 mb-4">Taxa de Ocupação</h3>
            <div className="relative h-32">
              <div className="absolute inset-0 flex items-center justify-center">
                <div className="text-center">
                  <p className="text-3xl font-bold text-gray-800">72%</p>
                  <p className="text-sm text-gray-500">do estoque</p>
                </div>
              </div>
              <svg className="w-full h-full transform -rotate-90">
                <circle
                  cx="64"
                  cy="64"
                  r="56"
                  stroke="currentColor"
                  strokeWidth="8"
                  fill="none"
                  className="text-gray-200"
                />
                <circle
                  cx="64"
                  cy="64"
                  r="56"
                  stroke="currentColor"
                  strokeWidth="8"
                  fill="none"
                  strokeDasharray={`${2 * Math.PI * 56 * 0.72} ${2 * Math.PI * 56}`}
                  className="text-blue-600"
                />
              </svg>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default DashboardPage;