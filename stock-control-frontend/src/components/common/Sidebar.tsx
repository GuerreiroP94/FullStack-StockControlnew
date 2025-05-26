import React from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import {
  LayoutDashboard,
  Package,
  ShoppingCart,
  TrendingUpDown,
  AlertCircle,
  Users,
  ChevronLeft,
  ChevronRight,
  Cpu,
  Settings,
  LogOut,
  User
} from 'lucide-react';
import { useAuth } from '../../contexts/AuthContext';
import { getInitials } from '../../utils/helpers';

interface SidebarProps {
  isOpen: boolean;
  toggleSidebar: () => void;
}

const Sidebar: React.FC<SidebarProps> = ({ isOpen, toggleSidebar }) => {
  const { isAdmin, user, logout } = useAuth();
  const navigate = useNavigate();

  const menuItems = [
    {
      path: '/dashboard',
      name: 'Dashboard',
      icon: LayoutDashboard,
      show: true
    },
    {
      path: '/components',
      name: 'Componentes',
      icon: Cpu,
      show: true
    },
    {
      path: '/products',
      name: 'Produtos',
      icon: Package,
      show: true
    },
    {
      path: '/movements',
      name: 'Movimentações',
      icon: TrendingUpDown,
      show: true
    },
    {
      path: '/alerts',
      name: 'Alertas',
      icon: AlertCircle,
      show: true
    },
    {
      path: '/users',
      name: 'Usuários',
      icon: Users,
      show: isAdmin
    }
  ];

  const filteredMenuItems = menuItems.filter(item => item.show);

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <aside className={`fixed left-0 top-0 h-full bg-white shadow-lg transition-all duration-300 z-30 ${
      isOpen ? 'w-64' : 'w-16'
    }`}>
      <div className="flex flex-col h-full">
        {/* Logo */}
        <div className="h-16 flex items-center justify-between px-4 border-b border-gray-200">
          {isOpen && (
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 bg-gradient-to-br from-blue-500 to-blue-600 rounded-lg flex items-center justify-center">
                <Package className="text-white" size={18} />
              </div>
              <span className="font-bold text-gray-800">PreSystem</span>
            </div>
          )}
          <button
            onClick={toggleSidebar}
            className="p-1.5 rounded-lg hover:bg-gray-100 transition-colors"
          >
            {isOpen ? <ChevronLeft size={20} /> : <ChevronRight size={20} />}
          </button>
        </div>

        {/* User Info Section */}
        {isOpen && (
          <div className="p-4 border-b border-gray-200">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-blue-500 rounded-full flex items-center justify-center text-white font-medium">
                {user && getInitials(user.name)}
              </div>
              <div>
                <p className="text-sm font-medium text-gray-800">{user?.name}</p>
                <p className="text-xs text-gray-500">
                  {user?.role === 'admin' ? 'Administrador' : 'Operador'}
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Menu Items */}
        <nav className="flex-1 py-4 px-2 overflow-y-auto">
          {filteredMenuItems.map((item) => (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) => `
                flex items-center gap-3 px-3 py-2.5 mb-1 rounded-lg transition-all duration-200
                ${isActive 
                  ? 'bg-blue-50 text-blue-600' 
                  : 'text-gray-600 hover:bg-gray-100 hover:text-gray-800'
                }
              `}
              title={!isOpen ? item.name : undefined}
            >
              <item.icon size={20} />
              {isOpen && <span className="font-medium">{item.name}</span>}
            </NavLink>
          ))}
        </nav>

        {/* Bottom Section - Settings and Logout */}
        <div className="border-t border-gray-200">
          <nav className="p-2">
            <NavLink
              to="/settings"
              className={({ isActive }) => `
                flex items-center gap-3 px-3 py-2.5 mb-1 rounded-lg transition-all duration-200
                ${isActive 
                  ? 'bg-blue-50 text-blue-600' 
                  : 'text-gray-600 hover:bg-gray-100 hover:text-gray-800'
                }
              `}
              title={!isOpen ? 'Configurações' : undefined}
            >
              <Settings size={20} />
              {isOpen && <span className="font-medium">Configurações</span>}
            </NavLink>
            
            <button
              onClick={handleLogout}
              className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all duration-200 text-red-600 hover:bg-red-50"
              title={!isOpen ? 'Sair' : undefined}
            >
              <LogOut size={20} />
              {isOpen && <span className="font-medium">Sair</span>}
            </button>
          </nav>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-gray-200">
          {isOpen ? (
            <div className="text-xs text-gray-500">
              <p>© 2024 PreSystem</p>
              <p>Versão 1.0.0</p>
            </div>
          ) : (
            <div className="w-8 h-8 bg-gray-100 rounded-full animate-pulse"></div>
          )}
        </div>
      </div>
    </aside>
  );
};

export default Sidebar;