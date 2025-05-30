import React, { useState } from 'react';
import { NavLink, useLocation, useNavigate } from 'react-router-dom';
import {
  LayoutDashboard,
  Package,
  TrendingUpDown,
  AlertCircle,
  Users,
  ChevronLeft,
  ChevronRight,
  ChevronDown,
  Cpu,
  ShoppingBag,
  PlusCircle,
  Settings,
  LogOut,
  User,
  Wrench
} from 'lucide-react';
import { useAuth } from '../../contexts/AuthContext';

interface SidebarProps {
  isOpen: boolean;
  toggleSidebar: () => void;
}

const Sidebar: React.FC<SidebarProps> = ({ isOpen, toggleSidebar }) => {
  const { isAdmin, logout, user } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const [productsSubmenuOpen, setProductsSubmenuOpen] = useState(false);
  const [componentsSubmenuOpen, setComponentsSubmenuOpen] = useState(false);

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

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
      show: true,
      hasSubmenu: true,
      submenu: [
        {
          path: '/components',
          name: 'Lista de Componentes',
          icon: Cpu
        },
        {
          path: '/components/maintenance',
          name: 'Manutenção de Grupos',
          icon: Wrench
        }
      ]
    },
    {
      path: '/products',
      name: 'Produtos',
      icon: Package,
      show: true,
      hasSubmenu: true,
      submenu: [
        {
          path: '/products',
          name: 'Produtos Criados',
          icon: ShoppingBag
        },
        {
          path: '/products/new',
          name: 'Criar Produto',
          icon: PlusCircle
        }
      ]
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
  const isProductsActive = location.pathname.startsWith('/products');
  const isComponentsActive = location.pathname.startsWith('/components');

  // Função para obter as iniciais do nome
  const getInitials = (name: string) => {
    return name
      .split(' ')
      .map(word => word[0])
      .join('')
      .toUpperCase()
      .slice(0, 2);
  };

  return (
    <aside className={`fixed left-0 top-0 h-full bg-white shadow-lg transition-all duration-300 z-30 flex flex-col ${
      isOpen ? 'w-64' : 'w-16'
    }`}>
      {/* Header com Logo */}
      <div className="h-16 flex items-center justify-between px-4 border-b border-gray-200">
        {isOpen ? (
          <>
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 bg-gradient-to-br from-blue-500 to-blue-600 rounded-lg flex items-center justify-center">
                <Package className="text-white" size={18} />
              </div>
              <span className="font-bold text-gray-800">PreSystem</span>
            </div>
            <button
              onClick={toggleSidebar}
              className="p-1.5 hover:bg-gray-100 rounded-lg transition-colors"
            >
              <ChevronLeft size={20} />
            </button>
          </>
        ) : (
          <button
            onClick={toggleSidebar}
            className="w-full flex items-center justify-center p-1.5 hover:bg-gray-100 rounded-lg transition-colors"
          >
            <ChevronRight size={20} />
          </button>
        )}
      </div>

      {/* User Avatar */}
      {user && (
        <div className={`flex items-center ${isOpen ? 'px-4 py-4' : 'px-2 py-4 justify-center'} border-b border-gray-200`}>
          <div className="flex items-center">
            <div className="w-10 h-10 bg-gradient-to-br from-blue-500 to-blue-600 rounded-full flex items-center justify-center text-white font-semibold">
              {user.name ? getInitials(user.name) : <User size={20} />}
            </div>
            {isOpen && (
              <div className="ml-3">
                <p className="text-sm font-semibold text-gray-900">{user.name}</p>
                <p className="text-xs text-gray-500">{user.email}</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Navigation Menu */}
      <nav className="flex-1 overflow-y-auto py-4">
        <div className="space-y-1 px-3">
          {filteredMenuItems.map((item) => (
            <div key={item.path}>
              {item.hasSubmenu ? (
                <>
                  <button
                    onClick={() => {
                      if (item.name === 'Produtos') {
                        setProductsSubmenuOpen(!productsSubmenuOpen);
                      } else if (item.name === 'Componentes') {
                        setComponentsSubmenuOpen(!componentsSubmenuOpen);
                      }
                    }}
                    className={`w-full flex items-center ${isOpen ? 'justify-between' : 'justify-center'} gap-3 px-3 py-2.5 rounded-lg transition-all duration-200
                      ${(item.name === 'Produtos' && isProductsActive) || (item.name === 'Componentes' && isComponentsActive)
                        ? 'bg-blue-50 text-blue-600' 
                        : 'text-gray-700 hover:bg-gray-100'
                      }
                    `}
                    title={!isOpen ? item.name : undefined}
                  >
                    <div className={`flex items-center ${isOpen ? 'gap-3' : ''}`}>
                      <item.icon size={20} />
                      {isOpen && <span className="font-medium">{item.name}</span>}
                    </div>
                    {isOpen && (
                      <ChevronDown 
                        size={16} 
                        className={`transition-transform duration-200 ${
                          (item.name === 'Produtos' && productsSubmenuOpen) || 
                          (item.name === 'Componentes' && componentsSubmenuOpen) 
                            ? 'rotate-180' : ''
                        }`}
                      />
                    )}
                  </button>
                  
                  {isOpen && item.submenu && (
                    (item.name === 'Produtos' && productsSubmenuOpen) || 
                    (item.name === 'Componentes' && componentsSubmenuOpen)
                  ) && (
                    <div className="ml-9 mt-1 space-y-1">
                      {item.submenu.map((subItem) => (
                        <NavLink
                          key={subItem.path}
                          to={subItem.path}
                          end={subItem.path === '/products' || subItem.path === '/components'}
                          className={({ isActive }) => `
                            flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-all duration-200
                            ${isActive 
                              ? 'bg-blue-50 text-blue-600 font-medium' 
                              : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900'
                            }
                          `}
                        >
                          <subItem.icon size={16} />
                          <span>{subItem.name}</span>
                        </NavLink>
                      ))}
                    </div>
                  )}
                </>
              ) : (
                <NavLink
                  to={item.path}
                  className={({ isActive }) => `
                    flex items-center ${isOpen ? 'gap-3' : 'justify-center'} px-3 py-2.5 rounded-lg transition-all duration-200
                    ${isActive 
                      ? 'bg-blue-50 text-blue-600 font-medium' 
                      : 'text-gray-700 hover:bg-gray-100'
                    }
                  `}
                  title={!isOpen ? item.name : undefined}
                >
                  <item.icon size={20} />
                  {isOpen && <span>{item.name}</span>}
                </NavLink>
              )}
            </div>
          ))}
        </div>
      </nav>

      {/* Bottom Section */}
      <div className="border-t border-gray-200">
        <div className="px-3 py-2">
          {/* Settings */}
          <NavLink
            to="/settings"
            className={({ isActive }) => `
              flex items-center ${isOpen ? 'gap-3' : 'justify-center'} px-3 py-2.5 rounded-lg transition-all duration-200
              ${isActive 
                ? 'bg-blue-50 text-blue-600' 
                : 'text-gray-700 hover:bg-gray-100'
              }
            `}
            title={!isOpen ? "Configurações" : undefined}
          >
            <Settings size={20} />
            {isOpen && <span className="font-medium">Configurações</span>}
          </NavLink>

          {/* Logout */}
          <button
            onClick={handleLogout}
            className={`w-full flex items-center ${isOpen ? 'gap-3' : 'justify-center'} px-3 py-2.5 rounded-lg text-red-600 hover:bg-red-50 hover:text-red-700 transition-all duration-200`}
            title={!isOpen ? "Sair" : undefined}
          >
            <LogOut size={20} />
            {isOpen && <span className="font-medium">Sair</span>}
          </button>
        </div>

        {/* Footer - apenas quando expandido */}
        {isOpen && (
          <div className="px-4 py-3 bg-gray-50 border-t border-gray-200">
            <div className="text-xs text-gray-500 text-center">
              <p>© 2024 PreSystem</p>
              <p>Versão 1.0.0</p>
            </div>
          </div>
        )}
      </div>
    </aside>
  );
};

export default Sidebar;