import React, { useState } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import {
  LayoutDashboard,
  Package,
  ShoppingCart,
  TrendingUpDown,
  AlertCircle,
  Users,
  ChevronLeft,
  ChevronRight,
  ChevronDown,
  Cpu,
  ShoppingBag,
  PlusCircle
} from 'lucide-react';
import { useAuth } from '../../contexts/AuthContext';

interface SidebarProps {
  isOpen: boolean;
  toggleSidebar: () => void;
}

const Sidebar: React.FC<SidebarProps> = ({ isOpen, toggleSidebar }) => {
  const { isAdmin } = useAuth();
  const location = useLocation();
  const [productsSubmenuOpen, setProductsSubmenuOpen] = useState(false);

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

        {/* Menu Items */}
        <nav className="flex-1 py-4 px-2">
          {filteredMenuItems.map((item) => (
            <div key={item.path}>
              {item.hasSubmenu ? (
                <>
                  <button
                    onClick={() => setProductsSubmenuOpen(!productsSubmenuOpen)}
                    className={`w-full flex items-center justify-between gap-3 px-3 py-2.5 mb-1 rounded-lg transition-all duration-200
                      ${isProductsActive 
                        ? 'bg-blue-50 text-blue-600' 
                        : 'text-gray-600 hover:bg-gray-100 hover:text-gray-800'
                      }
                    `}
                    title={!isOpen ? item.name : undefined}
                  >
                    <div className="flex items-center gap-3">
                      <item.icon size={20} />
                      {isOpen && <span className="font-medium">{item.name}</span>}
                    </div>
                    {isOpen && (
                      <ChevronDown 
                        size={16} 
                        className={`transition-transform duration-200 ${
                          productsSubmenuOpen ? 'rotate-180' : ''
                        }`}
                      />
                    )}
                  </button>
                  
                  {isOpen && productsSubmenuOpen && item.submenu && (
                    <div className="ml-4 mt-1 space-y-1">
                      {item.submenu.map((subItem) => (
                        <NavLink
                          key={subItem.path}
                          to={subItem.path}
                          className={({ isActive }) => `
                            flex items-center gap-3 px-3 py-2 rounded-lg transition-all duration-200
                            ${isActive 
                              ? 'bg-blue-50 text-blue-600' 
                              : 'text-gray-600 hover:bg-gray-100 hover:text-gray-800'
                            }
                          `}
                        >
                          <subItem.icon size={18} />
                          <span className="text-sm font-medium">{subItem.name}</span>
                        </NavLink>
                      ))}
                    </div>
                  )}
                </>
              ) : (
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
              )}
            </div>
          ))}
        </nav>

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