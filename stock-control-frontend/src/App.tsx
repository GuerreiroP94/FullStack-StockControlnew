import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './contexts/AuthContext';
import ProtectedRoute from './components/auth/ProtectedRoute';
import Layout from './components/common/Layout';

// Pages
import LoginPage from './pages/auth/LoginPage';
import ForgotPasswordPage from './pages/auth/ForgotPasswordPage';
import DashboardPage from './pages/dashboard/DashboardPage';
import ComponentsListPage from './pages/components/ComponentsListPage';
import ComponentFormPage from './pages/components/ComponentFormPage';
import ProductsListPage from './pages/products/ProductsListPage';
import ProductFormPage from './pages/products/ProductFormPage';
import MovementsListPage from './pages/movements/MovementsListPage';
import MovementFormPage from './pages/movements/MovementFormPage';
import AlertsPage from './pages/alerts/AlertsPage';
import UsersPage from './pages/users/UsersPage';
import SettingsPage from './pages/settings/SettingsPage';

function App() {
  return (
    <Router>
      <AuthProvider>
        <Routes>
          {/* Public Routes */}
          <Route path="/login" element={<LoginPage />} />
          <Route path="/forgot-password" element={<ForgotPasswordPage />} />

          {/* Protected Routes */}
          <Route element={<ProtectedRoute />}>
            <Route element={<Layout />}>
              <Route path="/dashboard" element={<DashboardPage />} />
              
              {/* Components */}
              <Route path="/components" element={<ComponentsListPage />} />
              <Route path="/components/new" element={<ComponentFormPage />} />
              <Route path="/components/:id/edit" element={<ComponentFormPage />} />
              
              {/* Products */}
              <Route path="/products" element={<ProductsListPage />} />
              <Route path="/products/new" element={<ProductFormPage />} />
              <Route path="/products/:id/edit" element={<ProductFormPage />} />
              
              {/* Movements */}
              <Route path="/movements" element={<MovementsListPage />} />
              <Route path="/movements/new" element={<MovementFormPage />} />
              
              {/* Alerts */}
              <Route path="/alerts" element={<AlertsPage />} />
              
              {/* Users - Admin Only */}
              <Route path="/users" element={<UsersPage />} />

              {/* Settings - User Logged */}
              <Route path="/settings" element={<SettingsPage />} />
            </Route>
          </Route>

          {/* Default Route */}
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </AuthProvider>
    </Router>
  );
}

export default App;