import React, { useState, useEffect } from 'react';
import { Settings, Key, Save, AlertCircle, Eye, EyeOff } from 'lucide-react';
import { useAuth } from '../../contexts/AuthContext';
import usersService from '../../services/users.service';
import authService from '../../services/auth.service';
import ConfirmModal from '../../components/common/ConfirmModal';
import SuccessMessage from '../../components/common/SuccessMessage';
import ErrorMessage from '../../components/common/ErrorMessage';

const SettingsPage: React.FC = () => {
  const { user, updateCurrentUser } = useAuth();
  const [loading, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [showConfirmModal, setShowConfirmModal] = useState(false);
  const [showPasswords, setShowPasswords] = useState(false);
  
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    currentPassword: '',
    newPassword: '',
    confirmPassword: ''
  });

  const [passwordErrors, setPasswordErrors] = useState({
    length: false,
    match: false,
    current: false
  });

  useEffect(() => {
    if (user) {
      setFormData(prev => ({
        ...prev,
        name: user.name,
        email: user.email
      }));
    }
  }, [user]);

  const validatePassword = (password: string) => {
    return password.length >= 6;
  };

  const handlePasswordChange = (field: string, value: string) => {
    setFormData(prev => ({ ...prev, [field]: value }));
    
    if (field === 'newPassword') {
      setPasswordErrors(prev => ({
        ...prev,
        length: value.length > 0 && value.length < 6,
        match: formData.confirmPassword.length > 0 && value !== formData.confirmPassword
      }));
    }
    
    if (field === 'confirmPassword') {
      setPasswordErrors(prev => ({
        ...prev,
        match: value.length > 0 && value !== formData.newPassword
      }));
    }
  };

  const validateCurrentPassword = async (): Promise<boolean> => {
    if (!user || !formData.currentPassword) return false;
    
    try {
      // ✅ CORREÇÃO: Converter para número
      const userIdString = authService.getCurrentUserId();
      const userId = userIdString ? parseInt(userIdString) : user.id;
      
      const isValid = await usersService.validatePassword(Number(userId), formData.currentPassword);
      return isValid;
    } catch (error) {
      console.error('Erro ao validar senha:', error);
      return false;
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    
    // Validações
    if (formData.newPassword || formData.confirmPassword) {
      if (!formData.currentPassword) {
        setError('Digite a senha atual para alterar a senha');
        return;
      }
      
      // Valida a senha atual
      const isCurrentPasswordValid = await validateCurrentPassword();
      if (!isCurrentPasswordValid) {
        setError('A senha atual está incorreta');
        return;
      }
      
      if (!validatePassword(formData.newPassword)) {
        setError('A nova senha deve ter pelo menos 6 caracteres');
        return;
      }
      
      if (formData.newPassword !== formData.confirmPassword) {
        setError('As senhas não coincidem');
        return;
      }
    }
    
    setShowConfirmModal(true);
  };

  const confirmSave = async () => {
    if (!user) return;
    
    try {
      setSaving(true);
      setError('');
      
      const updateData: any = {
        name: formData.name,
        email: formData.email
      };
      
      // Só inclui senha se o usuário preencheu
      if (formData.newPassword) {
        updateData.password = formData.newPassword;
      }
      
      // ✅ CORREÇÃO: Converter para número
      const userIdString = authService.getCurrentUserId();
      const userId = userIdString ? parseInt(userIdString) : user.id;
      
      await usersService.update(Number(userId), updateData);
      
      // Busca os dados atualizados do usuário
      const updatedUser = await usersService.getById(Number(userId));
      
      // Atualiza o contexto com os novos dados
      updateCurrentUser(updatedUser);
      
      setSuccess('Configurações salvas com sucesso!');
      setShowConfirmModal(false);
      
      // Limpa os campos de senha
      setFormData(prev => ({
        ...prev,
        currentPassword: '',
        newPassword: '',
        confirmPassword: ''
      }));
      
      // Remove mensagem de sucesso após 3 segundos
      setTimeout(() => setSuccess(''), 3000);
    } catch (error: any) {
      console.error('Erro ao salvar:', error);
      setError(error.response?.data?.message || 'Erro ao salvar configurações');
      setShowConfirmModal(false);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="p-6 max-w-4xl mx-auto">
      {/* Header */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6 mb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-gray-100 rounded-lg flex items-center justify-center">
            <Settings className="text-gray-600" size={20} />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-gray-800">Configurações</h1>
            <p className="text-sm text-gray-500">Gerencie suas informações pessoais e senha</p>
          </div>
        </div>
      </div>

      {/* Messages */}
      {error && <ErrorMessage message={error} onClose={() => setError('')} className="mb-6" />}
      {success && <SuccessMessage message={success} onClose={() => setSuccess('')} className="mb-6" />}

      {/* Form */}
      <form onSubmit={handleSubmit}>
        {/* Personal Information */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6 mb-6">
          <h2 className="text-lg font-semibold text-gray-800 mb-6 flex items-center gap-2">
            <span>👤</span> Informações Pessoais
          </h2>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Nome
              </label>
              <input
                type="text"
                value={formData.name}
                onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
                className="w-full px-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all"
                required
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                E-mail
              </label>
              <input
                type="email"
                value={formData.email}
                onChange={(e) => setFormData(prev => ({ ...prev, email: e.target.value }))}
                className="w-full px-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all"
                required
              />
            </div>
          </div>
        </div>

        {/* Change Password */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-lg font-semibold text-gray-800 flex items-center gap-2">
              <Key size={20} />
              Alterar Senha
            </h2>
            
            {/* Checkbox mostrar senha */}
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={showPasswords}
                onChange={(e) => setShowPasswords(e.target.checked)}
                className="w-4 h-4 text-blue-600 rounded focus:ring-blue-500"
              />
              <span className="text-sm text-gray-600 flex items-center gap-1">
                {showPasswords ? <EyeOff size={16} /> : <Eye size={16} />}
                Mostrar senhas
              </span>
            </label>
          </div>
          
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Senha Atual
              </label>
              <input
                type={showPasswords ? "text" : "password"}
                value={formData.currentPassword}
                onChange={(e) => handlePasswordChange('currentPassword', e.target.value)}
                className="w-full px-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all"
                placeholder="••••••••"
              />
              <p className="text-xs text-gray-500 mt-1">
                Deixe em branco se não quiser alterar a senha
              </p>
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Nova Senha
              </label>
              <input
                type={showPasswords ? "text" : "password"}
                value={formData.newPassword}
                onChange={(e) => handlePasswordChange('newPassword', e.target.value)}
                className={`w-full px-4 py-2.5 rounded-lg border transition-all ${
                  passwordErrors.length 
                    ? 'border-red-500 focus:border-red-500 focus:ring-red-200' 
                    : 'border-gray-300 focus:border-blue-500 focus:ring-blue-200'
                }`}
                placeholder="••••••••"
              />
              {passwordErrors.length && (
                <p className="text-xs text-red-600 mt-1 flex items-center gap-1">
                  <AlertCircle size={12} />
                  A senha deve ter pelo menos 6 caracteres
                </p>
              )}
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Confirmar Nova Senha
              </label>
              <input
                type={showPasswords ? "text" : "password"}
                value={formData.confirmPassword}
                onChange={(e) => handlePasswordChange('confirmPassword', e.target.value)}
                className={`w-full px-4 py-2.5 rounded-lg border transition-all ${
                  passwordErrors.match 
                    ? 'border-red-500 focus:border-red-500 focus:ring-red-200' 
                    : 'border-gray-300 focus:border-blue-500 focus:ring-blue-200'
                }`}
                placeholder="••••••••"
              />
              {passwordErrors.match && (
                <p className="text-xs text-red-600 mt-1 flex items-center gap-1">
                  <AlertCircle size={12} />
                  As senhas não coincidem
                </p>
              )}
            </div>
          </div>
        </div>

        {/* Submit Button */}
        <div className="flex justify-end mt-6">
          <button
            type="submit"
            className="flex items-center gap-2 px-6 py-2.5 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
          >
            <Save size={18} />
            Salvar Alterações
          </button>
        </div>
      </form>

      {/* Confirmation Modal */}
      <ConfirmModal
  isOpen={showConfirmModal}
  onClose={() => setShowConfirmModal(false)}
  onConfirm={confirmSave}
  title="Confirmar Alterações"
  message="Tem certeza que deseja salvar as alterações nas suas configurações?"
  confirmText="Sim, salvar"
  cancelText="Cancelar"
  isLoading={loading}
  type="info"
/>
    </div>
  );
};

export default SettingsPage;