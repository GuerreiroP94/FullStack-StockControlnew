import React from 'react';
import { AlertTriangle, Info, CheckCircle, XCircle } from 'lucide-react';
import BaseModal from './BaseModal';
import LoadingSpinner from './LoadingSpinner';

interface ConfirmModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => void;
  title: string;
  message: string;
  confirmText?: string;
  cancelText?: string;
  type?: 'danger' | 'warning' | 'info' | 'success';
  isLoading?: boolean;
}

const ConfirmModal: React.FC<ConfirmModalProps> = ({
  isOpen,
  onClose,
  onConfirm,
  title,
  message,
  confirmText = 'Confirmar',
  cancelText = 'Cancelar',
  type = 'warning',
  isLoading = false
}) => {
  const typeConfig = {
    danger: {
      icon: XCircle,
      iconColor: 'text-red-600',
      bgColor: 'bg-red-100',
      buttonColor: 'from-red-500 to-red-600 hover:from-red-600 hover:to-red-700'
    },
    warning: {
      icon: AlertTriangle,
      iconColor: 'text-yellow-600',
      bgColor: 'bg-yellow-100',
      buttonColor: 'from-yellow-500 to-yellow-600 hover:from-yellow-600 hover:to-yellow-700'
    },
    info: {
      icon: Info,
      iconColor: 'text-blue-600',
      bgColor: 'bg-blue-100',
      buttonColor: 'from-blue-500 to-blue-600 hover:from-blue-600 hover:to-blue-700'
    },
    success: {
      icon: CheckCircle,
      iconColor: 'text-green-600',
      bgColor: 'bg-green-100',
      buttonColor: 'from-green-500 to-green-600 hover:from-green-600 hover:to-green-700'
    }
  };

  const config = typeConfig[type];
  const Icon = config.icon;

  return (
    <BaseModal isOpen={isOpen} onClose={onClose} showCloseButton={false}>
      <div className="p-6">
        <div className="flex items-center gap-4 mb-4">
          <div className={`w-12 h-12 ${config.bgColor} rounded-full flex items-center justify-center`}>
            <Icon className={config.iconColor} size={24} />
          </div>
          <div className="flex-1">
            <h2 className="text-xl font-bold text-gray-800">{title}</h2>
          </div>
        </div>
        
        <p className="text-gray-600 mb-6 ml-16">{message}</p>
        
        <div className="flex gap-3 justify-end">
          <button
            onClick={onClose}
            disabled={isLoading}
            className="px-4 py-2 text-gray-600 hover:text-gray-800 hover:bg-gray-100 rounded-lg transition-all duration-200 disabled:opacity-50"
          >
            {cancelText}
          </button>
          <button
            onClick={onConfirm}
            disabled={isLoading}
            className={`px-4 py-2 bg-gradient-to-r ${config.buttonColor} text-white rounded-lg transition-all duration-200 flex items-center gap-2 disabled:opacity-50`}
          >
            {isLoading && <LoadingSpinner size="sm" />}
            {confirmText}
          </button>
        </div>
      </div>
    </BaseModal>
  );
};

export default ConfirmModal;