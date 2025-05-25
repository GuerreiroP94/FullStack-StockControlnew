import React from 'react';
import { AlertCircle, X } from 'lucide-react';

interface ErrorMessageProps {
  message: string;
  onClose?: () => void;
  className?: string;
}

const ErrorMessage: React.FC<ErrorMessageProps> = ({ message, onClose, className = '' }) => {
  return (
    <div className={`p-4 bg-red-50 border border-red-200 rounded-xl flex items-center gap-3 ${className}`}>
      <AlertCircle className="text-red-600 flex-shrink-0" size={20} />
      <p className="text-red-700 flex-1">{message}</p>
      {onClose && (
        <button
          onClick={onClose}
          className="text-red-600 hover:text-red-700 transition-colors"
        >
          <X size={18} />
        </button>
      )}
    </div>
  );
};

export default ErrorMessage;