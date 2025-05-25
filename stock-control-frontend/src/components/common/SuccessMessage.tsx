import React, { useEffect } from 'react';
import { Check, X } from 'lucide-react';

interface SuccessMessageProps {
  message: string;
  onClose?: () => void;
  autoClose?: boolean;
  duration?: number;
  className?: string;
}

const SuccessMessage: React.FC<SuccessMessageProps> = ({ 
  message, 
  onClose, 
  autoClose = true,
  duration = 3000,
  className = '' 
}) => {
  useEffect(() => {
    if (autoClose && onClose) {
      const timer = setTimeout(onClose, duration);
      return () => clearTimeout(timer);
    }
  }, [autoClose, duration, onClose]);

  return (
    <div className={`p-4 bg-green-50 border border-green-200 rounded-xl flex items-center gap-3 ${className}`}>
      <div className="w-5 h-5 bg-green-600 rounded-full flex items-center justify-center flex-shrink-0">
        <Check className="text-white" size={14} />
      </div>
      <p className="text-green-700 flex-1">{message}</p>
      {onClose && (
        <button
          onClick={onClose}
          className="text-green-600 hover:text-green-700 transition-colors"
        >
          <X size={18} />
        </button>
      )}
    </div>
  );
};

export default SuccessMessage;