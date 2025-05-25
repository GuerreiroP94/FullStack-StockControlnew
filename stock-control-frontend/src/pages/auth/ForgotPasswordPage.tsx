import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowLeft, Mail, Package } from 'lucide-react';

const ForgotPasswordPage: React.FC = () => {
  const [email, setEmail] = useState('');
  const [enviado, setEnviado] = useState(false);
  const navigate = useNavigate();

  const handleEnviar = (e: React.FormEvent) => {
    e.preventDefault();
    // Simula envio de email
    setEnviado(true);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center p-4">
      <div className="bg-white p-8 rounded-2xl shadow-xl w-full max-w-md">
        {/* Logo */}
        <div className="flex items-center justify-center gap-3 mb-8">
          <div className="w-12 h-12 bg-gradient-to-br from-blue-500 to-blue-600 rounded-xl flex items-center justify-center shadow-lg">
            <Package className="text-white" size={24} />
          </div>
          <h1 className="text-2xl font-bold text-gray-800">PreSystem</h1>
        </div>

        {/* Title */}
        <h2 className="text-xl font-semibold text-center text-gray-800 mb-2">
          Recuperar Senha
        </h2>
        <p className="text-center text-gray-600 mb-6">
          {enviado 
            ? 'Verifique seu e-mail' 
            : 'Digite seu e-mail para receber as instruções'}
        </p>

        {enviado ? (
          <div className="text-center">
            <div className="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <Mail className="text-green-600" size={32} />
            </div>
            <p className="text-green-600 font-medium mb-4">
              Um link de recuperação foi enviado para seu e-mail.
            </p>
            <p className="text-sm text-gray-600 mb-6">
              Verifique sua caixa de entrada e siga as instruções para redefinir sua senha.
            </p>
            <button
              onClick={() => {
                setEnviado(false);
                setEmail('');
              }}
              className="text-sm text-blue-600 hover:text-blue-700 hover:underline transition-colors"
            >
              Enviar novamente
            </button>
          </div>
        ) : (
          <form onSubmit={handleEnviar} className="space-y-4">
            <div>
              <label className="block text-gray-700 font-medium mb-2">E-mail</label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" size={18} />
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                  className="w-full pl-10 pr-4 py-2.5 rounded-lg border border-gray-300 bg-white text-gray-800 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
                  placeholder="seu@email.com"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={!email}
              className="w-full py-2.5 bg-gradient-to-r from-blue-500 to-blue-600 text-white rounded-lg hover:from-blue-600 hover:to-blue-700 disabled:from-gray-300 disabled:to-gray-400 disabled:cursor-not-allowed transition-all duration-200 font-medium shadow-sm"
            >
              Enviar Link de Recuperação
            </button>
          </form>
        )}

        <div className="text-center mt-6 pt-6 border-t border-gray-200">
          <button
            onClick={() => navigate('/login')}
            className="text-sm text-blue-600 hover:text-blue-700 hover:underline transition-colors inline-flex items-center gap-1"
          >
            <ArrowLeft size={16} />
            Voltar para login
          </button>
        </div>
      </div>
    </div>
  );
};

export default ForgotPasswordPage;