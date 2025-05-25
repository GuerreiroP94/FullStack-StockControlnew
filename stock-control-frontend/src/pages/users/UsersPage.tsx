import { useEffect, useState } from "react";
import { api } from "../../services/api";
import { 
  Users, 
  UserPlus, 
  Pencil, 
  Trash2, 
  Check, 
  X, 
  Search,
  Shield,
  User,
  Mail,
  Key,
  AlertCircle
} from "lucide-react";
import ConfirmModal from "../../components/common/ConfirmModal";
import ErrorMessage from "../../components/common/ErrorMessage";
import SuccessMessage from "../../components/common/SuccessMessage";
import LoadingSpinner from "../../components/common/LoadingSpinner";

interface Usuario {
  id: number;
  name: string;
  email: string;
  role: "admin" | "operator";
  password?: string;
}

interface NovoUsuario {
  name: string;
  email: string;
  password: string;
  role: "admin" | "operator";
}

export default function UsersPage() {
  const userIdLogado = localStorage.getItem("userId");
  const [usuarios, setUsuarios] = useState<Usuario[]>([]);
  const [usuariosFiltrados, setUsuariosFiltrados] = useState<Usuario[]>([]);
  const [erro, setErro] = useState("");
  const [sucesso, setSucesso] = useState("");
  const [loading, setLoading] = useState(true);
  const [editandoUsuario, setEditandoUsuario] = useState<Usuario | null>(null);
  const [confirmandoDelete, setConfirmandoDelete] = useState<Usuario | null>(null);
  const [mostrarFormNovoUsuario, setMostrarFormNovoUsuario] = useState(false);
  const [termoBusca, setTermoBusca] = useState("");
  const [filtroRole, setFiltroRole] = useState<"todos" | "admin" | "operator">("todos");
  
  const [novoUsuario, setNovoUsuario] = useState<NovoUsuario>({
    name: "",
    email: "",
    password: "",
    role: "operator"
  });

  useEffect(() => {
    fetchUsuarios();
  }, []);

  useEffect(() => {
    let filtrados = usuarios;

    // Filtro por busca
    if (termoBusca) {
      filtrados = filtrados.filter(u => 
        u.name.toLowerCase().includes(termoBusca.toLowerCase()) ||
        u.email.toLowerCase().includes(termoBusca.toLowerCase())
      );
    }

    // Filtro por role
    if (filtroRole !== "todos") {
      filtrados = filtrados.filter(u => u.role === filtroRole);
    }

    setUsuariosFiltrados(filtrados);
  }, [termoBusca, filtroRole, usuarios]);

  const fetchUsuarios = async () => {
    try {
      setLoading(true);
      const response = await api.get("/user");
      setUsuarios(response.data);
      setUsuariosFiltrados(response.data);
    } catch (err) {
      console.error(err);
      setErro("Erro ao carregar usuários.");
    } finally {
      setLoading(false);
    }
  };

  const criarUsuario = async () => {
    if (!novoUsuario.name || !novoUsuario.email || !novoUsuario.password) {
      setErro("Preencha todos os campos obrigatórios.");
      return;
    }

    try {
      await api.post("/user", novoUsuario);
      setSucesso("Usuário criado com sucesso!");
      setMostrarFormNovoUsuario(false);
      setNovoUsuario({ name: "", email: "", password: "", role: "operator" });
      fetchUsuarios();
      
      setTimeout(() => setSucesso(""), 3000);
    } catch (err) {
      console.error("Erro ao criar usuário:", err);
      setErro("Erro ao criar usuário. Verifique se o email já está em uso.");
    }
  };

  const salvarAlteracoes = async () => {
    if (!editandoUsuario) return;
    try {
      const { name, email, password } = editandoUsuario;
      await api.put(`/user/${editandoUsuario.id}`, {
        name,
        email,
        password: password || "",
      });
      setSucesso("Usuário atualizado com sucesso!");
      setEditandoUsuario(null);
      fetchUsuarios();
      
      setTimeout(() => setSucesso(""), 3000);
    } catch (err) {
      console.error("Erro ao salvar alterações:", err);
      setErro("Erro ao salvar alterações.");
    }
  };

  const deletarUsuario = async () => {
    if (!confirmandoDelete) return;
    try {
      await api.delete(`/user/${confirmandoDelete.id}`);
      setSucesso("Usuário excluído com sucesso!");
      setConfirmandoDelete(null);
      fetchUsuarios();
      
      setTimeout(() => setSucesso(""), 3000);
    } catch (err) {
      console.error("Erro ao deletar usuário:", err);
      setErro("Erro ao deletar usuário.");
    }
  };

  // Estatísticas
  const totalUsuarios = usuarios.length;
  const totalAdmins = usuarios.filter(u => u.role === "admin").length;
  const totalOperadores = usuarios.filter(u => u.role === "operator").length;

  return (
    <div className="p-6">
      {/* Header */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className="w-10 h-10 bg-gradient-to-br from-indigo-500 to-indigo-600 rounded-xl flex items-center justify-center shadow-lg">
              <Users className="text-white" size={20} />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-gray-800">Usuários do Sistema</h1>
              <p className="text-sm text-gray-500">Gerencie os usuários e suas permissões</p>
            </div>
          </div>
          <button
            onClick={() => setMostrarFormNovoUsuario(true)}
            className="flex items-center gap-2 px-4 py-2.5 bg-gradient-to-r from-indigo-500 to-indigo-600 text-white rounded-lg hover:from-indigo-600 hover:to-indigo-700 transition-all duration-200 shadow-sm"
          >
            <UserPlus size={18} />
            <span className="font-medium">Novo Usuário</span>
          </button>
        </div>
      </div>

      {/* Mensagens */}
      {erro && <ErrorMessage message={erro} onClose={() => setErro("")} className="mb-6" />}
      {sucesso && <SuccessMessage message={sucesso} onClose={() => setSucesso("")} className="mb-6" />}

      {/* Cards de Estatísticas */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500 mb-1">Total de Usuários</p>
              <p className="text-2xl font-bold text-gray-800">{totalUsuarios}</p>
            </div>
            <div className="w-12 h-12 bg-blue-100 rounded-full flex items-center justify-center">
              <Users className="text-blue-600" size={24} />
            </div>
          </div>
        </div>

        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500 mb-1">Administradores</p>
              <p className="text-2xl font-bold text-gray-800">{totalAdmins}</p>
            </div>
            <div className="w-12 h-12 bg-purple-100 rounded-full flex items-center justify-center">
              <Shield className="text-purple-600" size={24} />
            </div>
          </div>
        </div>

        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500 mb-1">Operadores</p>
              <p className="text-2xl font-bold text-gray-800">{totalOperadores}</p>
            </div>
            <div className="w-12 h-12 bg-green-100 rounded-full flex items-center justify-center">
              <User className="text-green-600" size={24} />
            </div>
          </div>
        </div>
      </div>

      {/* Filtros */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Busca */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" size={18} />
            <input
              type="text"
              placeholder="Buscar por nome ou email..."
              value={termoBusca}
              onChange={(e) => setTermoBusca(e.target.value)}
              className="w-full pl-10 pr-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200"
            />
          </div>

          {/* Filtro por Role */}
          <div className="flex gap-2">
            <button
              onClick={() => setFiltroRole("todos")}
              className={`px-4 py-2.5 rounded-lg font-medium transition-all duration-200 ${
                filtroRole === "todos"
                  ? "bg-blue-600 text-white"
                  : "bg-gray-100 text-gray-600 hover:bg-gray-200"
              }`}
            >
              Todos
            </button>
            <button
              onClick={() => setFiltroRole("admin")}
              className={`px-4 py-2.5 rounded-lg font-medium transition-all duration-200 ${
                filtroRole === "admin"
                  ? "bg-purple-600 text-white"
                  : "bg-gray-100 text-gray-600 hover:bg-gray-200"
              }`}
            >
              Administradores
            </button>
            <button
              onClick={() => setFiltroRole("operator")}
              className={`px-4 py-2.5 rounded-lg font-medium transition-all duration-200 ${
                filtroRole === "operator"
                  ? "bg-green-600 text-white"
                  : "bg-gray-100 text-gray-600 hover:bg-gray-200"
              }`}
            >
              Operadores
            </button>
          </div>
        </div>
      </div>

      {/* Tabela */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
        {loading ? (
          <div className="p-12 text-center">
            <LoadingSpinner size="lg" message="Carregando usuários..." />
          </div>
        ) : usuariosFiltrados.length === 0 ? (
          <div className="p-12 text-center">
            <Users className="mx-auto mb-4 text-gray-400" size={48} />
            <p className="text-lg font-medium text-gray-600">Nenhum usuário encontrado</p>
            <p className="text-sm text-gray-500 mt-1">
              {termoBusca || filtroRole !== "todos" 
                ? "Tente ajustar os filtros de busca" 
                : "Adicione novos usuários ao sistema"}
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full">
              <thead className="bg-gray-50 border-b border-gray-200">
                <tr>
                  <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Usuário
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Email
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Senha
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Permissão
                  </th>
                  <th className="px-6 py-4 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Ações
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {usuariosFiltrados.map((u) => (
                  <tr key={u.id} className="hover:bg-gray-50 transition-colors duration-150">
                    <td className="px-6 py-4 whitespace-nowrap">
                      {editandoUsuario?.id === u.id ? (
                        <div className="flex items-center gap-2">
                          <User className="text-gray-400" size={16} />
                          <input
                            type="text"
                            value={editandoUsuario.name}
                            onChange={(e) =>
                              setEditandoUsuario({ ...editandoUsuario, name: e.target.value })
                            }
                            className="px-3 py-1.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200"
                          />
                        </div>
                      ) : (
                        <div className="flex items-center gap-3">
                          <div className="w-8 h-8 bg-blue-100 rounded-full flex items-center justify-center">
                            <User className="text-blue-600" size={16} />
                          </div>
                          <div>
                            <p className="text-sm font-medium text-gray-900">{u.name}</p>
                            {u.id.toString() === userIdLogado && (
                              <p className="text-xs text-blue-600">Você</p>
                            )}
                          </div>
                        </div>
                      )}
                    </td>

                    <td className="px-6 py-4 whitespace-nowrap">
                      {editandoUsuario?.id === u.id ? (
                        <div className="flex items-center gap-2">
                          <Mail className="text-gray-400" size={16} />
                          <input
                            type="email"
                            value={editandoUsuario.email}
                            onChange={(e) =>
                              setEditandoUsuario({ ...editandoUsuario, email: e.target.value })
                            }
                            className="px-3 py-1.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200"
                          />
                        </div>
                      ) : (
                        <div className="flex items-center gap-2">
                          <Mail className="text-gray-400" size={16} />
                          <span className="text-sm text-gray-600">{u.email}</span>
                        </div>
                      )}
                    </td>

                    <td className="px-6 py-4 whitespace-nowrap">
                      {editandoUsuario?.id === u.id ? (
                        <div className="flex items-center gap-2">
                          <Key className="text-gray-400" size={16} />
                          <input
                            type="password"
                            placeholder="Nova senha (opcional)"
                            onChange={(e) =>
                              setEditandoUsuario({ ...editandoUsuario, password: e.target.value })
                            }
                            className="px-3 py-1.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200"
                          />
                        </div>
                      ) : (
                        <div className="flex items-center gap-2">
                          <Key className="text-gray-400" size={16} />
                          <span className="text-sm text-gray-400">••••••••</span>
                        </div>
                      )}
                    </td>

                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ${
                        u.role === "admin" 
                          ? "bg-purple-100 text-purple-800" 
                          : "bg-green-100 text-green-800"
                      }`}>
                        {u.role === "admin" ? (
                          <>
                            <Shield size={12} />
                            Administrador
                          </>
                        ) : (
                          <>
                            <User size={12} />
                            Operador
                          </>
                        )}
                      </span>
                    </td>

                    <td className="px-6 py-4 whitespace-nowrap text-right">
                      {u.id.toString() !== userIdLogado && (
                        <div className="flex items-center justify-end gap-2">
                          {editandoUsuario?.id === u.id ? (
                            <>
                              <button
                                onClick={salvarAlteracoes}
                                className="p-2 text-green-600 hover:bg-green-50 rounded-lg transition-all duration-200"
                                title="Salvar"
                              >
                                <Check size={18} />
                              </button>
                              <button
                                onClick={() => setEditandoUsuario(null)}
                                className="p-2 text-red-600 hover:bg-red-50 rounded-lg transition-all duration-200"
                                title="Cancelar"
                              >
                                <X size={18} />
                              </button>
                            </>
                          ) : (
                            <>
                              <button
                                onClick={() => setEditandoUsuario({ ...u, password: "" })}
                                className="p-2 text-blue-600 hover:bg-blue-50 rounded-lg transition-all duration-200"
                                title="Editar"
                              >
                                <Pencil size={18} />
                              </button>
                              <button
                                onClick={() => setConfirmandoDelete(u)}
                                className="p-2 text-red-600 hover:bg-red-50 rounded-lg transition-all duration-200"
                                title="Excluir"
                              >
                                <Trash2 size={18} />
                              </button>
                            </>
                          )}
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Modal Novo Usuário */}
      {mostrarFormNovoUsuario && (
        <div className="fixed inset-0 bg-black bg-opacity-30 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl shadow-xl w-full max-w-md">
            <div className="p-6">
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-xl font-bold text-gray-800">Novo Usuário</h2>
                <button
                  onClick={() => {
                    setMostrarFormNovoUsuario(false);
                    setNovoUsuario({ name: "", email: "", password: "", role: "operator" });
                  }}
                  className="text-gray-400 hover:text-gray-600"
                >
                  <X size={24} />
                </button>
              </div>

              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Nome *
                  </label>
                  <input
                    type="text"
                    value={novoUsuario.name}
                    onChange={(e) => setNovoUsuario({ ...novoUsuario, name: e.target.value })}
                    className="w-full px-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200"
                    placeholder="Nome completo"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Email *
                  </label>
                  <input
                    type="email"
                    value={novoUsuario.email}
                    onChange={(e) => setNovoUsuario({ ...novoUsuario, email: e.target.value })}
                    className="w-full px-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200"
                    placeholder="email@exemplo.com"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Senha *
                  </label>
                  <input
                    type="password"
                    value={novoUsuario.password}
                    onChange={(e) => setNovoUsuario({ ...novoUsuario, password: e.target.value })}
                    className="w-full px-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200"
                    placeholder="Senha segura"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Permissão
                  </label>
                  <select
                    value={novoUsuario.role}
                    onChange={(e) => setNovoUsuario({ ...novoUsuario, role: e.target.value as "admin" | "operator" })}
                    className="w-full px-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 bg-white"
                  >
                    <option value="operator">Operador</option>
                    <option value="admin">Administrador</option>
                  </select>
                </div>
              </div>

              <div className="flex gap-3 justify-end mt-6">
                <button
                  onClick={() => {
                    setMostrarFormNovoUsuario(false);
                    setNovoUsuario({ name: "", email: "", password: "", role: "operator" });
                  }}
                  className="px-4 py-2 text-gray-600 hover:text-gray-800 hover:bg-gray-100 rounded-lg transition-all duration-200"
                >
                  Cancelar
                </button>
                <button
                  onClick={criarUsuario}
                  className="px-4 py-2 bg-gradient-to-r from-indigo-500 to-indigo-600 text-white rounded-lg hover:from-indigo-600 hover:to-indigo-700 transition-all duration-200"
                >
                  Criar Usuário
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Modal Confirmar Delete */}
      <ConfirmModal
        isOpen={!!confirmandoDelete}
        onClose={() => setConfirmandoDelete(null)}
        onConfirm={deletarUsuario}
        title="Excluir Usuário"
        message={`Tem certeza que deseja excluir o usuário "${confirmandoDelete?.name}"? Esta ação não pode ser desfeita.`}
        confirmText="Excluir"
        type="danger"
      />
    </div>
  );
}