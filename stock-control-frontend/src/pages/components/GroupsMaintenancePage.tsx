import React, { useEffect, useState } from 'react';
import { Settings, Plus, Package, Cpu, Tag, Box } from 'lucide-react';
import componentsService from '../../services/components.service';
import { Component } from '../../types';
import { COMPONENT_GROUPS } from '../../utils/constants';
import LoadingSpinner from '../../components/common/LoadingSpinner';
import ErrorMessage from '../../components/common/ErrorMessage';
import SuccessMessage from '../../components/common/SuccessMessage';
import ConfirmModal from '../../components/common/ConfirmModal';

type MaintenanceType = 'group' | 'device' | 'package' | 'value';

interface MaintenanceState {
  groups: string[];
  devices: string[];
  packages: string[];
  values: string[];
}

const GroupsMaintenancePage: React.FC = () => {
  const [components, setComponents] = useState<Component[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  
  // Estado da aba ativa
  const [activeTab, setActiveTab] = useState<MaintenanceType>('group');
  
  // Estados para os dropdowns
  const [maintenanceState, setMaintenanceState] = useState<MaintenanceState>({
    groups: [...COMPONENT_GROUPS],
    devices: [],
    packages: [],
    values: []
  });
  
  // Estados para seleção
  const [selectedGroup, setSelectedGroup] = useState('');
  const [selectedDevice, setSelectedDevice] = useState('');
  const [selectedPackage, setSelectedPackage] = useState('');
  const [selectedValueItem, setSelectedValueItem] = useState('');
  
  // Estados para novos itens
  const [newGroupName, setNewGroupName] = useState('');
  const [newDeviceName, setNewDeviceName] = useState('');
  const [newPackageName, setNewPackageName] = useState('');
  const [newValueName, setNewValueName] = useState('');
  
  // Modal de confirmação
  const [confirmModal, setConfirmModal] = useState<{
    show: boolean;
    type: MaintenanceType | null;
    name: string;
  }>({ show: false, type: null, name: '' });

  useEffect(() => {
    fetchComponents();
  }, []);

  const fetchComponents = async () => {
    try {
      setLoading(true);
      const data = await componentsService.getAll();
      setComponents(data);
      
      // Extrair valores únicos para os dropdowns
      const uniqueGroups = Array.from(new Set(data.map(c => c.group).filter(Boolean)));
      const uniqueDevices = Array.from(new Set(data.map(c => c.device).filter(Boolean)));
      const uniquePackages = Array.from(new Set(data.map(c => c.package).filter(Boolean)));
      const uniqueValues = Array.from(new Set(data.map(c => c.value).filter(Boolean)));

      // Atualizar os dropdowns com valores únicos
      setMaintenanceState({
        groups: [...COMPONENT_GROUPS, ...uniqueGroups.filter(g => !COMPONENT_GROUPS.includes(g))],
        devices: uniqueDevices as string[],
        packages: uniquePackages as string[],
        values: uniqueValues as string[]
      });
    } catch (error) {
      setError('Erro ao carregar componentes');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleAddNew = (type: MaintenanceType, name: string) => {
    if (!name.trim()) {
      setError(`Por favor, insira um nome para o ${getTypeName(type)}`);
      return;
    }

    // Verificar se já existe
    const existingItems = maintenanceState[`${type}s` as keyof MaintenanceState] as string[];
    if (existingItems.includes(name)) {
      setError(`${getTypeName(type)} "${name}" já existe`);
      return;
    }

    // Abrir modal de confirmação
    setConfirmModal({ show: true, type, name });
  };

  const confirmAddNew = () => {
    const { type, name } = confirmModal;
    if (!type || !name) return;

    // Adicionar ao estado
    setMaintenanceState(prev => ({
      ...prev,
      [`${type}s`]: [...prev[`${type}s` as keyof MaintenanceState], name]
    }));

    // Limpar campos
    switch (type) {
      case 'group':
        setNewGroupName('');
        break;
      case 'device':
        setNewDeviceName('');
        break;
      case 'package':
        setNewPackageName('');
        break;
      case 'value':
        setNewValueName('');
        break;
    }

    setSuccess(`${getTypeName(type)} "${name}" criado com sucesso!`);
    setConfirmModal({ show: false, type: null, name: '' });
  };

  const cancelAddNew = () => {
    setError(`Criação de ${getTypeName(confirmModal.type!)} cancelada`);
    setConfirmModal({ show: false, type: null, name: '' });
  };

  const getTypeName = (type: MaintenanceType): string => {
    switch (type) {
      case 'group':
        return 'Grupo';
      case 'device':
        return 'Device';
      case 'package':
        return 'Package';
      case 'value':
        return 'Value';
    }
  };

  const getFilteredComponents = (type: MaintenanceType, value: string): Component[] => {
    if (!value) return [];
    
    switch (type) {
      case 'group':
        return components.filter(c => c.group === value);
      case 'device':
        return components.filter(c => c.device === value);
      case 'package':
        return components.filter(c => c.package === value);
      case 'value':
        return components.filter(c => c.value === value);
    }
  };

  const tabs = [
    { id: 'group' as MaintenanceType, name: 'Grupos', icon: Package },
    { id: 'device' as MaintenanceType, name: 'Devices', icon: Cpu },
    { id: 'package' as MaintenanceType, name: 'Packages', icon: Box },
    { id: 'value' as MaintenanceType, name: 'Values', icon: Tag }
  ];

  const renderTabContent = () => {
    let currentSelectedValue: string = '';
    let setCurrentSelectedValue: React.Dispatch<React.SetStateAction<string>> = () => {};
    let currentNewValue: string = '';
    let setCurrentNewValue: React.Dispatch<React.SetStateAction<string>> = () => {};
    
    switch (activeTab) {
      case 'group':
        currentSelectedValue = selectedGroup;
        setCurrentSelectedValue = setSelectedGroup;
        currentNewValue = newGroupName;
        setCurrentNewValue = setNewGroupName;
        break;
      case 'device':
        currentSelectedValue = selectedDevice;
        setCurrentSelectedValue = setSelectedDevice;
        currentNewValue = newDeviceName;
        setCurrentNewValue = setNewDeviceName;
        break;
      case 'package':
        currentSelectedValue = selectedPackage;
        setCurrentSelectedValue = setSelectedPackage;
        currentNewValue = newPackageName;
        setCurrentNewValue = setNewPackageName;
        break;
      case 'value':
        currentSelectedValue = selectedValueItem;
        setCurrentSelectedValue = setSelectedValueItem;
        currentNewValue = newValueName;
        setCurrentNewValue = setNewValueName;
        break;
    }
    
    const items = maintenanceState[`${activeTab}s` as keyof MaintenanceState] as string[];
    const filteredComponents = getFilteredComponents(activeTab, currentSelectedValue);

    return (
      <div className="p-6">
        {/* Adicionar Novo */}
        <div className="mb-6">
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Novo {getTypeName(activeTab)}
          </label>
          <div className="flex gap-2 max-w-md">
            <input
              type="text"
              value={currentNewValue}
              onChange={(e) => setCurrentNewValue(e.target.value)}
              placeholder={`Nome do ${getTypeName(activeTab).toLowerCase()}`}
              className="flex-1 px-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200"
            />
            <button
              onClick={() => handleAddNew(activeTab, currentNewValue)}
              className="px-4 py-2.5 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-all duration-200 flex items-center gap-2"
            >
              <Plus size={18} />
              Adicionar
            </button>
          </div>
        </div>

        {/* Seleção */}
        <div className="mb-6">
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Selecione um {getTypeName(activeTab)}
          </label>
          <select
            value={currentSelectedValue}
            onChange={(e) => setCurrentSelectedValue(e.target.value)}
            className="w-full max-w-md px-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200 bg-white"
          >
            <option value="">Selecione um {getTypeName(activeTab).toLowerCase()}...</option>
            {items.map(item => (
              <option key={item} value={item}>{item}</option>
            ))}
          </select>
        </div>

        {/* Lista de Componentes */}
        {currentSelectedValue && (
          <div>
            <h3 className="text-lg font-semibold text-gray-800 mb-4">
              Componentes com {getTypeName(activeTab).toLowerCase()} "{currentSelectedValue}"
              <span className="ml-2 text-sm font-normal text-gray-500">
                ({filteredComponents.length} {filteredComponents.length === 1 ? 'componente' : 'componentes'})
              </span>
            </h3>
            
            <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
              {filteredComponents.length === 0 ? (
                <div className="p-8 text-center">
                  <Package className="mx-auto mb-3 text-gray-400" size={40} />
                  <p className="text-gray-500">Nenhum componente com este {getTypeName(activeTab).toLowerCase()}</p>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="min-w-full">
                    <thead className="bg-gray-50 border-b border-gray-200">
                      <tr>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Componente
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Grupo
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Device
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Value
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Package
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Estoque
                        </th>
                      </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                      {filteredComponents.map(comp => (
                        <tr key={comp.id} className="hover:bg-gray-50">
                          <td className="px-6 py-4 whitespace-nowrap">
                            <p className="text-sm font-medium text-gray-900">{comp.name}</p>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <p className="text-sm text-gray-600">{comp.group}</p>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <p className="text-sm text-gray-600">{comp.device || '-'}</p>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <p className="text-sm text-gray-600">{comp.value || '-'}</p>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <p className="text-sm text-gray-600">{comp.package || '-'}</p>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <span className={`inline-flex px-2.5 py-1 text-xs font-medium rounded-full ${
                              comp.quantityInStock === 0 
                                ? 'bg-red-100 text-red-800' 
                                : comp.quantityInStock <= comp.minimumQuantity 
                                  ? 'bg-yellow-100 text-yellow-800'
                                  : 'bg-green-100 text-green-800'
                            }`}>
                              {comp.quantityInStock}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    );
  };

  if (loading) {
    return (
      <div className="p-6">
        <LoadingSpinner fullScreen message="Carregando dados..." />
      </div>
    );
  }

  return (
    <div className="p-6">
      {/* Header */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
        <div className="flex items-center gap-4">
          <div className="w-10 h-10 bg-gradient-to-br from-purple-500 to-purple-600 rounded-xl flex items-center justify-center shadow-lg">
            <Settings className="text-white" size={20} />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-gray-800">Manutenção de Grupos</h1>
            <p className="text-sm text-gray-500">Gerencie grupos, devices, packages e values</p>
          </div>
        </div>
      </div>

      {/* Messages */}
      {error && <ErrorMessage message={error} onClose={() => setError('')} className="mb-6" />}
      {success && <SuccessMessage message={success} onClose={() => setSuccess('')} className="mb-6" />}

      {/* Tabs */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200">
        <div className="flex border-b border-gray-200">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-6 py-4 font-medium transition-all duration-200 ${
                  activeTab === tab.id
                    ? 'text-purple-600 border-b-2 border-purple-600 bg-purple-50'
                    : 'text-gray-600 hover:text-gray-800 hover:bg-gray-50'
                }`}
              >
                <Icon size={18} />
                {tab.name}
              </button>
            );
          })}
        </div>

        {/* Tab Content */}
        {renderTabContent()}
      </div>

      {/* Modal de Confirmação */}
      <ConfirmModal
        isOpen={confirmModal.show}
        onClose={cancelAddNew}
        onConfirm={confirmAddNew}
        title={`Criar ${confirmModal.type ? getTypeName(confirmModal.type) : ''}`}
        message={`Deseja realmente criar um ${confirmModal.type ? getTypeName(confirmModal.type) : ''} com o nome "${confirmModal.name}"?`}
        confirmText="Sim, criar"
        cancelText="Não, cancelar"
        type="info"
      />
    </div>
  );
};

export default GroupsMaintenancePage;