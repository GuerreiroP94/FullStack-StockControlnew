import React from 'react';
import { Search, Filter, X } from 'lucide-react';
import { ComponentFilter } from '../../types';

interface ComponentFiltersProps {
  searchTerm: string;
  onSearchChange: (value: string) => void;
  filters: {
    group?: string;
    device?: string;
    package?: string;
    value?: string;
  };
  onFilterChange: (key: keyof ComponentFilter, value: any) => void;
  groups: string[];
  devices: string[];
  packages: string[];
  values: string[];
  onClearFilters: () => void;
  showClearButton?: boolean;
}

const ComponentFilters: React.FC<ComponentFiltersProps> = ({
  searchTerm,
  onSearchChange,
  filters,
  onFilterChange,
  groups,
  devices,
  packages,
  values,
  onClearFilters,
  showClearButton = true
}) => {
  const hasActiveFilters = searchTerm || Object.values(filters).some(v => v);

  return (
    <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <Filter size={20} className="text-gray-500" />
          <h2 className="text-lg font-semibold text-gray-800">Filtros</h2>
        </div>
        {showClearButton && hasActiveFilters && (
          <button
            onClick={onClearFilters}
            className="flex items-center gap-1 text-sm text-blue-600 hover:text-blue-700"
          >
            <X size={16} />
            Limpar filtros
          </button>
        )}
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        {/* Grupo */}
        <select
          value={filters.group || ''}
          onChange={(e) => onFilterChange('group', e.target.value)}
          className="w-full px-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200 bg-white"
        >
          <option value="">Todos os Grupos</option>
          {groups.map(group => (
            <option key={group} value={group}>{group}</option>
          ))}
        </select>

        {/* Device */}
        <select
          value={filters.device || ''}
          onChange={(e) => onFilterChange('device', e.target.value)}
          className="w-full px-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200 bg-white"
        >
          <option value="">Todos os Devices</option>
          {devices.map(device => (
            <option key={device} value={device}>{device}</option>
          ))}
        </select>

        {/* Package */}
        <select
          value={filters.package || ''}
          onChange={(e) => onFilterChange('package', e.target.value)}
          className="w-full px-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200 bg-white"
        >
          <option value="">Todos os Packages</option>
          {packages.map(pkg => (
            <option key={pkg} value={pkg}>{pkg}</option>
          ))}
        </select>

        {/* Value */}
        <select
          value={filters.value || ''}
          onChange={(e) => onFilterChange('value', e.target.value)}
          className="w-full px-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200 bg-white"
        >
          <option value="">Todos os Values</option>
          {values.map(value => (
            <option key={value} value={value}>{value}</option>
          ))}
        </select>

        {/* Search */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" size={18} />
          <input
            type="text"
            placeholder="Buscar componentes..."
            value={searchTerm}
            onChange={(e) => onSearchChange(e.target.value)}
            className="w-full pl-10 pr-4 py-2.5 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200"
          />
        </div>
      </div>
    </div>
  );
};

export default ComponentFilters;