import { useState, useEffect } from 'react';
import { ComponentFilter } from '../types';
import { COMPONENT_GROUPS } from '../utils/constants';

interface UseFiltersProps {
  initialFilters?: Partial<ComponentFilter>;
}

interface UseFiltersReturn {
  filters: ComponentFilter;
  setFilters: React.Dispatch<React.SetStateAction<ComponentFilter>>;
  updateFilter: (key: keyof ComponentFilter, value: any) => void;
  clearFilters: () => void;
  searchTerm: string;
  setSearchTerm: React.Dispatch<React.SetStateAction<string>>;
  groups: string[];
  devices: string[];
  packages: string[];
  values: string[];
  updateDropdowns: (components: any[]) => void;
}

export const useFilters = (props?: UseFiltersProps): UseFiltersReturn => {
  const [filters, setFilters] = useState<ComponentFilter>({
    name: '',
    group: '',
    device: '',
    package: '',
    value: '',
    searchTerm: '',
    pageNumber: 1,
    pageSize: 100,
    ...props?.initialFilters
  });

  const [searchTerm, setSearchTerm] = useState('');
  const [groups, setGroups] = useState<string[]>(COMPONENT_GROUPS);
  const [devices, setDevices] = useState<string[]>([]);
  const [packages, setPackages] = useState<string[]>([]);
  const [values, setValues] = useState<string[]>([]);

  const updateFilter = (key: keyof ComponentFilter, value: any) => {
    setFilters(prev => ({ ...prev, [key]: value, pageNumber: 1 }));
  };

  const clearFilters = () => {
    setFilters({
      name: '',
      group: '',
      device: '',
      package: '',
      value: '',
      searchTerm: '',
      pageNumber: 1,
      pageSize: 100
    });
    setSearchTerm('');
  };

  const updateDropdowns = (components: any[]) => {
    // Extrair valores únicos
    const uniqueGroups = Array.from(new Set(components.map(c => c.group).filter(Boolean)));
    const uniqueDevices = Array.from(new Set(components.map(c => c.device).filter(Boolean)));
    const uniquePackages = Array.from(new Set(components.map(c => c.package).filter(Boolean)));
    const uniqueValues = Array.from(new Set(components.map(c => c.value).filter(Boolean)));

    // Atualizar estados
    if (uniqueGroups.length > 0) {
      setGroups([...COMPONENT_GROUPS, ...uniqueGroups.filter(g => !COMPONENT_GROUPS.includes(g))]);
    }
    if (uniqueDevices.length > 0) {
      setDevices(uniqueDevices as string[]);
    }
    if (uniquePackages.length > 0) {
      setPackages(uniquePackages as string[]);
    }
    if (uniqueValues.length > 0) {
      setValues(uniqueValues as string[]);
    }
  };

  return {
    filters,
    setFilters,
    updateFilter,
    clearFilters,
    searchTerm,
    setSearchTerm,
    groups,
    devices,
    packages,
    values,
    updateDropdowns
  };
};