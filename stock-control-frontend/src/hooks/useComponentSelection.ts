import { useState } from 'react';

interface UseComponentSelectionReturn {
  selectedComponents: Set<number>;
  setSelectedComponents: React.Dispatch<React.SetStateAction<Set<number>>>;
  handleSelectComponent: (id: number) => void;
  handleSelectAll: (componentIds: number[]) => void;
  clearSelection: () => void;
  isSelected: (id: number) => boolean;
  selectedCount: number;
}

export const useComponentSelection = (): UseComponentSelectionReturn => {
  const [selectedComponents, setSelectedComponents] = useState<Set<number>>(new Set());

  const handleSelectComponent = (id: number) => {
    setSelectedComponents(prev => {
      const newSet = new Set(prev);
      if (newSet.has(id)) {
        newSet.delete(id);
      } else {
        newSet.add(id);
      }
      return newSet;
    });
  };

  const handleSelectAll = (componentIds: number[]) => {
    setSelectedComponents(prev => {
      // Se todos estão selecionados, desmarcar todos
      if (prev.size === componentIds.length) {
        return new Set();
      }
      // Caso contrário, selecionar todos
      return new Set(componentIds);
    });
  };

  const clearSelection = () => {
    setSelectedComponents(new Set());
  };

  const isSelected = (id: number): boolean => {
    return selectedComponents.has(id);
  };

  return {
    selectedComponents,
    setSelectedComponents,
    handleSelectComponent,
    handleSelectAll,
    clearSelection,
    isSelected,
    selectedCount: selectedComponents.size
  };
};