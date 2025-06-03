import { useState } from 'react';
import exportService from '../services/export.service';
import { Component } from '../types';

interface UseExportReturn {
  isExporting: boolean;
  exportError: string | null;
  exportComponents: (components: Component[], filename?: string) => Promise<void>;
  exportFilteredComponents: (
    components: Component[], 
    filters: any, 
    filename?: string
  ) => Promise<void>;
  exportProductWithOrder: (
    product: any,
    components: Component[],
    order: number[],
    quantity?: number
  ) => Promise<void>;
  clearExportError: () => void;
}

export const useExport = (): UseExportReturn => {
  const [isExporting, setIsExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);

  const exportComponents = async (components: Component[], filename?: string) => {
    try {
      setIsExporting(true);
      setExportError(null);
      await exportService.exportComponentsToExcel(components, filename);
    } catch (error) {
      setExportError('Erro ao exportar componentes');
      console.error('Export error:', error);
    } finally {
      setIsExporting(false);
    }
  };

  const exportFilteredComponents = async (
    components: Component[], 
    filters: any, 
    filename?: string
  ) => {
    try {
      setIsExporting(true);
      setExportError(null);
      await exportService.exportComponentsFiltered(components, filters, filename);
    } catch (error) {
      setExportError('Erro ao exportar componentes filtrados');
      console.error('Export error:', error);
    } finally {
      setIsExporting(false);
    }
  };

  const exportProductWithOrder = async (
    product: any,
    components: Component[],
    order: number[],
    quantity: number = 1
  ) => {
    try {
      setIsExporting(true);
      setExportError(null);
      await exportService.exportProductWithCustomOrder(
        product,
        components,
        order,
        quantity
      );
    } catch (error) {
      setExportError('Erro ao exportar produto');
      console.error('Export error:', error);
    } finally {
      setIsExporting(false);
    }
  };

  const clearExportError = () => {
    setExportError(null);
  };

  return {
    isExporting,
    exportError,
    exportComponents,
    exportFilteredComponents,
    exportProductWithOrder,
    clearExportError
  };
};