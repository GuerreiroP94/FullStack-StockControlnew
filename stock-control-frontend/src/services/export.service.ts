import { Component } from '../types';
import * as XLSX from 'xlsx';

// Interface para o relatório de produção
interface ProductionReportDto {
  productName: string;
  unitsToManufacture: number;
  components: Array<{
    componentName: string;
    device?: string;
    value?: string;
    package?: string;
    characteristics?: string;
    internalCode?: string;
    drawer?: string;
    division?: string;
    quantityPerUnit: number;
    totalQuantityNeeded: number;
    quantityInStock: number;
    suggestedPurchase: number;
    unitPrice?: number;
    totalPrice: number;
  }>;
}

// Interface para o plano de produção
interface ProductionPlanRow {
  qtdFabricar: number;
  qtdTotal: number;
  device: string;
  value: string;
  package: string;
  caracteristicas: string;
  codigo: string;
  gaveta: string;
  divisao: string;
  qtdEstoque: number;
  qtdCompra: number;
}

class ExportService {
  /**
   * Exporta componentes para arquivo Excel
   */
  exportComponentsToExcel(components: Component[], filename: string = 'componentes.xlsx') {
    // Preparar dados para Excel
    const data = components.map(comp => ({
      'ID': comp.id,
      'Nome': comp.name,
      'Grupo': comp.group,
      'Device': comp.device || '',
      'Value': comp.value || '',
      'Package': comp.package || '',
      'Características': comp.characteristics || '',
      'Código Interno': comp.internalCode || '',
      'Gaveta': comp.drawer || '',
      'Divisão': comp.division || '',
      'Qtd. Estoque': comp.quantityInStock,
      'Qtd. Mínima': comp.minimumQuantity,
      'Preço': comp.price || 0,
      'NCM': comp.ncm || '',
      'NVE': comp.nve || '',
      'Ambiente': comp.environment === 'laboratorio' ? 'Laboratório' : 'Estoque',
      'Data': comp.createdAt ? new Date(comp.createdAt).toLocaleDateString('pt-BR') : ''
    }));

    // Criar workbook e worksheet
    const ws = XLSX.utils.json_to_sheet(data);
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'Componentes');

    // Ajustar largura das colunas
    const maxWidth = 30;
    const wscols = Object.keys(data[0] || {}).map(() => ({ wch: maxWidth }));
    ws['!cols'] = wscols;

    // Gerar arquivo Excel
    XLSX.writeFile(wb, filename);
  }

  /**
   * Exporta relatório de produção para Excel
   */
  exportProductionReport(reportData: ProductionReportDto) {
    const { productName, unitsToManufacture, components } = reportData;
    
    // Preparar dados para Excel
    const data = components.map(comp => ({
      'Código Interno': comp.internalCode || '',
      'Componente': comp.componentName || '',
      'Device': comp.device || '',
      'Value': comp.value || '',
      'Package': comp.package || '',
      'Características': comp.characteristics || '',
      'Gaveta': comp.drawer || '',
      'Divisão': comp.division || '',
      'Qtd/Unidade': comp.quantityPerUnit || 0,
      'Qtd Total': comp.totalQuantityNeeded || 0,
      'Em Estoque': comp.quantityInStock || 0,
      'Comprar': comp.suggestedPurchase || 0,
      'Preço Unit.': comp.unitPrice || 0,
      'Preço Total': comp.totalPrice || 0
    }));

    // Calcular total geral
    const totalGeral = components.reduce((sum, comp) => sum + (comp.totalPrice || 0), 0);

    // Adicionar linha de total com valores vazios ou numéricos apropriados
    data.push({
      'Código Interno': '',
      'Componente': '',
      'Device': '',
      'Value': '',
      'Package': '',
      'Características': '',
      'Gaveta': '',
      'Divisão': '',
      'Qtd/Unidade': 0,
      'Qtd Total': 0,
      'Em Estoque': 0,
      'Comprar': 0,
      'Preço Unit.': 0,
      'Preço Total': totalGeral
    });

    // Criar workbook
    const ws = XLSX.utils.json_to_sheet(data);
    const wb = XLSX.utils.book_new();
    
    // Adicionar título no topo
    XLSX.utils.sheet_add_aoa(ws, [
      [`RELATÓRIO DE PRODUÇÃO - ${productName}`],
      [`Unidades a Fabricar: ${unitsToManufacture}`],
      [''] // linha vazia
    ], { origin: 'A1' });

    // Mesclar células do título
    ws['!merges'] = [
      { s: { r: 0, c: 0 }, e: { r: 0, c: 13 } },
      { s: { r: 1, c: 0 }, e: { r: 1, c: 13 } }
    ];

    XLSX.utils.book_append_sheet(wb, ws, 'Produção');

    // Ajustar largura das colunas
    ws['!cols'] = [
      { wch: 15 }, // Código Interno
      { wch: 25 }, // Componente
      { wch: 15 }, // Device
      { wch: 15 }, // Value
      { wch: 15 }, // Package
      { wch: 25 }, // Características
      { wch: 10 }, // Gaveta
      { wch: 10 }, // Divisão
      { wch: 12 }, // Qtd/Unidade
      { wch: 12 }, // Qtd Total
      { wch: 12 }, // Em Estoque
      { wch: 12 }, // Comprar
      { wch: 12 }, // Preço Unit.
      { wch: 15 }  // Preço Total
    ];

    // Gerar nome do arquivo
    const filename = `${productName.replace(/\s+/g, '_')}_producao_${new Date().toISOString().split('T')[0]}.xlsx`;
    
    // Gerar arquivo Excel
    XLSX.writeFile(wb, filename);
  }

  /**
   * Exporta plano de produção para Excel
   */
  exportProductionPlan(data: ProductionPlanRow[], filename?: string) {
    // Preparar dados principais
    const mainData = data.map(row => ({
      'QTD FABRICAR': row.qtdFabricar,
      'Qtd. Total': row.qtdTotal,
      'Device': row.device,
      'Value': row.value,
      'Package': row.package,
      'Características': row.caracteristicas,
      'Cód.': row.codigo,
      'Gaveta': row.gaveta,
      'Divisão': row.divisao,
      'Qtd. Estoque': row.qtdEstoque,
      'Qtd. Compra': row.qtdCompra
    }));

    // Criar worksheet principal
    const ws = XLSX.utils.json_to_sheet(mainData);
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'Plano de Produção');

    // Criar aba de componentes para compra
    const itemsNeedingPurchase = data.filter(row => row.qtdCompra > 0);
    if (itemsNeedingPurchase.length > 0) {
      const purchaseData = itemsNeedingPurchase.map(row => ({
        'Device': row.device,
        'Value': row.value,
        'Package': row.package,
        'Características': row.caracteristicas,
        'Código': row.codigo,
        'Gaveta': row.gaveta,
        'Divisão': row.divisao,
        'Estoque Atual': row.qtdEstoque,
        'Quantidade Necessária': row.qtdCompra
      }));

      const wsPurchase = XLSX.utils.json_to_sheet(purchaseData);
      XLSX.utils.book_append_sheet(wb, wsPurchase, 'Lista de Compras');
    }

    // Ajustar largura das colunas
    ws['!cols'] = [
      { wch: 12 }, // QTD FABRICAR
      { wch: 12 }, // Qtd. Total
      { wch: 15 }, // Device
      { wch: 15 }, // Value
      { wch: 15 }, // Package
      { wch: 25 }, // Características
      { wch: 12 }, // Cód.
      { wch: 10 }, // Gaveta
      { wch: 10 }, // Divisão
      { wch: 12 }, // Qtd. Estoque
      { wch: 12 }  // Qtd. Compra
    ];

    // Gerar arquivo Excel
    const exportFilename = filename || `plano_producao_${new Date().toISOString().split('T')[0]}.xlsx`;
    XLSX.writeFile(wb, exportFilename);
  }

  /**
   * Download template de importação
   */
  downloadImportTemplate() {
    const data = [{
      'Nome': 'Resistor 10K',
      'Descrição': 'Resistor de 10K Ohms',
      'Grupo': 'Resistor',
      'Device': 'SMD',
      'Value': '10K',
      'Package': '0805',
      'Características': '1/4W 5%',
      'Código Interno': 'RES-001',
      'Preço': 0.15,
      'Ambiente': 'estoque',
      'Gaveta': 'A1',
      'Divisão': '1',
      'NCM': '85411000',
      'NVE': '00',
      'Quantidade em Estoque': 100,
      'Quantidade Mínima': 20
    }];

    const ws = XLSX.utils.json_to_sheet(data);
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'Template');

    // Ajustar largura das colunas
    ws['!cols'] = Array(16).fill({ wch: 20 });

    XLSX.writeFile(wb, 'template_importacao_componentes.xlsx');
  }

  /**
   * Processa arquivo de importação Excel
   */
  async processImportFile(file: File): Promise<Partial<Component>[]> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      
      reader.onload = (e) => {
        try {
          const data = new Uint8Array(e.target?.result as ArrayBuffer);
          const workbook = XLSX.read(data, { type: 'array' });
          
          // Pegar primeira planilha
          const firstSheet = workbook.Sheets[workbook.SheetNames[0]];
          const jsonData = XLSX.utils.sheet_to_json(firstSheet);

          if (jsonData.length === 0) {
            throw new Error('Arquivo vazio ou sem dados');
          }

          const components: Partial<Component>[] = jsonData.map((row: any, index) => {
            // Validar campos obrigatórios
            if (!row['Nome'] || !row['Grupo']) {
              throw new Error(`Linha ${index + 2}: Nome e Grupo são obrigatórios`);
            }

            return {
              name: row['Nome'],
              description: row['Descrição'] || undefined,
              group: row['Grupo'],
              device: row['Device'] || undefined,
              value: row['Value'] || undefined,
              package: row['Package'] || undefined,
              characteristics: row['Características'] || undefined,
              internalCode: row['Código Interno'] || undefined,
              price: row['Preço'] ? parseFloat(row['Preço']) : undefined,
              environment: (row['Ambiente'] === 'laboratorio' ? 'laboratorio' : 'estoque') as 'estoque' | 'laboratorio',
              drawer: row['Gaveta'] || undefined,
              division: row['Divisão'] || undefined,
              ncm: row['NCM'] || undefined,
              nve: row['NVE'] || undefined,
              quantityInStock: parseInt(row['Quantidade em Estoque']) || 0,
              minimumQuantity: parseInt(row['Quantidade Mínima']) || 0
            };
          });

          resolve(components);
        } catch (error) {
          reject(error);
        }
      };

      reader.onerror = () => {
        reject(new Error('Erro ao ler arquivo'));
      };

      reader.readAsArrayBuffer(file);
    });
  }

  /**
   * Exporta componentes para arquivo CSV (mantido para compatibilidade)
   */
  exportComponentsToCSV(components: Component[], filename: string = 'componentes.csv') {
    // Usar a função Excel por padrão
    this.exportComponentsToExcel(components, filename.replace('.csv', '.xlsx'));
  }
/**
 * Exporta produto com ordem customizada de componentes
 */
exportProductWithCustomOrder(
  product: { name: string; components: any[] },
  components: Component[],
  componentOrder: number[],
  productionQuantity: number = 1
) {
  // Reorganizar componentes baseado na ordem customizada
  const orderedComponents = componentOrder.map(compId => {
    const pc = product.components.find(c => c.componentId === compId);
    const component = components.find(c => c.id === compId);
    
    if (!pc || !component) return null;

    return {
      componentName: pc.componentName || component.name,
      device: component.device,
      value: component.value,
      package: component.package,
      characteristics: component.characteristics,
      internalCode: component.internalCode,
      drawer: component.drawer,
      division: component.division,
      quantityPerUnit: pc.quantity,
      totalQuantityNeeded: pc.quantity * productionQuantity,
      quantityInStock: component.quantityInStock,
      suggestedPurchase: Math.max(0, (pc.quantity * productionQuantity) - component.quantityInStock),
      unitPrice: component.price,
      totalPrice: (component.price || 0) * pc.quantity * productionQuantity
    };
  }).filter(Boolean);

  const reportData: ProductionReportDto = {
    productName: product.name,
    unitsToManufacture: productionQuantity,
    components: orderedComponents as any[]
  };

  this.exportProductionReport(reportData);
}

/**
 * Exporta componentes com filtros aplicados
 */
exportComponentsFiltered(
  components: Component[],
  filters: {
    selectedColumns?: Set<string>;
    group?: string;
    device?: string;
    package?: string;
    value?: string;
  },
  filename?: string
) {
  // Aplicar filtros se existirem
  let filteredComponents = components;
  
  if (filters.group) {
    filteredComponents = filteredComponents.filter(c => c.group === filters.group);
  }
  if (filters.device) {
    filteredComponents = filteredComponents.filter(c => c.device === filters.device);
  }
  if (filters.package) {
    filteredComponents = filteredComponents.filter(c => c.package === filters.package);
  }
  if (filters.value) {
    filteredComponents = filteredComponents.filter(c => c.value === filters.value);
  }

  // Se tiver colunas selecionadas, filtrar
  if (filters.selectedColumns && filters.selectedColumns.size > 0) {
    const columnsArray = Array.from(filters.selectedColumns);
    const processedData = filteredComponents.map(comp => {
      const filtered: any = {};
      
      columnsArray.forEach(col => {
        if (col in comp) {
          filtered[col] = comp[col as keyof Component];
        }
      });
      
      return filtered;
    });
    
    // Criar workbook com dados filtrados
    const ws = XLSX.utils.json_to_sheet(processedData);
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'Componentes Filtrados');
    
    const exportFilename = filename || `componentes_filtrados_${new Date().toISOString().split('T')[0]}.xlsx`;
    XLSX.writeFile(wb, exportFilename);
  } else {
    // Exportar normal se não tiver filtros de colunas
    this.exportComponentsToExcel(filteredComponents, filename);
  }
}

/**
 * Exporta relatório resumido de estoque
 */
exportStockSummaryReport(components: Component[]) {
  const summary = {
    totalComponents: components.length,
    totalValue: 0,
    lowStockItems: 0,
    outOfStockItems: 0,
    byGroup: {} as { [key: string]: number },
    criticalItems: [] as any[]
  };

  components.forEach(comp => {
    // Calcular valor total
    summary.totalValue += (comp.price || 0) * comp.quantityInStock;
    
    // Contar itens com estoque baixo/zerado
    if (comp.quantityInStock === 0) {
      summary.outOfStockItems++;
    } else if (comp.quantityInStock <= comp.minimumQuantity) {
      summary.lowStockItems++;
    }
    
    // Agrupar por categoria
    if (!summary.byGroup[comp.group]) {
      summary.byGroup[comp.group] = 0;
    }
    summary.byGroup[comp.group]++;
    
    // Listar itens críticos
    if (comp.quantityInStock <= comp.minimumQuantity) {
      summary.criticalItems.push({
        name: comp.name,
        group: comp.group,
        currentStock: comp.quantityInStock,
        minimumStock: comp.minimumQuantity,
        deficit: comp.minimumQuantity - comp.quantityInStock
      });
    }
  });

  // Criar planilha de resumo
  const summaryData = [
    { Métrica: 'Total de Componentes', Valor: summary.totalComponents },
    { Métrica: 'Valor Total em Estoque', Valor: `R$ ${summary.totalValue.toFixed(2)}` },
    { Métrica: 'Itens com Estoque Baixo', Valor: summary.lowStockItems },
    { Métrica: 'Itens Sem Estoque', Valor: summary.outOfStockItems }
  ];

  const wb = XLSX.utils.book_new();
  
  // Aba de resumo
  const wsSummary = XLSX.utils.json_to_sheet(summaryData);
  XLSX.utils.book_append_sheet(wb, wsSummary, 'Resumo');
  
  // Aba de itens críticos
  if (summary.criticalItems.length > 0) {
    const wsCritical = XLSX.utils.json_to_sheet(summary.criticalItems);
    XLSX.utils.book_append_sheet(wb, wsCritical, 'Itens Críticos');
  }
  
  // Aba de distribuição por grupo
  const groupData = Object.entries(summary.byGroup).map(([group, count]) => ({
    Grupo: group,
    'Quantidade de Itens': count
  }));
  const wsGroups = XLSX.utils.json_to_sheet(groupData);
  XLSX.utils.book_append_sheet(wb, wsGroups, 'Por Grupo');
  
  const filename = `resumo_estoque_${new Date().toISOString().split('T')[0]}.xlsx`;
  XLSX.writeFile(wb, filename);
}

}

export default new ExportService();