import { Component } from '../types';

// Interface temporária para ProductionReportDto
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
   * Exporta componentes para arquivo CSV
   */
  exportComponentsToCSV(components: Component[], filename: string = 'componentes.csv') {
    // Cabeçalhos das colunas
    const headers = [
      'ID',
      'Nome',
      'Grupo',
      'Device',
      'Value',
      'Package',
      'Características',
      'Código Interno',
      'Gaveta',
      'Divisão',
      'Quantidade em Estoque',
      'Quantidade Mínima',
      'Preço',
      'NCM',
      'NVE',
      'Ambiente',
      'Data de Criação'
    ];

    // Converter componentes para linhas CSV
    const rows = components.map(comp => [
      comp.id,
      comp.name,
      comp.group,
      comp.device || '',
      comp.value || '',
      comp.package || '',
      comp.characteristics || '',
      comp.internalCode || '',
      comp.drawer || '',
      comp.division || '',
      comp.quantityInStock,
      comp.minimumQuantity,
      comp.price || '',
      comp.ncm || '',
      comp.nve || '',
      comp.environment === 'laboratorio' ? 'Laboratório' : 'Estoque',
      comp.createdAt ? new Date(comp.createdAt).toLocaleDateString('pt-BR') : ''
    ]);

    // Criar conteúdo CSV
    const csvContent = [
      headers.join(';'),
      ...rows.map(row => row.join(';'))
    ].join('\n');

    // Criar blob e fazer download
    const blob = new Blob(['\ufeff' + csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    const url = URL.createObjectURL(blob);
    
    link.setAttribute('href', url);
    link.setAttribute('download', filename);
    link.style.visibility = 'hidden';
    
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }

  /**
   * Exporta componentes para formato Excel-compatível (CSV com separador de ponto e vírgula)
   */
  exportComponentsToExcel(components: Component[], filename: string = 'componentes.xlsx') {
    // Por enquanto, vamos exportar como CSV com extensão .csv
    // que pode ser aberto no Excel
    this.exportComponentsToCSV(components, filename.replace('.xlsx', '.csv'));
  }

  /**
   * Prepara dados para importação em massa
   * Retorna um template CSV vazio com os cabeçalhos corretos
   */
  downloadImportTemplate() {
    const headers = [
      'Name',
      'Description',
      'Group',
      'Device',
      'Value',
      'Package',
      'Characteristics',
      'InternalCode',
      'Price',
      'Environment',
      'Drawer',
      'Division',
      'NCM',
      'NVE',
      'QuantityInStock',
      'MinimumQuantity'
    ];

    const exampleRow = [
      'Resistor 10K',
      'Resistor de 10K Ohms',
      'Resistor',
      'SMD',
      '10K',
      '0805',
      '1/4W 5%',
      'RES-001',
      '0.15',
      'estoque',
      'A1',
      '1',
      '85411000',
      '00',
      '100',
      '20'
    ];

    const csvContent = [
      headers.join(';'),
      exampleRow.join(';')
    ].join('\n');

    const blob = new Blob(['\ufeff' + csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    const url = URL.createObjectURL(blob);
    
    link.setAttribute('href', url);
    link.setAttribute('download', 'template_importacao_componentes.csv');
    link.style.visibility = 'hidden';
    
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }

  /**
   * Processa arquivo de importação
   * @param file Arquivo CSV para importar
   * @returns Promise com array de componentes processados
   */
  async processImportFile(file: File): Promise<Partial<Component>[]> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      
      reader.onload = (e) => {
        try {
          const text = e.target?.result as string;
          const lines = text.split('\n').filter(line => line.trim());
          
          if (lines.length < 2) {
            throw new Error('Arquivo vazio ou sem dados');
          }

          // Pular cabeçalho
          const dataLines = lines.slice(1);
          
          const components: Partial<Component>[] = dataLines.map((line, index) => {
            const values = line.split(';').map(v => v.trim());
            
            if (values.length < 16) {
              throw new Error(`Linha ${index + 2}: número insuficiente de colunas`);
            }

            return {
              name: values[0],
              description: values[1] || undefined,
              group: values[2],
              device: values[3] || undefined,
              value: values[4] || undefined,
              package: values[5] || undefined,
              characteristics: values[6] || undefined,
              internalCode: values[7] || undefined,
              price: values[8] ? parseFloat(values[8]) : undefined,
              environment: (values[9] === 'laboratorio' ? 'laboratorio' : 'estoque') as 'estoque' | 'laboratorio',
              drawer: values[10] || undefined,
              division: values[11] || undefined,
              ncm: values[12] || undefined,
              nve: values[13] || undefined,
              quantityInStock: parseInt(values[14]) || 0,
              minimumQuantity: parseInt(values[15]) || 0
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

      reader.readAsText(file, 'UTF-8');
    });
  }

  /**
   * Exporta relatório de produção para arquivo CSV
   * @param reportData Dados do relatório de produção
   */
  exportProductionReport(reportData: ProductionReportDto) {
    const { productName, unitsToManufacture, components } = reportData;
    
    // Cabeçalhos das colunas
    const headers = [
      'Código Interno',
      'Componente',
      'Device',
      'Value',
      'Package',
      'Características',
      'Gaveta',
      'Divisão',
      'Qtd/Unidade',
      'Qtd Total',
      'Em Estoque',
      'Comprar',
      'Preço Unit.',
      'Preço Total'
    ];

    // Título do relatório
    const title = `RELATÓRIO DE PRODUÇÃO - ${productName}`;
    const subtitle = `Unidades a Fabricar: ${unitsToManufacture}`;
    
    // Preparar dados para o CSV
    const rows = components.map((comp: any) => [
      comp.internalCode || '',
      comp.componentName || '',
      comp.device || '',
      comp.value || '',
      comp.package || '',
      comp.characteristics || '',
      comp.drawer || '',
      comp.division || '',
      comp.quantityPerUnit || 0,
      comp.totalQuantityNeeded || 0,
      comp.quantityInStock || 0,
      comp.suggestedPurchase || 0,
      comp.unitPrice ? `R$ ${comp.unitPrice.toFixed(2).replace('.', ',')}` : 'R$ 0,00',
      `R$ ${comp.totalPrice.toFixed(2).replace('.', ',')}`
    ]);

    // Calcular total geral
    const totalGeral = components.reduce((sum: number, comp: any) => sum + (comp.totalPrice || 0), 0);
    
    // Adicionar linha de total
    rows.push([
      '', '', '', '', '', '', '', '',
      'TOTAL:', '', '', '',
      '',
      `R$ ${totalGeral.toFixed(2).replace('.', ',')}`
    ]);

    // Criar conteúdo CSV
    const csvContent = [
      title,
      subtitle,
      '', // linha vazia
      headers.join(';'),
      ...rows.map((row: any[]) => row.join(';'))
    ].join('\n');

    // Criar blob e fazer download
    const blob = new Blob(['\ufeff' + csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    const url = URL.createObjectURL(blob);
    
    const filename = `relatorio_producao_${productName.replace(/\s+/g, '_')}_${new Date().toISOString().split('T')[0]}.csv`;
    
    link.setAttribute('href', url);
    link.setAttribute('download', filename);
    link.style.visibility = 'hidden';
    
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }

  /**
   * Exporta plano de produção para arquivo CSV
   * @param data Array com os dados do plano de produção
   */
  exportProductionPlan(data: ProductionPlanRow[]) {
    // Cabeçalhos das colunas alinhados com o modelo da imagem
    const headers = [
      'QTD FABRICAR',
      'Qtd. Total',
      'Device',
      'Value',
      'Package',
      'Características',
      'Cód.',
      'Gaveta',
      'Divisão',
      'Qtd. Estoque',
      'Qtd. Compra'
    ];

    // Converter dados para linhas CSV
    const rows = data.map(row => [
      row.qtdFabricar,
      row.qtdTotal,
      row.device,
      row.value,
      row.package,
      row.caracteristicas,
      row.codigo,
      row.gaveta,
      row.divisao,
      row.qtdEstoque,
      row.qtdCompra
    ]);

    // Adicionar linha vazia no final para indicar componentes com compra necessária
    const rowsNeedingPurchase = data.filter(row => row.qtdCompra > 0);
    if (rowsNeedingPurchase.length > 0) {
      rows.push(['', '', '', '', '', '', '', '', '', '', '']);
      rows.push(['COMPONENTES QUE PRECISAM SER COMPRADOS:', '', '', '', '', '', '', '', '', '', '']);
      rowsNeedingPurchase.forEach(row => {
        rows.push([
          '',
          '',
          row.device,
          row.value,
          row.package,
          row.caracteristicas,
          row.codigo,
          row.gaveta,
          row.divisao,
          row.qtdEstoque,
          row.qtdCompra
        ]);
      });
    }

    // Criar conteúdo CSV
    const csvContent = [
      headers.join(';'),
      ...rows.map(row => row.join(';'))
    ].join('\n');

    // Criar blob e fazer download
    const blob = new Blob(['\ufeff' + csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    const url = URL.createObjectURL(blob);
    
    const filename = `plano_producao_${new Date().toISOString().split('T')[0]}.csv`;
    
    link.setAttribute('href', url);
    link.setAttribute('download', filename);
    link.style.visibility = 'hidden';
    
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }
}

export default new ExportService();