import { Component } from '../types';

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
   * Nota: Para um verdadeiro arquivo Excel (.xlsx), seria necessário usar uma biblioteca como xlsx ou sheetjs
   */
  exportComponentsToExcel(components: Component[], filename: string = 'componentes.xlsx') {
    // Por enquanto, vamos exportar como CSV com extensão .xls
    // que pode ser aberto no Excel
    this.exportComponentsToCSV(components, filename.replace('.xlsx', '.csv'));
  }

  /**
   * Prepara dados para importação em massa
   * Retorna um template CSV vazio com os cabeçalhos corretos
   */
  downloadImportTemplate() {
    const headers = [
      'Nome*',
      'Grupo*',
      'Device',
      'Value',
      'Package',
      'Características',
      'Código Interno',
      'Gaveta',
      'Divisão',
      'Quantidade em Estoque*',
      'Quantidade Mínima*',
      'Preço',
      'NCM',
      'NVE',
      'Ambiente (estoque/laboratorio)',
      'Descrição'
    ];

    const exampleRow = [
      '12F1572',
      'Semicondutor',
      'Microcontrolador',
      '12F615',
      'SOIC-8',
      'Microcontrolador PIC 8 bits',
      'MC001',
      'A1',
      'B',
      '100',
      '20',
      '15.50',
      '8542.31.10',
      'AB1234',
      'estoque',
      'Microcontrolador PIC de 8 bits com 1.75KB de memória flash'
    ];

    const csvContent = [
      headers.join(';'),
      exampleRow.join(';'),
      '* Campos obrigatórios'
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
            
            if (values.length < 11) {
              throw new Error(`Linha ${index + 2}: número insuficiente de colunas`);
            }

            return {
              name: values[0],
              group: values[1],
              device: values[2] || undefined,
              value: values[3] || undefined,
              package: values[4] || undefined,
              characteristics: values[5] || undefined,
              internalCode: values[6] || undefined,
              drawer: values[7] || undefined,
              division: values[8] || undefined,
              quantityInStock: parseInt(values[9]) || 0,
              minimumQuantity: parseInt(values[10]) || 0,
              price: parseFloat(values[11]) || undefined,
              ncm: values[12] || undefined,
              nve: values[13] || undefined,
              environment: (values[14] === 'laboratorio' ? 'laboratorio' : 'estoque') as 'estoque' | 'laboratorio',
              description: values[15] || undefined
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
 * Exporta relatório de produção para arquivo CSV/Excel
 * @param reportData Dados do relatório de produção
 */
exportProductionReport(reportData: any) {
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
    comp.name || '',
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
    comp.price ? `R$ ${comp.price.toFixed(2).replace('.', ',')}` : 'R$ 0,00',
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
}

export default new ExportService();