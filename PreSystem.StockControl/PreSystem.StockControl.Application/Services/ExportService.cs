using ClosedXML.Excel;
using Microsoft.Extensions.Logging;
using PreSystem.StockControl.Application.DTOs;
using PreSystem.StockControl.Application.Interfaces.Services;
using System.Data;
using System.Drawing;

namespace PreSystem.StockControl.Application.Services
{
    public class ExportService : IExportService
    {
        private readonly ILogger<ExportService> _logger;

        public ExportService(ILogger<ExportService> logger)
        {
            _logger = logger;
        }

        // Exporta componentes para Excel
        public async Task<byte[]> ExportComponentsToExcelAsync(IEnumerable<ComponentDto> components)
        {
            await Task.CompletedTask; // Resolver warning de async

            using var workbook = new XLWorkbook();
            var worksheet = workbook.Worksheets.Add("Componentes");

            // Cabeçalhos
            var headers = new[]
            {
                "ID", "Código Interno", "Nome", "Descrição", "Grupo", "Device", "Value", "Package",
                "Características", "Quantidade em Estoque", "Quantidade Mínima", "Preço",
                "Ambiente", "Gaveta", "Divisão", "NCM", "NVE", "Última Entrada", "Qtd Entrada", "Qtd Saída"
            };

            for (int i = 0; i < headers.Length; i++)
            {
                worksheet.Cell(1, i + 1).Value = headers[i];
                worksheet.Cell(1, i + 1).Style.Font.Bold = true;
                worksheet.Cell(1, i + 1).Style.Fill.BackgroundColor = XLColor.LightGray;
            }

            // Dados
            int row = 2;
            foreach (var comp in components)
            {
                worksheet.Cell(row, 1).Value = comp.Id;
                worksheet.Cell(row, 2).Value = comp.InternalCode ?? "";
                worksheet.Cell(row, 3).Value = comp.Name;
                worksheet.Cell(row, 4).Value = comp.Description ?? "";
                worksheet.Cell(row, 5).Value = comp.Group;
                worksheet.Cell(row, 6).Value = comp.Device ?? "";
                worksheet.Cell(row, 7).Value = comp.Value ?? "";
                worksheet.Cell(row, 8).Value = comp.Package ?? "";
                worksheet.Cell(row, 9).Value = comp.Characteristics ?? "";
                worksheet.Cell(row, 10).Value = comp.QuantityInStock;
                worksheet.Cell(row, 11).Value = comp.MinimumQuantity;
                worksheet.Cell(row, 12).Value = comp.Price ?? 0;
                worksheet.Cell(row, 12).Style.NumberFormat.Format = "R$ #,##0.00";
                worksheet.Cell(row, 13).Value = comp.Environment;
                worksheet.Cell(row, 14).Value = comp.Drawer ?? "";
                worksheet.Cell(row, 15).Value = comp.Division ?? "";
                worksheet.Cell(row, 16).Value = comp.NCM ?? "";
                worksheet.Cell(row, 17).Value = comp.NVE ?? "";
                worksheet.Cell(row, 18).Value = comp.LastEntryDate?.ToString("dd/MM/yyyy") ?? "";
                worksheet.Cell(row, 19).Value = comp.LastEntryQuantity ?? 0;
                worksheet.Cell(row, 20).Value = comp.LastExitQuantity ?? 0;
                row++;
            }

            // Ajusta largura das colunas
            worksheet.Columns().AdjustToContents();

            // Salva em memória
            using var stream = new MemoryStream();
            workbook.SaveAs(stream);
            return stream.ToArray();
        }

        // Exporta relatório de produção para Excel
        public async Task<byte[]> ExportProductionReportToExcelAsync(ProductionReportDto report)
        {
            await Task.CompletedTask; // Resolver warning de async

            using var workbook = new XLWorkbook();
            var worksheet = workbook.Worksheets.Add("Relatório de Produção");

            // Título
            worksheet.Cell(1, 1).Value = "RELATÓRIO DE PRODUÇÃO";
            worksheet.Cell(1, 1).Style.Font.Bold = true;
            worksheet.Cell(1, 1).Style.Font.FontSize = 16;
            worksheet.Range(1, 1, 1, 12).Merge();

            worksheet.Cell(3, 1).Value = "Produto:";
            worksheet.Cell(3, 2).Value = report.ProductName;
            worksheet.Cell(3, 2).Style.Font.Bold = true;

            worksheet.Cell(4, 1).Value = "Unidades a Fabricar:";
            worksheet.Cell(4, 2).Value = report.UnitsToManufacture;
            worksheet.Cell(4, 2).Style.Font.Bold = true;

            // Cabeçalhos da tabela
            var headers = new[]
            {
                "Código Interno", "Componente", "Device", "Value", "Package", "Características",
                "Gaveta", "Divisão", "Qtd/Unidade", "Qtd Total", "Em Estoque", "Comprar", "Preço Unit.", "Preço Total"
            };

            int startRow = 6;
            for (int i = 0; i < headers.Length; i++)
            {
                worksheet.Cell(startRow, i + 1).Value = headers[i];
                worksheet.Cell(startRow, i + 1).Style.Font.Bold = true;
                worksheet.Cell(startRow, i + 1).Style.Fill.BackgroundColor = XLColor.DarkBlue;
                worksheet.Cell(startRow, i + 1).Style.Font.FontColor = XLColor.White;
            }

            // Dados
            int row = startRow + 1;
            decimal totalPrice = 0;

            foreach (var item in report.Components)
            {
                worksheet.Cell(row, 1).Value = item.InternalCode ?? "";
                worksheet.Cell(row, 2).Value = item.ComponentName;
                worksheet.Cell(row, 3).Value = item.Device ?? "";
                worksheet.Cell(row, 4).Value = item.Value ?? "";
                worksheet.Cell(row, 5).Value = item.Package ?? "";
                worksheet.Cell(row, 6).Value = item.Characteristics ?? "";
                worksheet.Cell(row, 7).Value = item.Drawer ?? "";
                worksheet.Cell(row, 8).Value = item.Division ?? "";
                worksheet.Cell(row, 9).Value = item.QuantityPerUnit;
                worksheet.Cell(row, 10).Value = item.TotalQuantityNeeded;
                worksheet.Cell(row, 11).Value = item.QuantityInStock;
                worksheet.Cell(row, 12).Value = item.SuggestedPurchase;

                if (item.SuggestedPurchase > 0)
                {
                    worksheet.Cell(row, 12).Style.Font.FontColor = XLColor.Red;
                    worksheet.Cell(row, 12).Style.Font.Bold = true;
                }

                worksheet.Cell(row, 13).Value = item.UnitPrice ?? 0;
                worksheet.Cell(row, 13).Style.NumberFormat.Format = "R$ #,##0.00";
                worksheet.Cell(row, 14).Value = item.TotalPrice;
                worksheet.Cell(row, 14).Style.NumberFormat.Format = "R$ #,##0.00";

                totalPrice += item.TotalPrice;
                row++;
            }

            // Total
            worksheet.Cell(row + 1, 13).Value = "TOTAL:";
            worksheet.Cell(row + 1, 13).Style.Font.Bold = true;
            worksheet.Cell(row + 1, 14).Value = totalPrice;
            worksheet.Cell(row + 1, 14).Style.NumberFormat.Format = "R$ #,##0.00";
            worksheet.Cell(row + 1, 14).Style.Font.Bold = true;

            // Ajusta largura das colunas
            worksheet.Columns().AdjustToContents();

            // Adiciona bordas
            var tableRange = worksheet.Range(startRow, 1, row - 1, headers.Length);
            tableRange.Style.Border.OutsideBorder = XLBorderStyleValues.Thin;
            tableRange.Style.Border.InsideBorder = XLBorderStyleValues.Thin;

            // Salva em memória
            using var stream = new MemoryStream();
            workbook.SaveAs(stream);
            return stream.ToArray();
        }

        // Exporta movimentações para Excel
        public async Task<byte[]> ExportMovementsToExcelAsync(IEnumerable<StockMovementDto> movements)
        {
            await Task.CompletedTask; // Resolver warning de async

            using var workbook = new XLWorkbook();
            var worksheet = workbook.Worksheets.Add("Movimentações");

            // Cabeçalhos
            var headers = new[]
            {
                "ID", "Data/Hora", "Tipo", "Componente", "Quantidade", "Responsável", "Usuário"
            };

            for (int i = 0; i < headers.Length; i++)
            {
                worksheet.Cell(1, i + 1).Value = headers[i];
                worksheet.Cell(1, i + 1).Style.Font.Bold = true;
                worksheet.Cell(1, i + 1).Style.Fill.BackgroundColor = XLColor.LightGray;
            }

            // Dados
            int row = 2;
            foreach (var mov in movements)
            {
                worksheet.Cell(row, 1).Value = mov.Id;
                worksheet.Cell(row, 2).Value = mov.MovementDate.ToString("dd/MM/yyyy HH:mm");
                worksheet.Cell(row, 3).Value = mov.MovementType;

                if (mov.MovementType == "Entrada")
                {
                    worksheet.Cell(row, 3).Style.Font.FontColor = XLColor.Green;
                }
                else
                {
                    worksheet.Cell(row, 3).Style.Font.FontColor = XLColor.Red;
                }

                worksheet.Cell(row, 4).Value = $"Componente #{mov.ComponentId}";
                worksheet.Cell(row, 5).Value = mov.Quantity;
                worksheet.Cell(row, 6).Value = mov.PerformedBy;
                worksheet.Cell(row, 7).Value = mov.UserName ?? "";
                row++;
            }

            // Ajusta largura das colunas
            worksheet.Columns().AdjustToContents();

            // Salva em memória
            using var stream = new MemoryStream();
            workbook.SaveAs(stream);
            return stream.ToArray();
        }
    }
}