using PreSystem.StockControl.Application.DTOs;

public interface IExportService
{
    Task<byte[]> ExportComponentsToExcelAsync(IEnumerable<ComponentDto> components);
    Task<byte[]> ExportProductionReportToExcelAsync(ProductionReportDto report);
    Task<byte[]> ExportMovementsToExcelAsync(IEnumerable<StockMovementDto> movements);
}