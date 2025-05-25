using PreSystem.StockControl.Application.DTOs;
using PreSystem.StockControl.Application.DTOs.Filters;

public interface IStockAlertService
{
    Task<IEnumerable<StockAlertDto>> GetAllAlertsAsync(StockAlertQueryParameters parameters);
    Task<IEnumerable<StockAlertDto>> GetAlertsByComponentIdAsync(int componentId);
}
