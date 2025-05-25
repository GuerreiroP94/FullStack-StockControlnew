using PreSystem.StockControl.Application.DTOs;
using PreSystem.StockControl.Application.DTOs.Filters;
using PreSystem.StockControl.Application.Interfaces.Services;
using PreSystem.StockControl.Domain.Interfaces.Repositories;

namespace PreSystem.StockControl.Application.Services
{
    public class StockAlertService : IStockAlertService
    {
        private readonly IStockAlertRepository _alertRepository;

        public StockAlertService(IStockAlertRepository alertRepository)
        {
            _alertRepository = alertRepository;
        }

        // Retorna todos os alertas de estoque
        public async Task<IEnumerable<StockAlertDto>> GetAllAlertsAsync(StockAlertQueryParameters parameters)
        {
            var alerts = await _alertRepository.GetAllAsync();

            if (parameters.ComponentId.HasValue)
                alerts = alerts.Where(a => a.ComponentId == parameters.ComponentId.Value);

            if (parameters.FromDate.HasValue)
                alerts = alerts.Where(a => a.CreatedAt >= parameters.FromDate.Value);

            if (parameters.ToDate.HasValue)
                alerts = alerts.Where(a => a.CreatedAt <= parameters.ToDate.Value);

            alerts = alerts
                .OrderByDescending(a => a.CreatedAt)
                .Skip((parameters.Page - 1) * parameters.PageSize)
                .Take(parameters.PageSize);

            return alerts.Select(a => new StockAlertDto
            {
                Id = a.Id,
                ComponentId = a.ComponentId,
                Message = a.Message,
                CreatedAt = a.CreatedAt
            });
        }


        // Retorna os alertas de um componente específico
        public async Task<IEnumerable<StockAlertDto>> GetAlertsByComponentIdAsync(int componentId)
        {
            var alerts = await _alertRepository.GetByComponentIdAsync(componentId);

            return alerts.Select(alert => new StockAlertDto
            {
                Id = alert.Id,
                ComponentId = alert.ComponentId,
                Message = alert.Message,
                CreatedAt = alert.CreatedAt
            });
        }
    }
}
