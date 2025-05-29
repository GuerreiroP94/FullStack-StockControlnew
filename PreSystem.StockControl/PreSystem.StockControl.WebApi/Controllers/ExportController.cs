using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PreSystem.StockControl.Application.DTOs;
using PreSystem.StockControl.Application.DTOs.Filters;
using PreSystem.StockControl.Application.Interfaces.Services;

namespace PreSystem.StockControl.WebApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class ExportController : ControllerBase
    {
        private readonly IExportService _exportService;
        private readonly IComponentService _componentService;
        private readonly IStockMovementService _movementService;

        public ExportController(
            IExportService exportService,
            IComponentService componentService,
            IStockMovementService movementService)
        {
            _exportService = exportService;
            _componentService = componentService;
            _movementService = movementService;
        }

        // GET: api/export/components
        [HttpGet("components")]
        public async Task<IActionResult> ExportComponents([FromQuery] ComponentFilterDto filter)
        {
            try
            {
                var components = await _componentService.GetAllComponentsAsync(filter);
                var fileBytes = await _exportService.ExportComponentsToExcelAsync(components);

                return File(fileBytes,
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    $"componentes_{DateTime.Now:yyyyMMdd_HHmmss}.xlsx");
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = "Erro ao exportar componentes", error = ex.Message });
            }
        }

        // POST: api/export/production-report
        [HttpPost("production-report")]
        public async Task<IActionResult> ExportProductionReport([FromBody] ProductionReportDto report)
        {
            try
            {
                var fileBytes = await _exportService.ExportProductionReportToExcelAsync(report);

                return File(fileBytes,
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    $"relatorio_producao_{DateTime.Now:yyyyMMdd_HHmmss}.xlsx");
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = "Erro ao exportar relatório", error = ex.Message });
            }
        }

        // GET: api/export/movements
        [HttpGet("movements")]
        public async Task<IActionResult> ExportMovements([FromQuery] StockMovementQueryParameters parameters)
        {
            try
            {
                var movements = await _movementService.GetAllMovementsAsync(parameters);
                var fileBytes = await _exportService.ExportMovementsToExcelAsync(movements);

                return File(fileBytes,
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    $"movimentacoes_{DateTime.Now:yyyyMMdd_HHmmss}.xlsx");
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = "Erro ao exportar movimentações", error = ex.Message });
            }
        }
    }
}