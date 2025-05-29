using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PreSystem.StockControl.Application.DTOs;
using PreSystem.StockControl.Application.DTOs.Filters;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class ExportController : ControllerBase
{
    // GET: api/export/components
    [HttpGet("components")]
    public async Task<IActionResult> ExportComponents([FromQuery] ComponentFilterDto filter)

    // POST: api/export/production-report
    [HttpPost("production-report")]
    public async Task<IActionResult> ExportProductionReport([FromBody] ProductionReportDto report)

    // GET: api/export/movements
    [HttpGet("movements")]
    public async Task<IActionResult> ExportMovements([FromQuery] StockMovementQueryParameters parameters)
}