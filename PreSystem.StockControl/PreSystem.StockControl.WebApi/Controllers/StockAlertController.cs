using Microsoft.AspNetCore.Mvc;
using PreSystem.StockControl.Application.Interfaces.Services;
using PreSystem.StockControl.Application.DTOs;
using PreSystem.StockControl.Application.DTOs.Filters;
using Microsoft.AspNetCore.Authorization;

namespace PreSystem.StockControl.WebApi.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api/[controller]")]
    [Authorize] // Essa linha garante que só acessa quem tiver JWT válido
    public class StockAlertController : ControllerBase
    {
        private readonly IStockAlertService _alertService;

        public StockAlertController(IStockAlertService alertService)
        {
            _alertService = alertService;
        }

        // GET: api/StockAlert
        [HttpGet]
        public async Task<ActionResult<IEnumerable<StockAlertDto>>> GetAll([FromQuery] StockAlertQueryParameters parameters)
        {
            var alerts = await _alertService.GetAllAlertsAsync(parameters);
            return Ok(alerts);
        }


        // GET: api/StockAlert/component/{componentId}
        [HttpGet("component/{componentId}")]
        public async Task<ActionResult<IEnumerable<StockAlertDto>>> GetByComponent(int componentId)
        {
            var alerts = await _alertService.GetAlertsByComponentIdAsync(componentId);
            return Ok(alerts);
        }
    }
}
