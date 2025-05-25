using Microsoft.AspNetCore.Mvc;
using PreSystem.StockControl.Application.DTOs;
using PreSystem.StockControl.Application.Interfaces.Services;
using Microsoft.AspNetCore.Authorization;
using PreSystem.StockControl.Application.DTOs.Filters;


namespace PreSystem.StockControl.WebApi.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api/[controller]")]
    [Authorize] // Essa linha garante que só acessa quem tiver JWT válido
    public class StockMovementController : ControllerBase
    {
        private readonly IStockMovementService _stockMovementService;

        public StockMovementController(IStockMovementService stockMovementService)
        {
            _stockMovementService = stockMovementService;
        }

        // GET: api/StockMovement
        [HttpGet]
        public async Task<ActionResult<IEnumerable<StockMovementDto>>> GetAll([FromQuery] StockMovementQueryParameters parameters)
        {
            var movements = await _stockMovementService.GetAllMovementsAsync(parameters);
            return Ok(movements);
        }

        //GET: api/StockMovement/component/5
        [HttpGet("component/{componentId}")]
        public async Task<ActionResult<IEnumerable<StockMovementDto>>> GetByComponentId(int componentId)
        {
            var movements = await _stockMovementService.GetMovementByIdAsync(componentId);
            return Ok(movements);
        }

        //POST: api/StockMovement
        [HttpPost]
        [Authorize(Roles = "Admin")] // Somente Admin pode registrar movimentações
        public async Task<ActionResult<StockMovementDto>> Create([FromBody] StockMovementCreateDto dto)

        {
            var created = await _stockMovementService.RegisterMovementAsync(dto);
            return CreatedAtAction(nameof(GetAll), new { id = created.Id }, created);
        }
    }
}
