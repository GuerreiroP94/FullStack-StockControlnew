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
    public class StockMovementController : ControllerBase
    {
        private readonly IStockMovementService _stockMovementService;
        private readonly ILogger<StockMovementController> _logger;

        public StockMovementController(IStockMovementService stockMovementService, ILogger<StockMovementController> logger)
        {
            _stockMovementService = stockMovementService;
            _logger = logger;
        }

        // GET: api/StockMovement
        [HttpGet]
        public async Task<ActionResult<IEnumerable<StockMovementDto>>> GetAll([FromQuery] StockMovementQueryParameters parameters)
        {
            var movements = await _stockMovementService.GetAllMovementsAsync(parameters);
            return Ok(movements);
        }

        // GET: api/StockMovement/component/5
        [HttpGet("component/{componentId}")]
        public async Task<ActionResult<IEnumerable<StockMovementDto>>> GetByComponentId(int componentId)
        {
            var movements = await _stockMovementService.GetMovementByIdAsync(componentId);
            return Ok(movements);
        }

        // POST: api/StockMovement
        [HttpPost]
        [Authorize(Roles = "admin")]
        public async Task<ActionResult<StockMovementDto>> Create([FromBody] StockMovementCreateDto dto)
        {
            var created = await _stockMovementService.RegisterMovementAsync(dto);
            return CreatedAtAction(nameof(GetAll), new { id = created.Id }, created);
        }

        // POST: api/StockMovement/bulk (Movimentações em massa)
        [HttpPost("bulk")]
        [Authorize(Roles = "admin")]
        public async Task<ActionResult<BulkMovementResultDto>> CreateBulkMovements([FromBody] BulkStockMovementDto dto)
        {
            if (dto.Movements == null || !dto.Movements.Any())
            {
                return BadRequest("Nenhuma movimentação fornecida");
            }

            try
            {
                var result = await _stockMovementService.RegisterBulkMovementsAsync(dto);

                if (result.Success)
                {
                    return Ok(result);
                }
                else
                {
                    return BadRequest(result);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro ao processar movimentações em massa");
                return StatusCode(500, new { message = "Erro ao processar movimentações", error = ex.Message });
            }
        }
    }
}