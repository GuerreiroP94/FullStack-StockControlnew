using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PreSystem.StockControl.Application.DTOs;
using PreSystem.StockControl.Application.DTOs.Filters;
using PreSystem.StockControl.Application.Interfaces.Services;

namespace PreSystem.StockControl.WebApi.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api/[controller]")]
    public class ComponentController : ControllerBase
    {
        private readonly IComponentService _componentService;
        private readonly ILogger<ComponentController> _logger;

        public ComponentController(IComponentService componentService, ILogger<ComponentController> logger)
        {
            _componentService = componentService;
            _logger = logger;
        }

        // GET: api/Component
        [HttpGet]
        public async Task<ActionResult<IEnumerable<ComponentDto>>> GetAll([FromQuery] ComponentFilterDto filter)
        {
            var components = await _componentService.GetAllComponentsAsync(filter);
            return Ok(components);
        }

        // GET: api/Component/{id}
        [HttpGet("{id}")]
        public async Task<ActionResult<ComponentDto>> GetById(int id)
        {
            var component = await _componentService.GetComponentByIdAsync(id);
            if (component == null) return NotFound();

            return Ok(component);
        }

        // POST: api/Component
        [HttpPost]
        public async Task<ActionResult<ComponentDto>> Create([FromBody] ComponentCreateDto dto)
        {
            var created = await _componentService.AddComponentAsync(dto);
            return CreatedAtAction(nameof(GetById), new { id = created.Id }, created);
        }

        // PUT: api/Component/{id}
        [HttpPut("{id}")]
        public async Task<ActionResult<ComponentDto>> Update(int id, [FromBody] ComponentCreateDto dto)
        {
            var updated = await _componentService.UpdateComponentAsync(id, dto);
            if (updated == null) return NotFound();

            return Ok(updated);
        }

        // DELETE: api/Component/{id}
        [HttpDelete("{id}")]
        [Authorize(Roles = "admin")]
        public async Task<IActionResult> Delete(int id)
        {
            var deleted = await _componentService.DeleteComponentAsync(id);
            if (!deleted) return NotFound();

            return NoContent();
        }

        // POST: api/Component/bulk (Importação em massa)
        [HttpPost("bulk")]
        [Authorize(Roles = "admin")]
        public async Task<ActionResult<ImportResultDto>> BulkImport(IFormFile file)
        {
            if (file == null || file.Length == 0)
            {
                return BadRequest("Arquivo não fornecido");
            }

            // Verifica se é CSV
            var extension = Path.GetExtension(file.FileName).ToLowerInvariant();
            if (extension != ".csv")
            {
                return BadRequest("Apenas arquivos CSV são suportados");
            }

            try
            {
                using var stream = file.OpenReadStream();
                var result = await _componentService.ImportComponentsAsync(stream);

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
                _logger.LogError(ex, "Erro ao processar importação em massa");
                return StatusCode(500, new { message = "Erro ao processar arquivo", error = ex.Message });
            }
        }

        // DELETE: api/Component/bulk (Exclusão múltipla)
        [HttpDelete("bulk")]
        [Authorize(Roles = "admin")]
        public async Task<IActionResult> DeleteMultiple([FromBody] List<int> componentIds)
        {
            if (componentIds == null || !componentIds.Any())
            {
                return BadRequest("Nenhum componente selecionado");
            }

            var success = await _componentService.DeleteMultipleComponentsAsync(componentIds);

            if (success)
            {
                return NoContent();
            }
            else
            {
                return StatusCode(500, new { message = "Erro ao deletar componentes" });
            }
        }

        // GET: api/Component/export/template
        [HttpGet("export/template")]
        public IActionResult GetImportTemplate()
        {
            var csvContent = "Name;Description;Group;Device;Value;Package;Characteristics;InternalCode;Price;Environment;Drawer;Division;NCM;NVE;QuantityInStock;MinimumQuantity\n";
            csvContent += "Resistor 10K;Resistor de 10K Ohms;Resistor;SMD;10K;0805;1/4W 5%;RES-001;0.15;estoque;A1;1;85411000;00;100;20\n";
            csvContent += "Capacitor 100nF;Capacitor cerâmico;Capacitor;Cerâmico;100nF;0603;50V X7R;CAP-001;0.25;estoque;A2;3;85322400;00;150;30";

            var bytes = System.Text.Encoding.UTF8.GetBytes(csvContent);
            return File(bytes, "text/csv", "template_importacao_componentes.csv");
        }
    }
}