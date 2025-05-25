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
    [Authorize] // Essa linha garante que só acessa quem tiver JWT válido
    public class ComponentController : ControllerBase
    {
        private readonly IComponentService _componentService;

        public ComponentController(IComponentService componentService)
        {
            _componentService = componentService;
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
        public async Task<IActionResult> Delete(int id)
        {
            var deleted = await _componentService.DeleteComponentAsync(id);
            if (!deleted) return NotFound();

            return NoContent();
        }
    }
}
