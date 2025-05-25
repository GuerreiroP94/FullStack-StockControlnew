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
    public class ProductController : ControllerBase
    {
        private readonly IProductService _productService;

        public ProductController(IProductService productService)
        {
            _productService = productService;
        }

        // GET: api/Product
        [HttpGet]
        public async Task<ActionResult<IEnumerable<ProductDto>>> GetAll([FromQuery] ProductQueryParameters parameters)
        {
            var products = await _productService.GetAllProductsAsync(parameters);
            return Ok(products);
        }

        // GET: api/Product/{id}
        [HttpGet("{id}")]
        public async Task<ActionResult<ProductDto>> GetById(int id)
        {
            // Busca o produto pelo ID
            var product = await _productService.GetProductByIdAsync(id);

            // Se não existir, retorna 404
            if (product == null)
                return NotFound();

            return Ok(product);
        }

        // POST: api/Product
        [HttpPost]
        public async Task<ActionResult> Create([FromBody] ProductCreateDto dto)
        {
            // Cria o produto usando os dados do DTO
            var created = await _productService.AddProductAsync(dto);

            return CreatedAtAction(nameof(GetById), new { id = created.Id }, created);
        }

        // PUT: api/Product
        [HttpPut]
        public async Task<ActionResult> Update([FromBody] ProductUpdateDto dto)
        {
            var updated = await _productService.UpdateProductAsync(dto);
            if (updated == null)
                return NotFound();

            return Ok(updated);
        }

        // DELETE: api/Product/{id}
        [HttpDelete("{id}")]
        public async Task<ActionResult> Delete(int id)
        {
            var deleted = await _productService.DeleteProductAsync(id);
            if (!deleted)
                return NotFound();

            return NoContent();
        }
    }
}
