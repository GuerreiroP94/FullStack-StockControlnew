#pragma warning disable IDE0290
using PreSystem.StockControl.Application.DTOs;
using PreSystem.StockControl.Application.DTOs.Filters;
using PreSystem.StockControl.Application.Interfaces.Services;
using PreSystem.StockControl.Domain.Entities;
using PreSystem.StockControl.Domain.Interfaces.Repositories;
using Microsoft.Extensions.Logging;

namespace PreSystem.StockControl.Application.Services
{
    public class ProductService : IProductService
    {
        private readonly IProductRepository _productRepository;
        private readonly ILogger<ProductService> _logger; // Logger para registrar ações do sistema

        public ProductService(IProductRepository productRepository, ILogger<ProductService> logger)
        {
            _productRepository = productRepository;
            _logger = logger; // Inicializa o logger
        }

        // Retorna todos os produtos convertidos para DTOs
        public async Task<IEnumerable<ProductDto>> GetAllProductsAsync(ProductQueryParameters parameters)
        {
            var products = await _productRepository.GetAllAsync();

            // Aplica filtro se houver
            if (!string.IsNullOrEmpty(parameters.Name))
                products = products.Where(p => p.Name.Contains(parameters.Name, StringComparison.OrdinalIgnoreCase));

            // Aplica paginação
            products = products
                .Skip((parameters.PageNumber - 1) * parameters.PageSize)
                .Take(parameters.PageSize);

            return products.Select(p => new ProductDto
            {
                Id = p.Id,
                Name = p.Name,
                Description = p.Description,
                CreatedAt = p.CreatedAt,
                CreatedBy = p.CreatedBy,
                Components = p.ProductComponents.Select(pc => new ProductComponentDto
                {
                    ComponentId = pc.ComponentId,
                    ComponentName = pc.Component?.Name ?? string.Empty,
                    Quantity = pc.Quantity
                }).ToList()
            });
        }

        // Retorna um único produto por ID (como DTO)
        public async Task<ProductDto?> GetProductByIdAsync(int id)
        {
            var product = await _productRepository.GetByIdAsync(id);
            if (product == null)
            {
                // Loga tentativa de busca de produto inexistente
                _logger.LogWarning("Tentativa de buscar produto com ID inexistente: {Id}", id);
                return null;
            }

            return new ProductDto
            {
                Id = product.Id,
                Name = product.Name,
                Description = product.Description,
                CreatedAt = product.CreatedAt,
                CreatedBy = product.CreatedBy,
                Components = product.ProductComponents.Select(pc => new ProductComponentDto
                {
                    ComponentId = pc.ComponentId,
                    ComponentName = pc.Component?.Name ?? string.Empty,
                    Quantity = pc.Quantity
                }).ToList()
            };
        }

        // Cria um novo produto a partir do DTO e retorna o DTO criado
        public async Task<ProductDto> AddProductAsync(ProductCreateDto dto)
        {
            var product = new Product
            {
                Name = dto.Name,
                Description = dto.Description,
                CreatedAt = DateTime.UtcNow,
                CreatedBy = dto.CreatedBy,
                ProductComponents = dto.Components.Select(c => new ProductComponent
                {
                    ComponentId = c.ComponentId,
                    Quantity = c.Quantity
                }).ToList()
            };

            await _productRepository.AddAsync(product);

            // Loga criação de produto
            _logger.LogInformation("Produto criado: {Nome} (ID: {Id}) com {QtdComponentes} componentes",
                product.Name, product.Id, product.ProductComponents.Count);

            return new ProductDto
            {
                Id = product.Id,
                Name = product.Name,
                Description = product.Description,
                CreatedAt = product.CreatedAt,
                CreatedBy = product.CreatedBy,
                Components = product.ProductComponents.Select(pc => new ProductComponentDto
                {
                    ComponentId = pc.ComponentId,
                    ComponentName = string.Empty,
                    Quantity = pc.Quantity
                }).ToList()
            };
        }

        public async Task<ProductDto?> UpdateProductAsync(ProductUpdateDto dto)
        {
            var product = await _productRepository.GetByIdAsync(dto.Id);
            if (product == null)
            {
                // Loga tentativa de atualização de produto inexistente
                _logger.LogWarning("Tentativa de atualizar produto inexistente: ID {Id}", dto.Id);
                return null;
            }

            product.Name = dto.Name;
            product.Description = dto.Description;
            product.ProductComponents = dto.Components.Select(c => new ProductComponent
            {
                ComponentId = c.ComponentId,
                Quantity = c.Quantity,
                ProductId = product.Id
            }).ToList();

            await _productRepository.UpdateAsync(product);

            // Loga atualização de produto
            _logger.LogInformation("Produto atualizado: {Nome} (ID: {Id})", product.Name, product.Id);

            return new ProductDto
            {
                Id = product.Id,
                Name = product.Name,
                Description = product.Description,
                CreatedAt = product.CreatedAt,
                CreatedBy = product.CreatedBy,
                Components = product.ProductComponents.Select(pc => new ProductComponentDto
                {
                    ComponentId = pc.ComponentId,
                    ComponentName = pc.Component?.Name ?? string.Empty,
                    Quantity = pc.Quantity
                }).ToList()
            };
        }

        // Deleta um produto do banco e retorna true se foi bem-sucedido
        public async Task<bool> DeleteProductAsync(int id)
        {
            var product = await _productRepository.GetByIdAsync(id);
            if (product == null)
            {
                // Loga tentativa de exclusão de produto inexistente
                _logger.LogWarning("Tentativa de excluir produto inexistente: ID {Id}", id);
                return false;
            }

            await _productRepository.DeleteAsync(product);

            // Loga exclusão de produto
            _logger.LogInformation("Produto excluído: {Nome} (ID: {Id})", product.Name, product.Id);
            return true;
        }
    }
}
