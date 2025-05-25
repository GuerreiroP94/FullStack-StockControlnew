using Microsoft.Extensions.Logging;
using PreSystem.StockControl.Application.DTOs;
using PreSystem.StockControl.Application.DTOs.Filters;
using PreSystem.StockControl.Application.Interfaces.Services;
using PreSystem.StockControl.Domain.Entities;
using PreSystem.StockControl.Domain.Interfaces.Repositories;

namespace PreSystem.StockControl.Application.Services
{
    // Serviço responsável pelas regras de negócio dos Componentes
    public class ComponentService : IComponentService
    {
        private readonly IComponentRepository _componentRepository;
        private readonly ILogger<ComponentService> _logger; // Logger para registrar ações da aplicação

        // Injeção de dependência do repositório e logger
        public ComponentService(IComponentRepository componentRepository, ILogger<ComponentService> logger)
        {
            _componentRepository = componentRepository;
            _logger = logger; // Armazena instância do logger
        }

        // Adiciona um novo componente com base nos dados do DTO
        public async Task<ComponentDto> AddComponentAsync(ComponentCreateDto dto)
        {
            var component = new Component
            {
                Name = dto.Name,
                Description = dto.Description,
                Group = dto.Group,
                QuantityInStock = dto.QuantityInStock,
                MinimumQuantity = dto.MinimumQuantity,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };

            await _componentRepository.AddAsync(component);

            // Loga a criação do componente
            _logger.LogInformation("Componente criado: {Nome}, Grupo: {Grupo}, Quantidade: {Quantidade}",
                component.Name, component.Group, component.QuantityInStock);

            // Retorna o componente criado como DTO
            return new ComponentDto
            {
                Id = component.Id,
                Name = component.Name,
                Description = component.Description,
                Group = component.Group,
                QuantityInStock = component.QuantityInStock,
                MinimumQuantity = component.MinimumQuantity
            };
        }

        // Retorna todos os componentes como uma lista de DTOs
        public async Task<IEnumerable<ComponentDto>> GetAllComponentsAsync(ComponentFilterDto filter)
        {
            var query = await _componentRepository.GetAllAsync();

            // Aplica filtros se existirem
            if (!string.IsNullOrWhiteSpace(filter.Name))
                query = query.Where(c => c.Name.Contains(filter.Name, StringComparison.OrdinalIgnoreCase));

            if (!string.IsNullOrWhiteSpace(filter.Group))
                query = query.Where(c => c.Group.Contains(filter.Group, StringComparison.OrdinalIgnoreCase));

            // Aplica paginação
            query = query
                .Skip((filter.PageNumber - 1) * filter.PageSize)
                .Take(filter.PageSize);

            return query.Select(c => new ComponentDto
            {
                Id = c.Id,
                Name = c.Name,
                Group = c.Group,
                QuantityInStock = c.QuantityInStock,
                MinimumQuantity = c.MinimumQuantity
            });
        }

        // Retorna um único componente pelo ID como DTO
        public async Task<ComponentDto?> GetComponentByIdAsync(int id)
        {
            var component = await _componentRepository.GetByIdAsync(id);
            if (component == null) return null;

            return new ComponentDto
            {
                Id = component.Id,
                Name = component.Name,
                Description = component.Description,
                Group = component.Group,
                QuantityInStock = component.QuantityInStock,
                MinimumQuantity = component.MinimumQuantity
            };
        }

        // Atualiza um componente existente
        public async Task<ComponentDto?> UpdateComponentAsync(int id, ComponentCreateDto dto)
        {
            var component = await _componentRepository.GetByIdAsync(id);
            if (component == null) return null;

            // Atualiza os dados
            component.Name = dto.Name;
            component.Description = dto.Description;
            component.Group = dto.Group;
            component.QuantityInStock = dto.QuantityInStock;
            component.MinimumQuantity = dto.MinimumQuantity;
            component.UpdatedAt = DateTime.UtcNow;

            await _componentRepository.UpdateAsync(component);

            // Loga a atualização do componente
            _logger.LogInformation("Componente atualizado: {Id}, Nome: {Nome}, Quantidade: {Quantidade}",
                component.Id, component.Name, component.QuantityInStock);

            return new ComponentDto
            {
                Id = component.Id,
                Name = component.Name,
                Description = component.Description,
                Group = component.Group,
                QuantityInStock = component.QuantityInStock,
                MinimumQuantity = component.MinimumQuantity
            };
        }

        // Remove um componente com base no ID
        public async Task<bool> DeleteComponentAsync(int id)
        {
            var component = await _componentRepository.GetByIdAsync(id);
            if (component == null)
            {
                // Loga tentativa inválida de exclusão
                _logger.LogWarning("Tentativa de deletar componente inexistente: ID {Id}", id);
                return false;
            }

            await _componentRepository.DeleteAsync(component);

            // Loga a exclusão do componente
            _logger.LogInformation("Componente deletado: {Id} - {Nome}", component.Id, component.Name);
            return true;
        }
    }
}
