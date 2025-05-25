using PreSystem.StockControl.Application.DTOs;
using PreSystem.StockControl.Application.DTOs.Filters;

namespace PreSystem.StockControl.Application.Interfaces.Services
{
    // Interface que define os serviços disponíveis para Componentes
    public interface IComponentService
    {
        // Adiciona um novo componente a partir do DTO de criação
        Task<ComponentDto> AddComponentAsync(ComponentCreateDto dto);

        // Retorna todos os componentes como uma lista de DTOs
        Task<IEnumerable<ComponentDto>> GetAllComponentsAsync(ComponentFilterDto filter);

        // Retorna um componente específico pelo ID (como DTO)
        Task<ComponentDto?> GetComponentByIdAsync(int id);

        // Atualiza um componente existente com base no ID e DTO de entrada
        Task<ComponentDto?> UpdateComponentAsync(int id, ComponentCreateDto dto);

        // Remove um componente com base no ID
        Task<bool> DeleteComponentAsync(int id);
    }
}
