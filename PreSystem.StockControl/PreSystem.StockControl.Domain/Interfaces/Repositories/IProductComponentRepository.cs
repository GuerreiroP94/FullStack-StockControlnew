using PreSystem.StockControl.Domain.Entities;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace PreSystem.StockControl.Domain.Interfaces.Repositories
{
    public interface IProductComponentRepository
    {
        // Retorna todos os componentes de um produto
        Task<IEnumerable<ProductComponent>> GetByProductIdAsync(int productId);

        // Adiciona uma lista de componentes para um produto
        Task AddRangeAsync(IEnumerable<ProductComponent> productComponents);

        // Remove todos os componentes associados a um produto
        Task RemoveByProductIdAsync(int productId);
    }
}
