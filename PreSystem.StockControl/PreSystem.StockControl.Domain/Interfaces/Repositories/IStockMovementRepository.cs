using PreSystem.StockControl.Domain.Entities;

namespace PreSystem.StockControl.Domain.Interfaces.Repositories
{
    // Interface para ações no repositório de movimentações de estoque
    public interface IStockMovementRepository : IRepository<StockMovement>
    {
        // Podemos adicionar métodos específicos aqui depois, se necessário
    }
}
