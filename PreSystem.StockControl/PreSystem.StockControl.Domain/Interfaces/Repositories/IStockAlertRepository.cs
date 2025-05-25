using PreSystem.StockControl.Domain.Entities;

namespace PreSystem.StockControl.Domain.Interfaces.Repositories
{
    public interface IStockAlertRepository : IRepository<StockAlert>
    {
        Task<IEnumerable<StockAlert>> GetByComponentIdAsync(int componentId);
    }
}
