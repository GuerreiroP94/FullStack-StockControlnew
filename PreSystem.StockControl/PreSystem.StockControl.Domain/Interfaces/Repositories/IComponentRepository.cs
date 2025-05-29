using PreSystem.StockControl.Domain.Entities;

namespace PreSystem.StockControl.Domain.Interfaces.Repositories
{
    public interface IComponentRepository : IRepository<Component>
    {
        Task AddRangeAsync(IEnumerable<Component> components);
        Task DeleteRangeAsync(IEnumerable<Component> components);
    }
}