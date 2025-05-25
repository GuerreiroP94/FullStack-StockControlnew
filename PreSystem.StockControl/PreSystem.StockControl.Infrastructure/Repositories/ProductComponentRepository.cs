using Microsoft.EntityFrameworkCore;
using PreSystem.StockControl.Domain.Entities;
using PreSystem.StockControl.Domain.Interfaces.Repositories;
using PreSystem.StockControl.Infrastructure.Persistence;

namespace PreSystem.StockControl.Infrastructure.Repositories
{
    public class ProductComponentRepository : IProductComponentRepository
    {
        private readonly StockControlDbContext _context;

        public ProductComponentRepository(StockControlDbContext context)
        {
            _context = context;
        }

        public async Task<IEnumerable<ProductComponent>> GetAllAsync()
        {
            return await _context.ProductComponents.ToListAsync();
        }

        public async Task<ProductComponent?> GetByIdAsync(Guid id)
        {
            return await _context.ProductComponents.FindAsync(id);
        }

        public async Task AddAsync(ProductComponent entity)
        {
            await _context.ProductComponents.AddAsync(entity);
            await _context.SaveChangesAsync();
        }

        public async Task UpdateAsync(ProductComponent entity)
        {
            _context.ProductComponents.Update(entity);
            await _context.SaveChangesAsync();
        }

        public async Task DeleteAsync(ProductComponent entity)
        {
            _context.ProductComponents.Remove(entity);
            await _context.SaveChangesAsync();
        }

        public async Task AddRangeAsync(IEnumerable<ProductComponent> entities)
        {
            await _context.ProductComponents.AddRangeAsync(entities);
            await _context.SaveChangesAsync();
        }

        public async Task<IEnumerable<ProductComponent>> GetByProductIdAsync(int productId)
        {
            return await _context.ProductComponents
                .Where(pc => pc.ProductId == productId)
                .ToListAsync();
        }

        public async Task RemoveByProductIdAsync(int productId)
        {
            var itemsToRemove = await _context.ProductComponents
                .Where(pc => pc.ProductId == productId)
                .ToListAsync();

            _context.ProductComponents.RemoveRange(itemsToRemove);
            await _context.SaveChangesAsync();
        }

    }
}
