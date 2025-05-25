using Microsoft.EntityFrameworkCore;
using PreSystem.StockControl.Domain.Entities;
using PreSystem.StockControl.Domain.Interfaces.Repositories;
using PreSystem.StockControl.Infrastructure.Persistence;

namespace PreSystem.StockControl.Infrastructure.Repositories
{
    // Essa classe implementa os métodos da interface IProductRepository e do genérico IRepository<Product>
    public class ProductRepository : IProductRepository
    {
        private readonly StockControlDbContext _context;

        // Injeção de dependência do contexto do banco
        public ProductRepository(StockControlDbContext context)
        {
            _context = context;
        }

        // Retorna todos os produtos com seus componentes relacionados
        public async Task<IEnumerable<Product>> GetAllAsync()
        {
            return await _context.Products
                                 .Include(p => p.ProductComponents)
                                 .ThenInclude(pc => pc.Component)
                                 .ToListAsync();
        }

        // Busca um produto por ID com os componentes associados
        public async Task<Product?> GetByIdAsync(int id)
        {
            return await _context.Products
                                 .Include(p => p.ProductComponents)
                                 .ThenInclude(pc => pc.Component)
                                 .FirstOrDefaultAsync(p => p.Id == id);
        }

        // Adiciona um novo produto no banco
        public async Task AddAsync(Product product)
        {
            await _context.Products.AddAsync(product);
            await _context.SaveChangesAsync();
        }

        // Atualiza um produto existente
        public async Task UpdateAsync(Product product)
        {
            _context.Products.Update(product);
            await _context.SaveChangesAsync();
        }

        // Remove um produto do banco
        public async Task DeleteAsync(Product product)
        {
            _context.Products.Remove(product);
            await _context.SaveChangesAsync();
        }
    }
}
