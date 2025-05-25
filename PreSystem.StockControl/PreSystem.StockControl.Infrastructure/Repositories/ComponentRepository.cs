using Microsoft.EntityFrameworkCore;
using PreSystem.StockControl.Domain.Entities;
using PreSystem.StockControl.Domain.Interfaces.Repositories;
using PreSystem.StockControl.Infrastructure.Persistence;

namespace PreSystem.StockControl.Infrastructure.Repositories
{
    public class ComponentRepository : IComponentRepository
    {
        private readonly StockControlDbContext _context;

        // Construtor com injeção do DbContext para acessar o banco
        public ComponentRepository(StockControlDbContext context)
        {
            _context = context;
        }

        // Buscar todos os componentes do banco
        public async Task<IEnumerable<Component>> GetAllAsync()
        {
            return await _context.Components.ToListAsync();
        }

        // Buscar um componente específico pelo ID
        public async Task<Component?> GetByIdAsync(int id)
        {
            return await _context.Components.FindAsync(id);
        }

        // Adicionar novo componente ao banco
        public async Task AddAsync(Component component)
        {
            await _context.Components.AddAsync(component);
            await _context.SaveChangesAsync(); // Salva no banco
        }

        // Atualizar um componente existente
        public async Task UpdateAsync(Component component)
        {
            _context.Components.Update(component);
            await _context.SaveChangesAsync();
        }

        // Remover componente do banco
        public async Task DeleteAsync(Component component)
        {
            _context.Components.Remove(component);
            await _context.SaveChangesAsync();
        }
    }
}
