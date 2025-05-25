#pragma warning disable IDE0290
using Microsoft.EntityFrameworkCore;
using PreSystem.StockControl.Domain.Entities;
using PreSystem.StockControl.Domain.Interfaces.Repositories;
using PreSystem.StockControl.Infrastructure.Persistence;

namespace PreSystem.StockControl.Infrastructure.Repositories
{
    // Implementação do repositório de movimentações de estoque
    public class StockMovementRepository : IStockMovementRepository
    {
        private readonly StockControlDbContext _context;

        public StockMovementRepository(StockControlDbContext context)
        {
            _context = context;
        }

        // Retorna todas as movimentações
        public async Task<IEnumerable<StockMovement>> GetAllAsync()
        {
            return await _context.StockMovements
                .Include(m => m.User) // Carrega o nome do usuário via navegação
                .ToListAsync();
        }

        // Retorna uma movimentação específica pelo ID
        public async Task<StockMovement?> GetByIdAsync(int id)
        {
            return await _context.StockMovements
                .Include(m => m.User)
                .FirstOrDefaultAsync(m => m.Id == id);
        }

        // Adiciona uma nova movimentação
        public async Task AddAsync(StockMovement movement)
        {
            await _context.StockMovements.AddAsync(movement);
            await _context.SaveChangesAsync();
        }

        // Atualiza uma movimentação existente
        public async Task UpdateAsync(StockMovement movement)
        {
            _context.StockMovements.Update(movement);
            await _context.SaveChangesAsync();
        }

        // Remove uma movimentação
        public async Task DeleteAsync(StockMovement movement)
        {
            _context.StockMovements.Remove(movement);
            await _context.SaveChangesAsync();
        }
    }
}
