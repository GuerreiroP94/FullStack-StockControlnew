using Microsoft.EntityFrameworkCore;
using PreSystem.StockControl.Domain.Entities;
using PreSystem.StockControl.Domain.Interfaces.Repositories;
using PreSystem.StockControl.Infrastructure.Persistence;

namespace PreSystem.StockControl.Infrastructure.Repositories
{
    public class StockAlertRepository : IStockAlertRepository
    {
        private readonly StockControlDbContext _context;

        public StockAlertRepository(StockControlDbContext context)
        {
            _context = context;
        }

        // Lista todos os alertas
        public async Task<IEnumerable<StockAlert>> GetAllAsync()
        {
            return await _context.StockAlerts.ToListAsync();
        }

        // Lista os alertas de um componente específico
        public async Task<IEnumerable<StockAlert>> GetByComponentIdAsync(int componentId)
        {
            return await _context.StockAlerts
                .Where(alert => alert.ComponentId == componentId)
                .ToListAsync();
        }

        // Adiciona um novo alerta
        public async Task AddAsync(StockAlert alert)
        {
            await _context.StockAlerts.AddAsync(alert);
            await _context.SaveChangesAsync();
        }

        // Remove um alerta (se necessário futuramente)
        public async Task DeleteAsync(StockAlert alert)
        {
            _context.StockAlerts.Remove(alert);
            await _context.SaveChangesAsync();
        }

        // Busca alerta por ID (caso precise futuramente)
        public async Task<StockAlert?> GetByIdAsync(int id)
        {
            return await _context.StockAlerts.FindAsync(id);
        }

        // Atualiza alerta (não obrigatório agora, mas já fica preparado)
        public async Task UpdateAsync(StockAlert alert)
        {
            _context.StockAlerts.Update(alert);
            await _context.SaveChangesAsync();
        }
    }
}
