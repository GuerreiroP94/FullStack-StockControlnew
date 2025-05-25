using PreSystem.StockControl.Domain.Entities;

namespace PreSystem.StockControl.Domain.Interfaces.Repositories
{
    public interface IUserRepository
    {
        // Busca usuário por e-mail (usado no login)
        Task<User?> GetByEmailAsync(string email);

        // Adiciona um novo usuário ao banco
        Task AddAsync(User user);

        // Retorna todos os usuários cadastrados
        Task<List<User>> GetAllAsync();

        // Retorna um usuário pelo ID
        Task<User?> GetByIdAsync(int id);

        // Atualiza um usuário (ex: papel, nome etc.)
        Task UpdateAsync(User user);
    }
}
