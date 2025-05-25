// PreSystem.StockControl.Domain/Entities/User.cs

namespace PreSystem.StockControl.Domain.Entities
{
    // Representa um usuário do sistema
    public class User
    {
        // Identificador único
        public int Id { get; set; }

        // Nome de exibição
        public string Name { get; set; } = string.Empty;

        // E-mail do usuário (será o login)
        public string Email { get; set; } = string.Empty;

        // Senha com hash (nunca armazenar em texto puro)
        public string PasswordHash { get; set; } = string.Empty;

        // Papel do usuário (ex: admin, operador)
        public string Role { get; set; } = "operator";

        // Data de criação
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        // Movimentações feitas por esse usuário (relação 1:N)
        public ICollection<StockMovement>? StockMovements { get; set; }
    }
}
