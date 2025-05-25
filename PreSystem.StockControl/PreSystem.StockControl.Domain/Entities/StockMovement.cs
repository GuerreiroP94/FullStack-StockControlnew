namespace PreSystem.StockControl.Domain.Entities
{
    // Representa uma movimentação de estoque (entrada ou saída)
    public class StockMovement
    {
        // Identificador único da movimentação
        public int Id { get; set; }

        // ID do componente afetado (chave estrangeira)
        public int ComponentId { get; set; }

        // Objeto de navegação para o componente relacionado
        public Component Component { get; set; } = null!;

        // Tipo da movimentação (ex: "Entrada", "Saída", "Ajuste")
        public string MovementType { get; set; } = string.Empty;

        // Quantidade alterada (positiva para entrada, negativa para saída)
        public int QuantityChanged { get; set; }

        // Data e hora da movimentação
        public DateTime PerformedAt { get; set; }

        // Usuário que realizou a movimentação (ex: nome ou email)
        public string PerformedBy { get; set; } = string.Empty;

        // ID do usuário que realizou a movimentação (relacionamento com User)
        public int? UserId { get; set; }

        // Objeto de navegação para o usuário
        public User? User { get; set; }
    }
}
