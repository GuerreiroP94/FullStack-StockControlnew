namespace PreSystem.StockControl.Application.DTOs
{
    // DTO para representar os dados de uma movimentação de estoque
    public class StockMovementDto
    {
        //ID Atribuído automaticamente pelo banco de dados
        public int Id { get; set; }

        // ID do componente movimentado
        public int ComponentId { get; set; }

        // Tipo de movimentação: Entrada ou Saída
        public string MovementType { get; set; } = string.Empty;

        // Quantidade movimentada (positiva para entrada, negativa para saída)
        public int Quantity { get; set; }

        // Data da movimentação
        public DateTime MovementDate { get; set; }

        // Nome do usuário que realizou a movimentação (capturado do token)
        public string PerformedBy { get; set; } = string.Empty;

        // ID do usuário responsável pela movimentação (se autenticado)
        public int? UserId { get; set; }

        // Novo campo com o nome do usuário relacionado
        public string? UserName { get; set; }
    }
}
