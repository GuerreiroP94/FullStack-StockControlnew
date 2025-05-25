namespace PreSystem.StockControl.Application.DTOs
{
    public class StockAlertDto
    {
        // Identificador único do alerta
        public int Id { get; set; }

        // ID do componente relacionado ao alerta
        public int ComponentId { get; set; }

        // Mensagem do alerta
        public string Message { get; set; } = string.Empty;

        // Data de criação do alerta
        public DateTime CreatedAt { get; set; }
    }
}
