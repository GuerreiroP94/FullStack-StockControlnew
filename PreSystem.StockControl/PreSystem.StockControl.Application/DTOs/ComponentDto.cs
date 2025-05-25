namespace PreSystem.StockControl.Application.DTOs
{
    // DTO de retorno de dados de um componente
    public class ComponentDto
    {
        public int Id { get; set; }                      // Identificador único
        public string Name { get; set; } = string.Empty; // Nome do componente
        public string? Description { get; set; }         // Descrição opcional
        public string Group { get; set; } = string.Empty;// Grupo do componente
        public int QuantityInStock { get; set; }         // Quantidade atual
        public int MinimumQuantity { get; set; }         // Quantidade mínima para alerta
    }
}
