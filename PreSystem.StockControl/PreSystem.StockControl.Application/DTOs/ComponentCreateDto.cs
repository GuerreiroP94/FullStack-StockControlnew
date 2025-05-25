namespace PreSystem.StockControl.Application.DTOs
{
    // DTO usado na criação e atualização de um componente
    public class ComponentCreateDto
    {
        public string Name { get; set; } = string.Empty; // Nome do componente
        public string? Description { get; set; }         // Descrição opcional
        public string Group { get; set; } = string.Empty;// Grupo (ex: Semicondutor, Resistor)
        public int QuantityInStock { get; set; }         // Estoque inicial
        public int MinimumQuantity { get; set; }         // Estoque mínimo
    }
}
