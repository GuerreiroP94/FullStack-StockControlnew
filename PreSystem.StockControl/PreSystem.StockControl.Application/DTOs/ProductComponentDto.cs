namespace PreSystem.StockControl.Application.DTOs
{
    // Representa os dados de um componente dentro de um produto
    public class ProductComponentDto
    {
        public int ComponentId { get; set; }
        public string ComponentName { get; set; } = string.Empty;
        public string Group { get; set; } = string.Empty;
        public int Quantity { get; set; }
    }
}
