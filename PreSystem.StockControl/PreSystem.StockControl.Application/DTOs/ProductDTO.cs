namespace PreSystem.StockControl.Application.DTOs

{
    // Representa o retorno de um produto com seus componentes
    public class ProductDto
    {
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public string? Description { get; set; }
        public DateTime CreatedAt { get; set; }
        public string? CreatedBy { get; set; }
        public List<ProductComponentDto> Components { get; set; } = new();
    }
}
