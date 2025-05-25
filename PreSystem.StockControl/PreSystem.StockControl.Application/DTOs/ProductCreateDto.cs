namespace PreSystem.StockControl.Application.DTOs
{
    // Representa os dados necessários para criar um novo produto
    public class ProductCreateDto
    {
        public string Name { get; set; } = string.Empty;
        public string? Description { get; set; }
        public string? CreatedBy { get; set; }
        public List<ProductComponentCreateDto> Components { get; set; } = new();
    }
}
