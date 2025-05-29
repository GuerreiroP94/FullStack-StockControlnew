namespace PreSystem.StockControl.Application.DTOs
{
    // DTO usado na criação e atualização de um componente
    public class ComponentCreateDto
    {
        public string Name { get; set; } = string.Empty;
        public string? Description { get; set; }
        public string Group { get; set; } = string.Empty;

        // Novos campos
        public string? Device { get; set; }
        public string? Value { get; set; }
        public string? Package { get; set; }
        public string? Characteristics { get; set; }
        public string? InternalCode { get; set; }
        public decimal? Price { get; set; }
        public string Environment { get; set; } = "estoque";
        public string? Drawer { get; set; }
        public string? Division { get; set; }
        public string? NCM { get; set; }
        public string? NVE { get; set; }

        // Campos existentes
        public int QuantityInStock { get; set; }
        public int MinimumQuantity { get; set; }
    }
}