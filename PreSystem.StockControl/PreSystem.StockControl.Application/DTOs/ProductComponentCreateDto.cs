namespace PreSystem.StockControl.Application.DTOs
{
    // DTO para especificar os componentes ao criar um novo produto
    public class ProductComponentCreateDto
    {
        public int ComponentId { get; set; }     // ID do componente
        public int Quantity { get; set; }        // Quantidade necessária
    }
}
