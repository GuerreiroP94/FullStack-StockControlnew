namespace PreSystem.StockControl.Application.DTOs
{
    // DTO para atualização de produtos (inclui o ID do produto)
    public class ProductUpdateDto : ProductCreateDto
    {
        public int Id { get; set; } // Identificador do produto a ser atualizado
    }
}
