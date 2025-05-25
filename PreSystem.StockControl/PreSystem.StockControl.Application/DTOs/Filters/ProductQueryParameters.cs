namespace PreSystem.StockControl.Application.DTOs.Filters
{
    // Parâmetros de consulta para listagem de produtos
    public class ProductQueryParameters
    {
        public int PageNumber { get; set; } = 1;   // Página atual (começa em 1)
        public int PageSize { get; set; } = 10;    // Quantidade por página
        public string? Name { get; set; }          // Filtro por nome
    }
}
