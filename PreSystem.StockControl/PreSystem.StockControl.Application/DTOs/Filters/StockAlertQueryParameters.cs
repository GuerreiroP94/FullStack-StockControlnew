namespace PreSystem.StockControl.Application.DTOs.Filters
{
    public class StockAlertQueryParameters
    {
        public int Page { get; set; } = 1;              // Página atual (padrão: 1)
        public int PageSize { get; set; } = 10;         // Quantidade por página (padrão: 10)

        public int? ComponentId { get; set; }           // Filtro opcional por componente
        public DateTime? FromDate { get; set; }         // Filtro por data mínima de criação
        public DateTime? ToDate { get; set; }           // Filtro por data máxima de criação
    }
}
