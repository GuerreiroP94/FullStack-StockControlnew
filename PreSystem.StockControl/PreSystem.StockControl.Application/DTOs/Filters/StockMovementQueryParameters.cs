namespace PreSystem.StockControl.Application.DTOs.Filters
{
    public class StockMovementQueryParameters
    {
        public int? ComponentId { get; set; } // Filtro por componente
        public string? MovementType { get; set; } // Entrada ou Saída
        public DateTime? StartDate { get; set; } // De
        public DateTime? EndDate { get; set; } // Até

        public int Page { get; set; } = 1; // Página atual (default 1)
        public int PageSize { get; set; } = 10; // Tamanho da página (default 10)
    }
}
