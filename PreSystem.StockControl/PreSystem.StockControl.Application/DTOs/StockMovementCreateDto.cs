namespace PreSystem.StockControl.Application.DTOs
{
    public class StockMovementCreateDto
    {
        public int ComponentId { get; set; }
        public string MovementType { get; set; } = string.Empty;
        public int Quantity { get; set; }
        public string PerformedBy { get; set; } = string.Empty;
    }
}
