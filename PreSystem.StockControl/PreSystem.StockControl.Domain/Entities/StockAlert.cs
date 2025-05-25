namespace PreSystem.StockControl.Domain.Entities
{
    public class StockAlert
    {
        public int Id { get; set; }
        public int ComponentId { get; set; }
        public string Message { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }

        public Component Component { get; set; } = null!;
    }
}
