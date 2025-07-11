﻿namespace PreSystem.StockControl.Application.DTOs
{
    // DTO para movimentação em massa de estoque
    public class BulkStockMovementDto
    {
        public List<StockMovementItemDto> Movements { get; set; } = new();
    }

    // Item individual de movimentação
    public class StockMovementItemDto
    {
        public int ComponentId { get; set; }
        public string MovementType { get; set; } = string.Empty; // "Entrada" ou "Saida"
        public int Quantity { get; set; }
    }

    // DTO para exportação de relatório de produção
    public class ProductionReportDto
    {
        public string ProductName { get; set; } = string.Empty;
        public int UnitsToManufacture { get; set; }
        public List<ProductionReportItemDto> Components { get; set; } = new();
    }

    // Item do relatório de produção
    public class ProductionReportItemDto
    {
        public string ComponentName { get; set; } = string.Empty;
        public string? Device { get; set; }
        public string? Value { get; set; }
        public string? Package { get; set; }
        public string? Characteristics { get; set; }
        public string? InternalCode { get; set; }
        public string? Drawer { get; set; }
        public string? Division { get; set; }
        public int QuantityPerUnit { get; set; }
        public int TotalQuantityNeeded { get; set; }
        public int QuantityInStock { get; set; }
        public int SuggestedPurchase { get; set; }
        public decimal? UnitPrice { get; set; }
        public decimal TotalPrice { get; set; }
    }
}