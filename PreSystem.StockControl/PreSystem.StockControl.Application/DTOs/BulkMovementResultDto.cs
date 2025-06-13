﻿namespace PreSystem.StockControl.Application.DTOs
{
    public class BulkMovementResultDto
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty; // ADICIONADA
        public int TotalMovements { get; set; }
        public int SuccessCount { get; set; }
        public int ErrorCount { get; set; }
        public List<string> Errors { get; set; } = new();
        public List<int> AlertsGenerated { get; set; } = new();
    }
}