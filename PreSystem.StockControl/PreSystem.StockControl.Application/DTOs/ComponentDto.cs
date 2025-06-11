﻿namespace PreSystem.StockControl.Application.DTOs
{
    // DTO de retorno de dados de um componente
    public class ComponentDto
    {
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public string? Description { get; set; }
        public string Group { get; set; } = string.Empty;

        // Campos da hierarquia
        public string? Device { get; set; }
        public string? Value { get; set; }
        public string? Package { get; set; }

        // Características técnicas
        public string? Characteristics { get; set; }
        public string? InternalCode { get; set; }
        public decimal? Price { get; set; }

        // Localização
        public string Environment { get; set; } = "estoque";
        public string? Drawer { get; set; }
        public string? Division { get; set; }

        // Códigos fiscais
        public string? NCM { get; set; }
        public string? NVE { get; set; }

        // Datas de movimentação
        public DateTime? LastEntryDate { get; set; }
        public int? LastEntryQuantity { get; set; }
        public int? LastExitQuantity { get; set; }

        // Controle de estoque
        public int QuantityInStock { get; set; }
        public int MinimumQuantity { get; set; }

        // Auditoria
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }
    }
}