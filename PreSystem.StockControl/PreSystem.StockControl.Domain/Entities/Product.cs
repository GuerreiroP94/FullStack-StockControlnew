using System.Collections.Generic;
namespace PreSystem.StockControl.Domain.Entities
{
    public class Product
    {
        // Identificador único do produto
        public int Id { get; set; }

        // Nome do produto montado (ex: "Central de Controle X")
        public string Name { get; set; } = string.Empty;

        // Descrição do produto final
        public string? Description { get; set; }

        // Data de criação do produto
        public DateTime CreatedAt { get; set; }

        // Nome do usuário que criou o produto (pode virar um ID futuramente)
        public string? CreatedBy { get; set; }

        // Lista que armazena todos os componentes que fazem parte do produto
        public ICollection<ProductComponent> ProductComponents { get; set; } = new List<ProductComponent>();

        public DateTime? UpdatedAt { get; set; }


    }
}
