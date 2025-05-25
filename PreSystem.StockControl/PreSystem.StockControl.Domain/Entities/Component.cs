namespace PreSystem.StockControl.Domain.Entities;

public class Component
{
    // Identificador único do componente
    public int Id { get; set; }

    // Nome do componente - inicializado com string.Empty para evitar erros de referência nula
    public string Name { get; set; } = string.Empty;

    // Descrição é opcional, então pode ser nula
    public string? Description { get; set; }

    // Grupo do componente - também inicializado com string.Empty
    public string Group { get; set; } = string.Empty;

    // Quantidade atual no estoque
    public int QuantityInStock { get; set; }

    // Quantidade mínima para gerar alerta de estoque baixo
    public int MinimumQuantity { get; set; }

    // Data de criação do registro
    public DateTime CreatedAt { get; set; }

    // Data da última modificação do registro
    public DateTime UpdatedAt { get; set; }

    // Lista de relacionamentos com os produtos (inicializada para evitar erro de null)
    public ICollection<ProductComponent> ProductComponents { get; set; } = new List<ProductComponent>();

    public ICollection<StockAlert> StockAlerts { get; set; } = new List<StockAlert>();

}
