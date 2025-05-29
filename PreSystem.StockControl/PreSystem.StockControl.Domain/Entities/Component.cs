namespace PreSystem.StockControl.Domain.Entities;

public class Component
{
    // Identificador único do componente
    public int Id { get; set; }

    // Nome do componente - inicializado com string.Empty para evitar erros de referência nula
    public string Name { get; set; } = string.Empty;

    // Descrição é opcional, então pode ser nula
    public string? Description { get; set; }

    // Grupo do componente (nível 1 da hierarquia)
    public string Group { get; set; } = string.Empty;

    // ==== NOVOS CAMPOS ====

    // Device (nível 2 da hierarquia)
    public string? Device { get; set; }

    // Value (nível 3 da hierarquia)
    public string? Value { get; set; }

    // Package (tipo de encapsulamento)
    public string? Package { get; set; }

    // Características técnicas
    public string? Characteristics { get; set; }

    // Código interno do componente
    public string? InternalCode { get; set; }

    // Preço unitário
    public decimal? Price { get; set; }

    // Ambiente onde está armazenado (estoque ou laboratório)
    public string Environment { get; set; } = "estoque";

    // Gaveta onde está armazenado
    public string? Drawer { get; set; }

    // Divisão/Seção da gaveta
    public string? Division { get; set; }

    // NCM - Nomenclatura Comum do Mercosul
    public string? NCM { get; set; }

    // NVE - Nomenclatura de Valor Aduaneiro e Estatística
    public string? NVE { get; set; }

    // Data da última entrada
    public DateTime? LastEntryDate { get; set; }

    // Quantidade da última entrada
    public int? LastEntryQuantity { get; set; }

    // Quantidade da última saída
    public int? LastExitQuantity { get; set; }

    // ==== CAMPOS EXISTENTES ====

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

    // Lista de alertas de estoque
    public ICollection<StockAlert> StockAlerts { get; set; } = new List<StockAlert>();
}