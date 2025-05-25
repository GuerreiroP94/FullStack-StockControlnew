namespace PreSystem.StockControl.Domain.Entities
{
    // Essa classe representa a tabela que conecta os Produtos aos Componentes
    // Ou seja, ela mostra quais componentes fazem parte de cada produto
    public class ProductComponent
    {
        // ID do produto (chave estrangeira para a tabela Product)
        public int ProductId { get; set; }

        // Objeto de navegação para acessar os dados do produto relacionado
        public Product Product { get; set; } = null!;

        // ID do componente (chave estrangeira para a tabela Component)
        public int ComponentId { get; set; }

        // Objeto de navegação para acessar os dados do componente relacionado
        public Component Component { get; set; } = null!;

        // Quantidade necessária desse componente para montar o produto
        public int Quantity { get; set; }
    }
}
