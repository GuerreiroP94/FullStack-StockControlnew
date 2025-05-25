using PreSystem.StockControl.Application.DTOs;
using PreSystem.StockControl.Application.DTOs.Filters;


namespace PreSystem.StockControl.Application.Interfaces.Services;

// Define a interface do serviço de produto, usada para abstração da lógica
public interface IProductService
{
    // Retorna uma lista paginada e filtrada de produtos com base nos parâmetros fornecidos
    Task<IEnumerable<ProductDto>> GetAllProductsAsync(ProductQueryParameters parameters);

    // Busca um produto específico pelo seu ID
    Task<ProductDto?> GetProductByIdAsync(int id);

    // Cria um novo produto com base nos dados fornecidos no DTO
    Task<ProductDto> AddProductAsync(ProductCreateDto dto);

    // Atualiza um produto existente com os dados fornecidos
    Task<ProductDto?> UpdateProductAsync(ProductUpdateDto dto); 

    // Deleta um produto com base no ID e retorna verdadeiro se deu certo
    Task<bool> DeleteProductAsync(int id);
}
