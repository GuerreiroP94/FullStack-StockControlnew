namespace PreSystem.StockControl.Application.DTOs
{
    // DTO para criação de novo usuário
    public class UserCreateDto
    {
        public string Name { get; set; } = string.Empty;

        public string Email { get; set; } = string.Empty;

        public string Password { get; set; } = string.Empty;

        public string Role { get; set; } = "operator"; // default para operador
    }
}