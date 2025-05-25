namespace PreSystem.StockControl.Application.DTOs
{
    // DTO usado para retorno de informações públicas de um usuário
    public class UserResponseDto
    {
        public int Id { get; set; }

        public string Name { get; set; } = string.Empty;

        public string Email { get; set; } = string.Empty;

        public string Role { get; set; } = string.Empty;

        public DateTime CreatedAt { get; set; }
    }
}