namespace PreSystem.StockControl.Application.DTOs
{
    // DTO usado para login do usuário
    public class UserLoginDto
    {
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }
}
