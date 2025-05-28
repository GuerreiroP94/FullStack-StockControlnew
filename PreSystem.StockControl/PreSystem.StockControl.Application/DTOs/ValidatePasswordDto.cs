namespace PreSystem.StockControl.Application.DTOs
{
    /// <summary>
    /// DTO utilizado para validação de senha do usuário
    /// </summary>
    public class ValidatePasswordDto
    {
        /// <summary>
        /// Senha atual do usuário que será validada
        /// </summary>
        /// <example>senhaAtual123</example>
        public string Password { get; set; } = string.Empty;
    }
}