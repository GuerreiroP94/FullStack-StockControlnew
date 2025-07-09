using PreSystem.StockControl.Application.DTOs;

namespace PreSystem.StockControl.Application.Interfaces.Services
{
    public interface IAuthService
    {
        Task<string> GenerateJwtTokenAsync(UserResponseDto user);
        Task<UserResponseDto?> ValidateAndLoginAsync(UserLoginDto loginDto);
        Task<bool> RequestPasswordResetAsync(string email);
        Task<bool> ResetPasswordAsync(string token, string newPassword);
    }
}
