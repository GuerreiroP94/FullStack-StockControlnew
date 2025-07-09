using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using PreSystem.StockControl.Application.DTOs;
using PreSystem.StockControl.Application.Interfaces.Services;
using PreSystem.StockControl.Domain.Entities;
using PreSystem.StockControl.Domain.Interfaces.Repositories;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace PreSystem.StockControl.WebApi.Services
{
    public class AuthService : IAuthService
    {
        private readonly IUserService _userService;
        private readonly IEmailService _emailService;
        private readonly IConfiguration _configuration;
        private readonly IPasswordResetTokenRepository _tokenRepository;
        private readonly IUserRepository _userRepository;

        public AuthService(
            IUserService userService,
            IEmailService emailService,
            IConfiguration configuration,
            IPasswordResetTokenRepository tokenRepository,
            IUserRepository userRepository)
        {
            _userService = userService;
            _emailService = emailService;
            _configuration = configuration;
            _tokenRepository = tokenRepository;
            _userRepository = userRepository;
        }

        public async Task<string> GenerateJwtTokenAsync(UserResponseDto user)
        {
            var jwtSecret = _configuration["JWT_SECRET"]
                ?? Environment.GetEnvironmentVariable("JWT_SECRET")
                ?? throw new InvalidOperationException("JWT_SECRET não configurado.");

            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(jwtSecret);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim("UserId", user.Id.ToString()),
                    new Claim("Email", user.Email),
                    new Claim("Name", user.Name),
                    new Claim("Role", user.Role)
                }),
                Expires = DateTime.UtcNow.AddDays(7),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        public async Task<UserResponseDto?> ValidateAndLoginAsync(UserLoginDto loginDto)
        {
            var user = await _userService.AuthenticateAsync(loginDto);
            if (user == null) return null;

            return new UserResponseDto
            {
                Id = user.Id,
                Name = user.Name,
                Email = user.Email,
                Role = user.Role,
                CreatedAt = user.CreatedAt
            };
        }

        public async Task<PasswordResetResponseDto> RequestPasswordResetAsync(string email)
        {
            try
            {
                // Verificar se usuário existe
                var user = await _userRepository.GetByEmailAsync(email);
                if (user == null)
                {
                    // Por segurança, sempre retorna sucesso mesmo se email não existir
                    return new PasswordResetResponseDto
                    {
                        Success = true,
                        Message = "Se o email existe em nosso sistema, você receberá instruções para redefinir sua senha."
                    };
                }

                // Invalidar tokens existentes
                await _tokenRepository.InvalidateTokensByEmailAsync(email);

                // Gerar novo token
                var resetToken = GenerateSecureToken();
                var tokenEntity = new PasswordResetToken
                {
                    Email = email,
                    Token = resetToken,
                    ExpiresAt = DateTime.UtcNow.AddHours(24),
                    IsUsed = false,
                    CreatedAt = DateTime.UtcNow,
                    UserId = user.Id
                };

                await _tokenRepository.AddAsync(tokenEntity);

                // Gerar link de reset
                var frontendUrl = _configuration["FrontendUrl"]
                    ?? Environment.GetEnvironmentVariable("FRONTEND_URL")
                    ?? "http://localhost:3000";

                var resetLink = $"{frontendUrl}/reset-password?token={resetToken}";

                // Enviar email
                var emailSent = await _emailService.SendPasswordResetEmailAsync(user.Email, resetLink);

                return new PasswordResetResponseDto
                {
                    Success = emailSent,
                    Message = emailSent
                        ? "Instruções enviadas para seu email."
                        : "Erro ao enviar email. Tente novamente.",
                    Token = resetToken // Apenas para desenvolvimento - remover em produção
                };
            }
            catch (Exception)
            {
                return new PasswordResetResponseDto
                {
                    Success = false,
                    Message = "Erro interno. Tente novamente mais tarde."
                };
            }
        }

        public async Task<PasswordResetResponseDto> ResetPasswordAsync(string token, string newPassword)
        {
            try
            {
                // Validar token
                var resetToken = await _tokenRepository.GetByTokenAsync(token);
                if (resetToken == null || resetToken.IsUsed || resetToken.ExpiresAt < DateTime.UtcNow)
                {
                    return new PasswordResetResponseDto
                    {
                        Success = false,
                        Message = "Token inválido ou expirado."
                    };
                }

                // Buscar usuário
                var user = await _userRepository.GetByIdAsync(resetToken.UserId!.Value);
                if (user == null)
                {
                    return new PasswordResetResponseDto
                    {
                        Success = false,
                        Message = "Usuário não encontrado."
                    };
                }

                // Atualizar senha
                user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(newPassword);
                await _userRepository.UpdateAsync(user);

                // Marcar token como usado
                resetToken.IsUsed = true;
                await _tokenRepository.UpdateAsync(resetToken);

                return new PasswordResetResponseDto
                {
                    Success = true,
                    Message = "Senha redefinida com sucesso."
                };
            }
            catch (Exception)
            {
                return new PasswordResetResponseDto
                {
                    Success = false,
                    Message = "Erro interno. Tente novamente mais tarde."
                };
            }
        }

        public async Task<bool> ValidateResetTokenAsync(string token)
        {
            var resetToken = await _tokenRepository.GetByTokenAsync(token);
            return resetToken != null && !resetToken.IsUsed && resetToken.ExpiresAt > DateTime.UtcNow;
        }

        private static string GenerateSecureToken()
        {
            using var rng = RandomNumberGenerator.Create();
            var bytes = new byte[32];
            rng.GetBytes(bytes);
            return Convert.ToBase64String(bytes).Replace("+", "-").Replace("/", "_").Replace("=", "");
        }
    }
}