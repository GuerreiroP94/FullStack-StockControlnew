using Microsoft.AspNetCore.Http;
using PreSystem.StockControl.Application.Interfaces.Services;
using System.Security.Claims;

namespace PreSystem.StockControl.Application.Services
{
    public class UserContextService : IUserContextService
    {
        private readonly IHttpContextAccessor _httpContextAccessor;

        public UserContextService(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }

        public string? GetCurrentUsername()
        {
            var context = _httpContextAccessor.HttpContext;
            return context?.User?.FindFirst("Name")?.Value
                ?? context?.User?.Identity?.Name;
        }

        public int? GetCurrentUserId()
        {
            var context = _httpContextAccessor.HttpContext;
            var userIdClaim = context?.User?.FindFirst("UserId")?.Value;

            if (int.TryParse(userIdClaim, out int userId))
                return userId;

            return null;
        }
    }
}