using System.Security.Claims;

namespace PreSystem.StockControl.Application.Interfaces.Services
{
    public interface IUserContextService
    {
        string? GetCurrentUsername();
        int? GetCurrentUserId();
    }
}
