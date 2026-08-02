using Microsoft.AspNetCore.Mvc;

namespace AuthService.Controllers;

public class AuthControllerBase : ControllerBase
{
    protected string? GetCurrentUserId() => User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
}
