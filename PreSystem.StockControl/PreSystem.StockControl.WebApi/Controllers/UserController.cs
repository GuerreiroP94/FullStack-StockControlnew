using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PreSystem.StockControl.Application.DTOs;
using PreSystem.StockControl.Application.Interfaces.Services;
using System.Security.Claims;

namespace PreSystem.StockControl.WebApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UserController : ControllerBase
    {
        private readonly IUserService _userService;
        private readonly IUserContextService _userContextService;

        public UserController(IUserService userService, IUserContextService userContextService)
        {
            _userService = userService;
            _userContextService = userContextService;
        }

        // GET: api/user - Listar todos (apenas admin)
        [Authorize(Roles = "admin")]
        [HttpGet]
        public async Task<IActionResult> GetAllUsers()
        {
            var users = await _userService.GetAllUsersAsync();
            return Ok(users);
        }

        // GET: api/user/me - Dados do usuário atual
        [Authorize]
        [HttpGet("me")]
        public async Task<IActionResult> GetCurrentUser()
        {
            var userId = _userContextService.GetCurrentUserId();
            if (userId == null) return Unauthorized();

            var user = await _userService.GetUserByIdAsync(userId.Value);
            if (user == null) return NotFound();

            return Ok(user);
        }

        // GET: api/user/{id} - Buscar por ID (usuário pode ver seus próprios dados)
        [Authorize]
        [HttpGet("{id:int}")]
        public async Task<IActionResult> GetUserById(int id)
        {
            var currentUserId = _userContextService.GetCurrentUserId();
            var currentUserRole = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value;

            // Se não for admin, só pode ver seus próprios dados
            if (currentUserRole != "admin" && currentUserId != id)
            {
                return Forbid("Você só pode acessar seus próprios dados.");
            }

            var user = await _userService.GetUserByIdAsync(id);
            if (user == null) return NotFound();
            return Ok(user);
        }

        // POST: api/user - Criar usuário (apenas admin)
        [Authorize(Roles = "admin")]
        [HttpPost]
        public async Task<IActionResult> CreateUser([FromBody] UserCreateDto dto)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);
            var createdUser = await _userService.CreateUserAsync(dto);
            return CreatedAtAction(nameof(GetUserById), new { id = createdUser.Id }, createdUser);
        }

        // PUT: api/user/{id}/role - Atualizar role (apenas admin)
        [Authorize(Roles = "admin")]
        [HttpPut("{id:int}/role")]
        public async Task<IActionResult> UpdateUserRole(int id, [FromBody] string newRole)
        {
            var result = await _userService.UpdateUserRoleAsync(id, newRole);
            if (!result) return NotFound();
            return NoContent();
        }

        // PUT: api/user/{id} - Atualizar usuário (apenas admin)
        [Authorize(Roles = "admin")]
        [HttpPut("{id:int}")]
        public async Task<IActionResult> UpdateUserByAdmin(int id, [FromBody] UserUpdateDto dto)
        {
            var result = await _userService.UpdateUserByAdminAsync(id, dto);
            if (!result) return NotFound();
            return NoContent();
        }

        // POST: api/user/{id}/validate-password - Validar senha do usuário
        [Authorize]
        [HttpPost("{id:int}/validate-password")]
        [ProducesResponseType(typeof(object), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(StatusCodes.Status403Forbidden)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> ValidatePassword(int id, [FromBody] ValidatePasswordDto dto)
        {
            try
            {
                var currentUserId = _userContextService.GetCurrentUserId();

                if (currentUserId == null)
                {
                    return Unauthorized(new { error = "Usuário não autenticado" });
                }

                if (currentUserId != id)
                {
                    return StatusCode(403, new { error = "Você não tem permissão para validar a senha de outro usuário." });
                }

                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState);
                }

                var isValid = await _userService.ValidatePasswordAsync(id, dto.Password);

                return Ok(new
                {
                    isValid = isValid,
                    message = isValid ? "Senha válida" : "Senha inválida"
                });
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(new { error = ex.Message });
            }
            catch (Exception)
            {
                return StatusCode(500, new { error = "Erro ao processar solicitação" });
            }
        }
    }
}