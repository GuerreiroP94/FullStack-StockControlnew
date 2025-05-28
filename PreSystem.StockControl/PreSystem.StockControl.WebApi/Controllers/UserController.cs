// PreSystem.StockControl.WebApi/Controllers/UserController.cs

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PreSystem.StockControl.Application.DTOs;
using PreSystem.StockControl.Application.Interfaces.Services;
using PreSystem.StockControl.Application.Services;

namespace PreSystem.StockControl.WebApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UserController : ControllerBase
    {
        private readonly IUserService _userService;
        private readonly IUserContextService _userContextService;

        public UserController(IUserService userService, IUserContextService userContextService) // ADICIONE O PARÂMETRO
        {
            _userService = userService;
            _userContextService = userContextService; // ADICIONE ESTA ATRIBUIÇÃO
        }

        [Authorize(Roles = "admin")]
        [HttpGet]
        public async Task<IActionResult> GetAllUsers()
        {
            var users = await _userService.GetAllUsersAsync();
            return Ok(users);
        }

        [Authorize(Roles = "admin")]
        [HttpGet("{id:int}")]
        public async Task<IActionResult> GetUserById(int id)
        {
            var user = await _userService.GetUserByIdAsync(id);
            if (user == null) return NotFound();
            return Ok(user);
        }

        [Authorize(Roles = "admin")]
        [HttpPost]
        public async Task<IActionResult> CreateUser([FromBody] UserCreateDto dto)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);
            var createdUser = await _userService.CreateUserAsync(dto);
            return CreatedAtAction(nameof(GetUserById), new { id = createdUser.Id }, createdUser);
        }

        [Authorize(Roles = "admin")]
        [HttpPut("{id:int}/role")]
        public async Task<IActionResult> UpdateUserRole(int id, [FromBody] string newRole)
        {
            var result = await _userService.UpdateUserRoleAsync(id, newRole);
            if (!result) return NotFound();
            return NoContent();
        }

        [Authorize(Roles = "admin")]
        [HttpPut("{id:int}")]
        public async Task<IActionResult> UpdateUserByAdmin(int id, [FromBody] UserUpdateDto dto)
        {
            var result = await _userService.UpdateUserByAdminAsync(id, dto);
            if (!result) return NotFound();
            return NoContent();
        }

        /// <summary>
        /// Valida a senha atual do usuário autenticado
        /// </summary>
        /// <remarks>
        /// Este endpoint é usado para verificar se a senha fornecida corresponde à senha atual do usuário.
        /// É útil em cenários onde o usuário precisa confirmar sua identidade antes de realizar ações sensíveis,
        /// como alterar a própria senha ou dados críticos do perfil.
        /// 
        /// Exemplo de requisição:
        /// 
        ///     POST /api/user/1/validate-password
        ///     {
        ///         "password": "minhasenhaatual123"
        ///     }
        /// 
        /// </remarks>
        /// <param name="id">ID do usuário (deve ser o mesmo do usuário autenticado)</param>
        /// <param name="dto">Objeto contendo a senha a ser validada</param>
        /// <returns>Retorna um objeto indicando se a senha é válida</returns>
        /// <response code="200">Senha validada com sucesso. Retorna { "isValid": true/false }</response>
        /// <response code="400">Dados inválidos na requisição</response>
        /// <response code="401">Usuário não autenticado</response>
        /// <response code="403">Usuário tentando validar senha de outro usuário</response>
        /// <response code="500">Erro interno do servidor</response>
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
                // Obtém o ID do usuário atual através do contexto (JWT)
                var currentUserId = _userContextService.GetCurrentUserId();

                // Verifica se conseguiu obter o ID do usuário
                if (currentUserId == null)
                {
                    return Unauthorized(new { error = "Usuário não autenticado" });
                }

                // Verifica se o usuário está tentando validar sua própria senha
                if (currentUserId != id)
                {
                    // CORREÇÃO: Usar StatusCode 403 ao invés de Forbid()
                    return StatusCode(403, new { error = "Você não tem permissão para validar a senha de outro usuário." });
                }

                // Valida o modelo
                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState);
                }

                // Chama o serviço para realizar a validação
                var isValid = await _userService.ValidatePasswordAsync(id, dto.Password);

                // Retorna o resultado em formato JSON
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
