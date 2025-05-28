using FluentValidation;
using PreSystem.StockControl.Application.DTOs;

namespace PreSystem.StockControl.Application.Validators
{
    /// <summary>
    /// Validador para o DTO de validação de senha
    /// </summary>
    public class ValidatePasswordDtoValidator : AbstractValidator<ValidatePasswordDto>
    {
        public ValidatePasswordDtoValidator()
        {
            // A senha é obrigatória e não pode estar vazia
            RuleFor(x => x.Password)
                .NotEmpty().WithMessage("A senha é obrigatória.")
                .MinimumLength(1).WithMessage("A senha não pode estar vazia.");
        }
    }
}