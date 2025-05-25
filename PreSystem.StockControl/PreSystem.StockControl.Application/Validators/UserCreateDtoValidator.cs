using FluentValidation;
using PreSystem.StockControl.Application.DTOs;

namespace PreSystem.StockControl.Application.Validators
{
    public class UserCreateDtoValidator : AbstractValidator<UserCreateDto>
    {
        public UserCreateDtoValidator()
        {
            // O nome é obrigatório e deve ter entre 2 e 100 caracteres
            RuleFor(x => x.Name)
                .NotEmpty().WithMessage("O nome é obrigatório.")
                .Length(2, 100).WithMessage("O nome deve ter entre 2 e 100 caracteres.");

            // O e-mail é obrigatório e deve ter um formato válido
            RuleFor(x => x.Email)
                .NotEmpty().WithMessage("O e-mail é obrigatório.")
                .EmailAddress().WithMessage("Formato de e-mail inválido.");

            // A senha é obrigatória e deve ter pelo menos 4 caracteres
            RuleFor(x => x.Password)
                .NotEmpty().WithMessage("A senha é obrigatória.")
                .MinimumLength(4).WithMessage("A senha deve ter pelo menos 4 caracteres.");

            // O papel (role) é obrigatório e deve ser 'admin' ou 'operator'
            RuleFor(x => x.Role)
                .NotEmpty().WithMessage("O papel é obrigatório.")
                .Must(role => role == "admin" || role == "operator")
                .WithMessage("O papel deve ser 'admin' ou 'operator'.");
        }
    }
}
