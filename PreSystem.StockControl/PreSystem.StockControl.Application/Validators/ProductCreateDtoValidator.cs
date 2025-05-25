using FluentValidation;
using PreSystem.StockControl.Application.DTOs;

namespace PreSystem.StockControl.Application.Validators
{
    // Validador para o DTO de criação de produto
    public class ProductCreateDtoValidator : AbstractValidator<ProductCreateDto>
    {
        public ProductCreateDtoValidator()
        {
            // O campo Name é obrigatório e deve ter no máximo 100 caracteres
            RuleFor(p => p.Name)
                .NotEmpty().WithMessage("O nome do produto é obrigatório.")
                .MaximumLength(100).WithMessage("O nome do produto deve ter no máximo 100 caracteres.");

            // O campo Description é opcional, mas se for preenchido, terá no máximo 255 caracteres
            RuleFor(p => p.Description)
                .MaximumLength(255).WithMessage("A descrição deve ter no máximo 255 caracteres.");

            // O campo CreatedBy deve ser maior que zero
            RuleFor(p => p.CreatedBy)
                .NotEmpty().WithMessage("O campo CreatedBy deve ser um número maior que zero.");

            // O produto deve ter ao menos um componente vinculado
            RuleFor(p => p.Components)
                .NotEmpty().WithMessage("O produto deve conter pelo menos um componente.");

            // Cada componente na lista também será validado individualmente
            RuleForEach(p => p.Components).SetValidator(new ProductComponentCreateDtoValidator());
        }
    }
}