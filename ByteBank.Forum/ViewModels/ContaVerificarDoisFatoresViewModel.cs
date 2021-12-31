using System.ComponentModel.DataAnnotations;

namespace ByteBank.Forum.ViewModels
{
    public class ContaVerificarDoisFatoresViewModel
    {
        [Required]
        [Display(Name = "Token do SMS")]
        public string Token { get; set; }

        [Display(Name = "Continuar logado")]
        public bool ContinuarLogado { get; set; }

        [Display(Name = "Lembrar deste computador")]
        public bool LembrarDesteComputador { get; set; }
    }
}