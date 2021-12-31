using System.ComponentModel.DataAnnotations;

namespace ByteBank.Forum.ViewModels
{
    public class ContaDadosMinhaContaViewModel
    {
        [Required]
        [Display(Name = "Nome Completo")]
        public string NomeCompleto { get; set; }

        [Display(Name = "Celular")]
        public string Celular { get; set; }

        [Display(Name = "Habilitar Autenticação de Dois Fatores")]
        public bool HabilitarAutenticacaoDoisFatores { get; set; }

        public bool CelularConfirmado { get; set; }
    }
}