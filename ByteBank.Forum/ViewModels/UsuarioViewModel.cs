using ByteBank.Forum.Models;
using System.ComponentModel.DataAnnotations;

namespace ByteBank.Forum.ViewModels
{
    public class UsuarioViewModel
    {
        public UsuarioViewModel()
        {
        }

        public UsuarioViewModel(UsuarioAplicacao usuarioAplicacao)
        {
            Id = usuarioAplicacao.Id;
            NomeCompleto = usuarioAplicacao.NomeCompleto;
            Email = usuarioAplicacao.Email;
            UserName = usuarioAplicacao.UserName;
        }

        public string Id{ get; set; }

        [Display(Name = "Nome")]
        public string NomeCompleto{ get; set; }

        [Display(Name = "E-mail")]
        public string Email { get; set; }

        [Display(Name = "Username")]
        public string UserName { get; set; }
    }
}