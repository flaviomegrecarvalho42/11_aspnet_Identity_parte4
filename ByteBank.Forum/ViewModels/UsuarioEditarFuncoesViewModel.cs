using ByteBank.Forum.Models;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;

namespace ByteBank.Forum.ViewModels
{
    public class UsuarioEditarFuncoesViewModel
    {
        public UsuarioEditarFuncoesViewModel()
        {
        }

        public UsuarioEditarFuncoesViewModel(UsuarioAplicacao usuarioAplicacao, RoleManager<IdentityRole> roleManager)
        {
            Id = usuarioAplicacao.Id;
            NomeCompleto = usuarioAplicacao.NomeCompleto;
            Email = usuarioAplicacao.Email;
            UserName = usuarioAplicacao.UserName;
            Funcoes = roleManager
                      .Roles
                      .ToList()
                      .Select(funcao => new UsuarioFuncaoViewModel
                      {
                          Nome = funcao.Name,
                          Id = funcao.Id
                      }).ToList();

            foreach (var funcao in Funcoes)
            {
                bool usuarioPossuiRole = usuarioAplicacao.Roles.Any(usuarioRole => usuarioRole.RoleId == funcao.Id);
                funcao.Selecionado = usuarioPossuiRole;
            }
        }

        public string Id { get; set; }

        [Display(Name = "Nome")]
        public string NomeCompleto { get; set; }

        [Display(Name = "E-mail")]
        public string Email { get; set; }

        [Display(Name = "Username")]
        public string UserName { get; set; }

        [Display(Name = "Funções")]
        public List<UsuarioFuncaoViewModel> Funcoes { get; set; }
    }
}