using ByteBank.Forum.Models;
using ByteBank.Forum.Util;
using ByteBank.Forum.ViewModels;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace ByteBank.Forum.Controllers
{
    [Authorize(Roles = Roles.Administrador)]
    public class UsuarioController : Controller
    {
        private UserManager<UsuarioAplicacao> _userManager;
        private RoleManager<IdentityRole> _roleManager;

        public UserManager<UsuarioAplicacao> UserManager
        {
            get
            {
                if (_userManager == null)
                {
                    var contextOwin = HttpContext.GetOwinContext();
                    _userManager = contextOwin.GetUserManager<UserManager<UsuarioAplicacao>>();
                }

                return _userManager;
            }

            set { _userManager = value; }
        }

        public RoleManager<IdentityRole> RoleManager
        {
            get
            {
                if (_roleManager == null)
                {
                    var contextOwin = HttpContext.GetOwinContext();
                    _roleManager = contextOwin.GetUserManager<RoleManager<IdentityRole>>();
                }

                return _roleManager;
            }

            set { _roleManager = value; }
        }

        public ActionResult Index()
        {
            var usuarios = UserManager
                          .Users
                          .ToList()
                          .Select(usuario => new UsuarioViewModel(usuario));

            return View(usuarios);
        }

        public async Task<ActionResult> EditarFuncoes(string id)
        {
            var usuario = await UserManager.FindByIdAsync(id);
            var modelo = new UsuarioEditarFuncoesViewModel(usuario, RoleManager);

            return View(modelo);
        }

        [HttpPost]
        public async Task<ActionResult> EditarFuncoes(UsuarioEditarFuncoesViewModel usuarioFuncaoViewModel)
        {
            if (ModelState.IsValid)
            {
                var usuario = await UserManager.FindByIdAsync(usuarioFuncaoViewModel.Id);
                var rolesUsuario = UserManager.GetRoles(usuario.Id);

                var resultadoRemocao = await UserManager.RemoveFromRolesAsync(usuarioFuncaoViewModel.Id,rolesUsuario.ToArray());

                if (resultadoRemocao.Succeeded)
                {
                    var funcoesSelecionadasPeloAdmin = usuarioFuncaoViewModel.Funcoes
                                                                             .Where(f => f.Selecionado)
                                                                             .Select(f => f.Nome)
                                                                             .ToArray();

                    var resultadoInclusao = await UserManager.AddToRolesAsync(usuarioFuncaoViewModel.Id, funcoesSelecionadasPeloAdmin);

                    if (resultadoInclusao.Succeeded)
                    {
                        return RedirectToAction("Index");
                    }
                }
            }

            return View();
        }
    }
}