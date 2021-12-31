using ByteBank.Forum.Util;
using System.Web.Mvc;

namespace ByteBank.Forum.Controllers
{
    [Authorize(Roles = Roles.Administrador)]
    public class AdministracaoController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }
    }
}