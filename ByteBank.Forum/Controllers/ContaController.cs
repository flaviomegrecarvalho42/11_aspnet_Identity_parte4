using ByteBank.Forum.Models;
using ByteBank.Forum.ViewModels;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using System.Configuration;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace ByteBank.Forum.Controllers
{
    public class ContaController : Controller
    {
        private UserManager<UsuarioAplicacao> _userManager;
        private SignInManager<UsuarioAplicacao, string> _signInManager;

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

        public SignInManager<UsuarioAplicacao, string> SignInManager
        {
            get
            {
                if (_signInManager == null)
                {
                    var contextOwin = HttpContext.GetOwinContext();
                    _signInManager = contextOwin.GetUserManager<SignInManager<UsuarioAplicacao, string>>();
                }

                return _signInManager;
            }

            set { _signInManager = value; }
        }

        public IAuthenticationManager AuthenticationManager
        {
            get
            {
                var contextoOwin = Request.GetOwinContext();
                return contextoOwin.Authentication;
            }
        }

        public ActionResult Registrar()
        {
            return View();
        }

        [HttpPost]
        public async Task<ActionResult> Registrar(ContaRegistrarViewModel contaRegistrarViewModel)
        {
            if (ModelState.IsValid)
            {
                var novoUsuario = new UsuarioAplicacao
                {
                    Email = contaRegistrarViewModel.Email,
                    UserName = contaRegistrarViewModel.UserName,
                    NomeCompleto = contaRegistrarViewModel.NomeCompleto
                };

                var usuarioCadastrado = await UserManager.FindByEmailAsync(contaRegistrarViewModel.Email);

                if (usuarioCadastrado != null)
                {
                    return View("AguardandoConfirmacao");
                }

                var resultado = await UserManager.CreateAsync(novoUsuario, contaRegistrarViewModel.Senha);

                if (!resultado.Succeeded)
                {
                    AdicionaErros(resultado);

                    return View(contaRegistrarViewModel);
                }

                // Enviar o email de confirmação
                await EnviarEmailDeConfirmacaoOuAlteracaoSenhaAsync(novoUsuario, false);
                return View("AguardandoConfirmacao");
            }

            return View("Error");
        }

        [HttpPost]
        public ActionResult RegistrarPorAutenticacaoExterna(string provider)
        {
            SignInManager.AuthenticationManager.Challenge(new AuthenticationProperties
            {
                RedirectUri = Url.Action("RegistrarPorAutenticacaoExternaCallback")
            }, provider);

            return new HttpUnauthorizedResult();
        }

        public async Task<ActionResult> RegistrarPorAutenticacaoExternaCallback()
        {
            var loginInfo = await SignInManager.AuthenticationManager.GetExternalLoginInfoAsync();
            var usuarioExiste = await UserManager.FindByEmailAsync(loginInfo.Email);

            if (usuarioExiste != null)
            {
                return View("Error");
            }

            var novoUsuario = new UsuarioAplicacao
            {
                Email = loginInfo.Email,
                UserName = loginInfo.Email,
                NomeCompleto = loginInfo.ExternalIdentity.FindFirstValue(loginInfo.ExternalIdentity.NameClaimType)
            };

            var resultado = await UserManager.CreateAsync(novoUsuario);

            if (resultado.Succeeded)
            {
                var resultadoAddLoginInfo = await UserManager.AddLoginAsync(novoUsuario.Id, loginInfo.Login);

                if (resultadoAddLoginInfo.Succeeded)
                {
                    return RedirectToAction("Index", "Home");
                }
            }

            return View("Error");
        }

        public async Task<ActionResult> ConfirmacarEmail(string usuarioId, string token)
        {
            if (string.IsNullOrWhiteSpace(usuarioId) || string.IsNullOrWhiteSpace(token))
            {
                return View("Error");
            }

            var resultado = await UserManager.ConfirmEmailAsync(usuarioId, token);

            if (!resultado.Succeeded)
            {
                return View("Error");
            }

            return View("EmailConfirmado");
        }

        public ActionResult Login()
        {
            ContaLoginViewModel contaLoginViewModel = new ContaLoginViewModel();
            contaLoginViewModel.ContinuarLogado = true;
            ViewData.Model = contaLoginViewModel;

            return View();
        }

        [HttpPost]
        public async Task<ActionResult> Login(ContaLoginViewModel contaLoginViewModel)
        {
            if (ModelState.IsValid)
            {
                var usuario = await UserManager.FindByEmailAsync(contaLoginViewModel.Email);

                if (usuario == null)
                {
                    return SenhaOuUsuarioInvalidos();
                }

                var signInResultado = await SignInManager
                                            .PasswordSignInAsync(usuario.UserName,
                                                                 contaLoginViewModel.Password,
                                                                 isPersistent: contaLoginViewModel.ContinuarLogado,
                                                                 shouldLockout: true);

                switch (signInResultado)
                {
                    case SignInStatus.Success:
                        if (!usuario.EmailConfirmed)
                        {
                            AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
                            return View("AguardandoConfirmacao");
                        }

                        return RedirectToAction("Index", "Home");
                    case SignInStatus.LockedOut:
                        bool senhaCorreta = await UserManager.CheckPasswordAsync(usuario, contaLoginViewModel.Password);

                        if (senhaCorreta)
                        {
                            ModelState.AddModelError("", "A conta está bloqueada!");
                        }
                        else
                        {
                            return SenhaOuUsuarioInvalidos();
                        }

                        break;
                    case SignInStatus.RequiresVerification:
                        return RedirectToAction("VerificarDoisFatores");
                    default:
                        return SenhaOuUsuarioInvalidos();
                }
            }

            return View("Error");
        }

        [HttpPost]
        public ActionResult LoginPorAutenticacaoExterna(string provider)
        {
            SignInManager.AuthenticationManager.Challenge(new AuthenticationProperties { RedirectUri = Url.Action("LoginPorAutenticacaoExternaCallback") },
                                                          provider);

            return new HttpUnauthorizedResult();
        }

        public async Task<ActionResult> LoginPorAutenticacaoExternaCallback()
        {
            var loginInfo = await SignInManager.AuthenticationManager.GetExternalLoginInfoAsync();
            var signInResultado = await SignInManager.ExternalSignInAsync(loginInfo, true);

            if (signInResultado == SignInStatus.Success)
            {
                return RedirectToAction("Index", "Home");
            }

            return View("Error");
        }

        public ActionResult LembrarSenha()
        {
            return View();
        }

        [HttpPost]
        public async Task<ActionResult> LembrarSenha(ContaEsqueciSenhaViewModel contaEsqueciSenhViewModel)
        {
            if (ModelState.IsValid)
            {
                var usuario = await UserManager.FindByEmailAsync(contaEsqueciSenhViewModel.Email);

                if (usuario != null)
                {
                    await EnviarEmailDeConfirmacaoOuAlteracaoSenhaAsync(usuario, true);
                }

                return View("EmailAlteracaoSenhaEnviado");
            }

            return View("Error");
        }

        public ActionResult ConfirmarAlteracaoSenha(string usuarioId, string token)
        {
            var contaConfirmaAlteracaoSenhaViewModel = new ContaConfirmaAlteracaoSenhaViewModel
            {
                UsuarioId = usuarioId,
                Token = token
            };

            return View(contaConfirmaAlteracaoSenhaViewModel);
        }

        [HttpPost]
        public async Task<ActionResult> ConfirmarAlteracaoSenha(ContaConfirmaAlteracaoSenhaViewModel contaConfirmaAlteracaoSenhaViewModel)
        {
            if (ModelState.IsValid)
            {
                // Verifica o Token recebido
                // Verifica o ID do usuário
                // Mudar a senha
                var resultadoAlteracao = await UserManager.ResetPasswordAsync(contaConfirmaAlteracaoSenhaViewModel.UsuarioId,
                                                                              contaConfirmaAlteracaoSenhaViewModel.Token,
                                                                              contaConfirmaAlteracaoSenhaViewModel.NewPassword);

                if (!resultadoAlteracao.Succeeded)
                {
                    AdicionaErros(resultadoAlteracao);
                }

                return View("AlteracaoSenhaConfirmada");
            }

            return View("Error");
        }

        [HttpPost]
        public ActionResult Logoff()
        {
            AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
            return RedirectToAction("Index", "Home");
        }

        [HttpPost]
        public ActionResult EsquecerNavegador()
        {
            AuthenticationManager.SignOut(DefaultAuthenticationTypes.TwoFactorRememberBrowserCookie);

            return RedirectToAction("AtualizarDadosConta");
        }

        [HttpPost]
        public async Task<ActionResult> DeslogarDeTodosOsLocais()
        {
            var usuarioId = HttpContext.User.Identity.GetUserId();
            await UserManager.UpdateSecurityStampAsync(usuarioId);
            
            return RedirectToAction("Index", "Home");
        }

        public async Task<ActionResult> AtualizarDadosConta()
        {
            var usuarioId = HttpContext.User.Identity.GetUserId();
            var usuario = await UserManager.FindByIdAsync(usuarioId);

            var contaDadosMinhaContaViewModel = new ContaDadosMinhaContaViewModel
            {
                NomeCompleto = usuario.NomeCompleto,
                Celular = usuario.PhoneNumber,
                HabilitarAutenticacaoDoisFatores = usuario.TwoFactorEnabled,
                CelularConfirmado = usuario.PhoneNumberConfirmed,
            };

            return View(contaDadosMinhaContaViewModel);
        }

        [HttpPost]
        public async Task<ActionResult> AtualizarDadosConta(ContaDadosMinhaContaViewModel contaDadosMinhaContaViewModel)
        {
            if (ModelState.IsValid)
            {
                var usuarioId = HttpContext.User.Identity.GetUserId();
                var usuario = await UserManager.FindByIdAsync(usuarioId);

                usuario.NomeCompleto = contaDadosMinhaContaViewModel.NomeCompleto;
                usuario.PhoneNumber = contaDadosMinhaContaViewModel.Celular;

                if (!usuario.PhoneNumberConfirmed)
                {
                    await EnviarSmsConfirmacaoAsync(usuario);
                }
                else
                {
                    usuario.TwoFactorEnabled = contaDadosMinhaContaViewModel.HabilitarAutenticacaoDoisFatores;
                }

                var resultadoUpdate = await UserManager.UpdateAsync(usuario);

                if (!resultadoUpdate.Succeeded)
                {
                    AdicionaErros(resultadoUpdate);
                }

                return View("DadosContaAtualizado", contaDadosMinhaContaViewModel);
            }

            return View("Error");
        }

        public ActionResult VerificarCodigoCelular()
        {
            return View();
        }

        [HttpPost]
        public async Task<ActionResult> VerificarCodigoCelular(string token)
        {
            var usuarioId = HttpContext.User.Identity.GetUserId();
            var usuario = await UserManager.FindByIdAsync(usuarioId);

            var resultado = await UserManager.ChangePhoneNumberAsync(usuarioId, usuario.PhoneNumber, token);

            if (!resultado.Succeeded)
            {
                AdicionaErros(resultado);
            }

            return View("CelularVerificado");
        }

        public async Task<ActionResult> VerificarDoisFatores()
        {
            bool sendTwoFactorCode = await SignInManager.SendTwoFactorCodeAsync(ConfigurationManager.AppSettings["provider:two_factor_signIn"]);

            if (!sendTwoFactorCode)
            {
                return View("Error");
            }

            return View();
        }

        [HttpPost]
        public async Task<ActionResult> VerificarDoisFatores(ContaVerificarDoisFatoresViewModel contaVerificarDoisFatoresViewModel)
        {
            var resultado = await SignInManager.TwoFactorSignInAsync(ConfigurationManager.AppSettings["provider:two_factor_signIn"],
                                                                     contaVerificarDoisFatoresViewModel.Token,
                                                                     isPersistent: contaVerificarDoisFatoresViewModel.ContinuarLogado,
                                                                     rememberBrowser: contaVerificarDoisFatoresViewModel.LembrarDesteComputador);

            if (resultado != SignInStatus.Success)
            {
                return View("Error");
            }

            return View("VerificarDoisFatoresRealizado");
        }

        private void AdicionaErros(IdentityResult identityResult)
        {
            foreach (var erro in identityResult.Errors)
            {
                ModelState.AddModelError("", erro);
            }
        }

        private ActionResult SenhaOuUsuarioInvalidos()
        {
            ModelState.AddModelError("", "Credenciais inválidas!");
            return View("Login");
        }

        private async Task EnviarEmailDeConfirmacaoOuAlteracaoSenhaAsync(UsuarioAplicacao usuarioAplicacaoModel, bool ehAlteracaoSenha)
        {
            string textoLinkCallBack = "ConfirmarEmail";
            string assuntoEmail = "Fórum ByteBank - Confirmação de Email";

            if (ehAlteracaoSenha)
            {
                textoLinkCallBack = "ConfirmarAlteracaoSenha";
                assuntoEmail = "Fórum ByteBank - Alteração de Senha";
            }

            // Gerar o token de reset da senha
            var tokenEmail = ehAlteracaoSenha ? await UserManager.GeneratePasswordResetTokenAsync(usuarioAplicacaoModel.Id) :
                                                await UserManager.GenerateEmailConfirmationTokenAsync(usuarioAplicacaoModel.Id);

            // Gerar a url para o usuário
            var linkDeCallback = Url.Action(
                textoLinkCallBack,
                "Conta",
                new { usuarioId = usuarioAplicacaoModel.Id, token = tokenEmail },
                Request.Url.Scheme);

            // Enviar email
            await UserManager.SendEmailAsync(
                usuarioAplicacaoModel.Id,
                assuntoEmail,
                ehAlteracaoSenha ? $"Bem-vido ao fórum ByteBank, cliqque aqui {linkDeCallback} para alterar a sua senha!" :
                                   $"Bem-vido ao fórum ByteBank, cliqque aqui {linkDeCallback} para confirmar seu email!");
        }

        private async Task EnviarSmsConfirmacaoAsync(UsuarioAplicacao usuarioAplicacao)
        {
            var tokenComfirmacao = await UserManager.GenerateChangePhoneNumberTokenAsync(usuarioAplicacao.Id, usuarioAplicacao.PhoneNumber);
            await UserManager.SendSmsAsync(usuarioAplicacao.Id, $"Token de Confirmação: {tokenComfirmacao}");
        }
    }
}