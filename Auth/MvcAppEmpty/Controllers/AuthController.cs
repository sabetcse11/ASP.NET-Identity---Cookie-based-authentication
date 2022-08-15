using Microsoft.Owin;
using Microsoft.Owin.Security;
using MvcAppEmpty.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;

namespace MvcAppEmpty.Controllers
{
    [AllowAnonymous]
    public class AuthController : Controller
    {
        // GET: Auth
        public ActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Login(Login model)
        {
            if (!ModelState.IsValid)
                return View(model);

            if (model.Email.Length > 0 && model.Password.Length > 0)
            {
                // Credentials are ok, now do the sign in
                // Get the authentication Manager
                // create a claim
                // create claimsidentity
                // sign in by manager & claimsidentity

                IOwinContext context = Request.GetOwinContext();
                IAuthenticationManager manager = context.Authentication;

                var claims = new List<Claim>();
                claims.Add(new Claim(ClaimTypes.Email, model.Email));
                claims.Add(new Claim(ClaimTypes.Name, "Sabet"));

                ClaimsIdentity identity = new ClaimsIdentity(claims: claims, authenticationType: "ApplicationCookie");
                manager.SignIn(identities: identity);
                return Redirect("/");
            }
            return View(model);
        }

        [Authorize]
        public ActionResult LogOut()
        {
            IOwinContext context = Request.GetOwinContext();
            IAuthenticationManager manager = context.Authentication;
            manager.SignOut();
            return Redirect("/");
        }
    }
}