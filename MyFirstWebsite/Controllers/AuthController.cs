using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using MyFirstWebsite.Models;
using System.Security.Claims;

namespace MyFirstWebsite.Controllers
{
   [AllowAnonymous]

    public class AuthController : Controller
    {
        // GET: Auth

        [HttpGet]
        public ActionResult Login(string returnUrl)
        {
        
            var model = new LoginModel
            {
                ReturnUrl = returnUrl
            };
 
            return View(model);
        }

        [HttpPost]
        public ActionResult Login(LoginModel model)
        {
            if (!ModelState.IsValid) //Checks if input fields have the correct format
            {
                return View(model); //Returns the view with the input values so that the user doesn't have to retype again
                
            }

            //Checks whether the input is the same as those literals. Note: Never ever do this! This is just to demo the validation while we're not yet doing any database interaction
            if (model.Email == "admin@admin.com" && model.Password == "123456")
            {
                var identity = new ClaimsIdentity(new[] {
                new Claim(ClaimTypes.Name, "el enix"),
                new Claim(ClaimTypes.Email, "xtian@email.com"),
                new Claim(ClaimTypes.Country, "Philippines")
                }, "ApplicationCookie");

                var ctx = Request.GetOwinContext();
                var authManager = ctx.Authentication;
                authManager.SignIn(identity);

                return Redirect(GetRedirectUrl(model.ReturnUrl));
            }

            ModelState.AddModelError("", "Invalid email or password");
            return View(model); //Should always be declared on the end of an action method


        }

        private string GetRedirectUrl(string returnUrl)
        {
            if (string.IsNullOrEmpty(returnUrl) || !Url.IsLocalUrl(returnUrl))
            {
                return Url.Action("index", "home");
            }
            return returnUrl;
        }

        public ActionResult Logout()
        {
            var ctx = Request.GetOwinContext();
            var authManager = ctx.Authentication;

            authManager.SignOut("ApplicationCookie");
            return RedirectToAction("Login", "Auth");
        }
    }
}