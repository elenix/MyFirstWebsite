using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using MyFirstWebsite.Models;
using MyFirstWebsite.Controllers.CustomLibraries;
using System.Security.Claims;

namespace MyFirstWebsite.Controllers
{
    [AllowAnonymous]

    public class AuthController : Controller
    {
        // GET: Auth

        [HttpGet]
        public ActionResult Index()
        {
            var db = new MainDbContext();
            return View(db.Lists.Where(x => x.Public == "YES").ToList());
        }

        [HttpGet]
        public ActionResult Login()
        {

            var model = new Users
            {

            };

            return View();
        }

        [HttpPost]
        public ActionResult Login(Users model)
        {
            if (!ModelState.IsValid) //Checks if input fields have the correct format
            {
                return View(model); //Returns the view with the input values so that the user doesn't have to retype again

            }
            using (var db = new MainDbContext())
            {
                var emailCheck = db.Users.FirstOrDefault(u => u.Email == model.Email);
                var getPassword = db.Users.Where(u => u.Email == model.Email).Select(u => u.Password);
                var materializePassword = getPassword.ToList();
                var password = materializePassword[0];
                var decryptedPassword = CustomDecrypt.Decrypt(password);

                if (model.Email != null && model.Password == decryptedPassword)
                {
                    var getName = db.Users.Where(u => u.Email == model.Email).Select(u => u.Name);
                    var materializeName = getName.ToList();
                    var name = materializeName[0];

                    var getCountry = db.Users.Where(u => u.Email == model.Email).Select(u => u.Country);
                    var materializeCountry = getCountry.ToList();
                    var country = materializeCountry[0];

                    var getEmail = db.Users.Where(u => u.Email == model.Email).Select(u => u.Email);
                    var materializeEmail = getEmail.ToList();
                    var email = materializeEmail[0];

                    var identity = new ClaimsIdentity(new[] {
                    new Claim(ClaimTypes.Name, name),
                    new Claim(ClaimTypes.Email, email),
                    new Claim(ClaimTypes.Country, country)
                 }, "ApplicationCookie");

                    var ctx = Request.GetOwinContext();
                    var authManager = ctx.Authentication;
                    authManager.SignIn(identity);

                    return RedirectToAction("Index", "Home");
                }
            }

            ModelState.AddModelError("", "Invalid email or password");
            return View(model); //Should always be declared on the end of an action method



        }

        public ActionResult Logout()
        {
            var ctx = Request.GetOwinContext();
            var authManager = ctx.Authentication;

            authManager.SignOut("ApplicationCookie");
            return RedirectToAction("Login", "Auth");
        }

        public ActionResult Registration()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Registration(Users model)
        {
            if (ModelState.IsValid)
            {
                using (var db = new MainDbContext())
                {
                    var encryptedPassword = CustomEnrypt.Encrypt(model.Password);
                    var user = db.Users.Create();
                    user.Email = model.Email;
                    user.Password = encryptedPassword;
                    user.Country = model.Country;
                    user.Name = model.Name;
                    db.Users.Add(user);
                    db.SaveChanges();
                }
            }
            else
            {
                ModelState.AddModelError("", "One or more fields have been");
            }
            return View();
        }
    }
}