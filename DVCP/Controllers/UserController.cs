using DVCP.Models;
using DVCP.ViewModel;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;

namespace DVCP.Controllers
{
    public class UserController : Controller
    {
        UnitOfWork UnitOfWork = new UnitOfWork(new DVCPContext());
        // GET: User
        public ActionResult Login()
        {
            if (Request.IsAuthenticated)
            {
                return RedirectToAction("Index", "Home");
            }
            return View();
        }
        public ActionResult Logout()
        {
            FormsAuthentication.SignOut();
            return RedirectToAction("Index", "Home");
        }
        [Authorize(Roles = "admin")]
        public ActionResult UserManager()
        {
           List<User> lstUser = UnitOfWork.userRepository.AllUsers().ToList();
           return View(lstUser);
        }
        public void setCookie(string username, bool rememberme = false, string role = "normal")
        {
            var authTicket = new FormsAuthenticationTicket(
                               1,
                               username,
                               DateTime.Now,
                               DateTime.Now.AddMinutes(120),
                               rememberme,
                               role
                               );

            string encryptedTicket = FormsAuthentication.Encrypt(authTicket);

            var authCookie = new HttpCookie(FormsAuthentication.FormsCookieName, encryptedTicket);
            Response.Cookies.Add(authCookie);
        }

        [HttpPost]
        public ActionResult Login(LoginViewModel model, string ReturnUrl)
        {

            if (ModelState.IsValid)
            {
                User user = UnitOfWork.userRepository.FindByUsername(model.Username);
                if (user != null)
                {
                    // Kiểm tra xem tài khoản có bị khóa không
                    if (user.LockoutEndTime.HasValue && user.LockoutEndTime.Value > DateTime.Now)
                    {
                        ViewBag.Error = "Tài khoản đã bị khóa. Vui lòng thử lại sau 1 phút.";
                        return View();
                    }

                    // Kiểm tra mật khẩu
                    if (user.password == CommonData.CommonFunction.CalculateMD5Hash(model.Password) && user.status)
                    {
                        // Đăng nhập thành công, reset số lần đăng nhập thất bại
                        user.FailedLoginAttempts = 0;
                        user.LockoutEndTime = null;
                        UnitOfWork.Commit();

                        setCookie(user.username, model.RememberMe, user.userrole);

                        if (!string.IsNullOrEmpty(ReturnUrl))
                            return Redirect(ReturnUrl);
                        return RedirectToAction("Index", "Home");
                    }
                    else
                    {
                        // Tăng số lần đăng nhập thất bại
                        user.FailedLoginAttempts++;

                        // Kiểm tra nếu số lần đăng nhập thất bại >= 5
                        if (user.FailedLoginAttempts >= 5)
                        {
                            user.LockoutEndTime = DateTime.Now.AddMinutes(1); // Khóa tài khoản trong 1 phút
                            ViewBag.Error = "Bạn đã nhập sai mật khẩu quá nhiều lần. Tài khoản đã bị tạm khóa trong 1 phút.";
                        }
                        else
                        {
                            ViewBag.Error = "Mật khẩu không chính xác !";
                        }

                        UnitOfWork.Commit();
                        return View();
                    }

                }
            }         
            ViewBag.Error = "Tài khoản không tồn tại";
            return View();
        }
        [Authorize(Roles="admin")]
        public ActionResult createUser()
        {
            return View();
        }

        public bool ContainsSpecialCharacters(string input)
        {
            return System.Text.RegularExpressions.Regex.IsMatch(input, @"[^a-zA-Z0-9]");
        }

        [HttpPost]
        public ActionResult createUser(userListViewModel model)
        {
            if(ModelState.IsValid)
            {
                // Kiểm tra nếu username chứa ký tự đặc biệt
                if (ContainsSpecialCharacters(model.username))
                {
                    ViewBag.anno = "Username không được chứa kí tự đặc biệt";
                    return View();
                }

                User user = UnitOfWork.userRepository.FindByUsername(model.username);
                if(user == null)
                {
                    User nuser = new User
                    {
                        username = model.username,
                        fullname = model.fullname,
                        status = true,
                        userrole = "editor",
                        password = CommonData.CommonFunction.CalculateMD5Hash(model.password)
                    };
                    UnitOfWork.userRepository.Add(nuser);
                    UnitOfWork.Commit();
                    return RedirectToAction("UserManager");
                }
                else
                {
                    ViewBag.anno = "Tên người dùng này đã tồn tại";
                    return View();
                }
            }
            return View();
        }
        [Authorize]
        public ActionResult ChangePass()
        {
            return View();
        }
        [HttpPost]
        public ActionResult ChangePass(changepassViewModel model)
        {
            if(ModelState.IsValid)
            {
                if(model.oldpassword == model.password)
                {
                    ViewBag.anno = "Mật khẩu mới không được trùng mật khẩu cũ !";
                    return View();
                }
                else
                {
                    User user = UnitOfWork.userRepository.FindByUsername(User.Identity.Name);
                    if(user != null)
                    {
                        user.password = CommonData.CommonFunction.CalculateMD5Hash(model.password);
                        UnitOfWork.Commit();
                        return RedirectToAction("Logout");
                    }
                }
            }
            return View();
        }
        [Authorize(Roles="admin")]
        public JsonResult changeStatus(int userid,bool state = true)
        {
            string prefix = state ? "Đã bỏ cấm" : "Đã cấm";
            User u = UnitOfWork.userRepository.FindByID(userid);
            if(u.username != "admin")
            {
                u.status = state;
                UnitOfWork.Commit();
                return Json(new { Message = prefix + " \"" + u.username + "\"" }, JsonRequestBehavior.AllowGet);
            }
            return Json(new { Message = "Không được cấm admin" }, JsonRequestBehavior.AllowGet);
        }
    }
}