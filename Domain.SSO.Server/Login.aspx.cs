using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace Domain.SSO.Server
{
    public partial class Login : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {

        }

        protected void btnLogin_Click(object sender, EventArgs e)
        {
            using (dbDataContext db=new dbDataContext())
            {
                string userName = this.txtUserName.Text.Trim();
                string password = this.txtPassword.Text.Trim();
                if (string.IsNullOrEmpty(userName))
                {
                    this.lblMessage.Text = "用户名不能为空";
                    return;
                }

                if (string.IsNullOrEmpty(password))
                {
                    this.lblMessage.Text = "密码不能为空";
                    return;
                }
                var entry = db.p_User.FirstOrDefault(x=>x.UserName==userName&&x.Pwd== MD5String(password));
                if (entry != null)
                {
                    if (Domain.Security.SmartAuthenticate.AuthenticateUser(userName, password, true))
                    {
                        this.lblMessage.Text = "登录成功";
                        string returnUrl = Request["returnUrl"];
                        if (string.IsNullOrEmpty(returnUrl))
                            Response.Redirect("default.aspx");
                        else
                            Response.Redirect(returnUrl);
                    }
                    else
                    {
                        this.lblMessage.Text = "登录失败，请重试";
                        return;
                    }
                }
                else
                {
                    this.lblMessage.Text = "用户名或密码错误";
                    return;
                }
               
            }
        }
        /// <summary>
        /// MD5加密
        /// </summary>
        /// <param name="sInputString">需要加密的字符串</param>
        /// <returns>加密后字符串</returns>
        public static string MD5String(string sInputString)
        {
            MD5 md5 = new MD5CryptoServiceProvider();
            byte[] fromData = System.Text.Encoding.Unicode.GetBytes(sInputString);
            byte[] targetData = md5.ComputeHash(fromData);
            string byte2String = null;

            for (int i = 0; i < targetData.Length; i++)
            {
                byte2String += targetData[i].ToString("x");
            }

            return byte2String;
        }
    }
}