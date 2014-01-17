using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.DirectoryServices.AccountManagement;

namespace ActiveDirectoryLogin.Filters
{
    public class AuthorizeADAttribute : AuthorizeAttribute
    {
        public string Groups { get; set; }

        protected override bool AuthorizeCore(HttpContextBase httpContext)
        {
            if (base.AuthorizeCore(httpContext))
            {
                //if (String.IsNullOrEmpty(Groups))
                    return true;

                var groups = Groups.Split(',').ToList();

                var context = new PrincipalContext(ContextType.Domain, "YourDomainHere");

                var userPrincipal = UserPrincipal.FindByIdentity(
                                       context,
                                       IdentityType.SamAccountName,
                                       httpContext.User.Identity.Name);

                foreach (var group in groups)
                    if (userPrincipal.IsMemberOf(context,
                         IdentityType.Name,
                         group))
                        return true;
            }
            return false;
        }

        protected override void HandleUnauthorizedRequest(AuthorizationContext filterContext)
        {
            if (filterContext.HttpContext.User.Identity.IsAuthenticated)
            {
                var result = new ViewResult();
                result.ViewName = "NotAuthorized";
                result.MasterName = "_Layout";
                filterContext.Result = result;
            }
            else
                base.HandleUnauthorizedRequest(filterContext);
        }
    }
}
