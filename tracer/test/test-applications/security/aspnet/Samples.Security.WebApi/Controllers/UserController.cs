using System.Collections.Generic;
using System.Web.Http;
using System.Web.Mvc;
using Datadog.Trace;

namespace Samples.Security.WebApi.Controllers
{
    public class UserController : ApiController
    {
        private readonly ITracer _tracer = TracerProviderBuilder.Create().Build().GetTracer();

        // GET api/user
        public string Get()
        {
            var userId = "user3";

            return Get(userId);
        }

        // GET api/user/<userid>
        public string Get(string id)
        {
            var userId = id ?? "user3";

            var userDetails = new UserDetails()
            {
                Id = userId,
            };
            _tracer.ActiveScope?.Span.SetUser(userDetails);

            return userId;
        }
    }
}
