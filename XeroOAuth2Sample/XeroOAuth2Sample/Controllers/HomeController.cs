using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Formatting;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Xero.NetStandard.OAuth2.Client;
using WorkflowMaxOAuth2Sample.Example;
using WorkflowMaxOAuth2Sample.Extensions;
using WorkflowMaxOAuth2Sample.Models;
using WorkflowMaxOAuth2Sample.Models.ClientApi;

namespace WorkflowMaxOAuth2Sample.Controllers
{
    public class HomeController : Controller
    {
        private readonly MemoryTokenStore _tokenStore;
        private readonly IXeroClient _xeroClient;
        private readonly IHttpClientFactory _httpClientFactory;

        public HomeController(MemoryTokenStore tokenStore, IXeroClient xeroClient, IHttpClientFactory httpClientFactory)
        {
            _tokenStore = tokenStore;
            _xeroClient = xeroClient;
            _httpClientFactory = httpClientFactory;
        }

        [HttpGet]
        public IActionResult Index()
        {
            if (User.Identity.IsAuthenticated)
            {
                return RedirectToAction(nameof(TenantClientLists));
            }

            return View();
        }

        [HttpGet]
        [Authorize]
        public async Task<IActionResult> TenantClientLists()
        {
            var token = await _tokenStore.GetAccessTokenAsync(User.XeroUserId());

            var connections = await _xeroClient.GetConnectionsAsync(token);

            if (!connections.Any())
            {
                return RedirectToAction(nameof(NoTenants));
            }

            var data = new List<(Guid tenantId, ClientListResponse clients)>();

            var client = _httpClientFactory.CreateClient("WorkflowMax");
            client.SetBearerToken(token.AccessToken);

            foreach (var connection in connections)
            {
                var request = new HttpRequestMessage
                {
                    RequestUri = new Uri("client.api/list", UriKind.Relative),
                    Headers = { { "Xero-Tenant-Id", connection.TenantId.ToString() } }
                };

                var response = await client.SendAsync(request);

                response.EnsureSuccessStatusCode();

                var clients = await response.Content.ReadAsAsync<ClientListResponse>(new[]
                {
                    new XmlMediaTypeFormatter
                    {
                        UseXmlSerializer = true
                    }
                });

                data.Add((connection.TenantId, clients));
            }

            var model = new TenantClientListsModel
            {
                LoggedInUser = $"{User.FindFirstValue(ClaimTypes.GivenName)} {User.FindFirstValue(ClaimTypes.Surname)}",
                TenantClients = data
            };

            return View(model);
        }

        [HttpGet]
        [Authorize]
        public IActionResult NoTenants()
        {
            return View();
        }

        [HttpGet]
        [Authorize(AuthenticationSchemes = "XeroSignIn")]
        public IActionResult SignIn()
        {
            return RedirectToAction(nameof(TenantClientLists));
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
