using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Common.Diagnostics;
using Common.Registration;
using Xunit;

public sealed class RuntimeSessionPropagationTests
{
    [Fact]
    public async Task Authentication_contracts_and_lifecycle_share_session_across_recreated_clients()
    {
        string root = Path.Combine(Path.GetTempPath(), "runtime-session-" + Guid.NewGuid().ToString("N"));
        string path = Path.Combine(root, "identity.json");
        try
        {
            var store = new FileRegistrationIdentityStore(path);
            var identity = await store.LoadOrCreateAsync("Aegis.Cafeteria.Services", "kratos");
            await store.SaveAsync(identity with { RegistrationId = "registered", Credential = "test-credential" });
            var seen = new List<string>();
            using var handler = new SessionCheckingHandler(request =>
            {
                Assert.Equal(ApplicationRuntimeSession.Id,
                    Assert.Single(request.Headers.GetValues(ApplicationRuntimeSession.HeaderName)));
                seen.Add(request.RequestUri!.AbsolutePath);
                return request.RequestUri.AbsolutePath == "/api/registration/authenticate"
                    ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(
                        """{"registrationId":"registered","state":"Registered"}""",
                        Encoding.UTF8, "application/json") }
                    : new HttpResponseMessage(HttpStatusCode.OK);
            });
            using var lifecycleHttp = new HttpClient(handler, disposeHandler: false);
            var sink = new HttpLifecycleEventSink(lifecycleHttp,
                new HttpLifecycleEventSinkOptions(new Uri("https://configuration.example/api/operations/activity/observe")));
            var options = new RegistrationLifecycleOptions(
                new Uri("https://configuration.example/"),
                "Aegis.Cafeteria.Services", "kratos", path);
            for (int i = 0; i < 2; i++)
            {
                using var http = new HttpClient(handler, disposeHandler: false);
                var client = new RegistrationLifecycleClient(http, options, store, lifecycleEventSink: sink);
                Assert.Equal(RegistrationLifecycleState.Registered, (await client.StepAsync()).State);
                Assert.Equal(HttpStatusCode.OK, await client.PublishConfigurationContractAsync(new JsonObject
                {
                    ["applicationId"] = "Aegis.Cafeteria.Services",
                    ["instanceId"] = "kratos",
                    ["requirements"] = new JsonArray()
                }));
            }
            Assert.Equal(2, seen.Count(x => x == "/api/registration/authenticate"));
            Assert.Equal(2, seen.Count(x => x == "/api/contracts/register"));
            Assert.Contains("/api/operations/activity/observe", seen);
            // Session identity belongs to the process, not the durable installation file.
            if (!OperatingSystem.IsWindows())
                Assert.DoesNotContain(ApplicationRuntimeSession.Id, await File.ReadAllTextAsync(path));
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }

    private sealed class SessionCheckingHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(respond(request));
    }
}
