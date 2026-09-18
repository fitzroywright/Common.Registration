using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Common.Registration;
using Xunit;

public sealed class RegistrationTests
{
    [Fact]
    public void ConfigurationContractPolicy_RemovesValueBearingFields()
    {
        var contract = new JsonObject
        {
            ["applicationId"] = "Aegis.Hello",
            ["requirements"] = new JsonArray
            {
                new JsonObject
                {
                    ["id"] = "secret",
                    ["kind"] = "Secret",
                    ["value"] = "must-not-leak",
                    ["safeDisplayValue"] = "must-not-leak",
                    ["defaultValue"] = "must-not-leak"
                }
            }
        };

        JsonObject sanitized = ConfigurationContractPolicy.MetadataOnly(contract);
        JsonObject requirement = sanitized["requirements"]![0]!.AsObject();

        Assert.Null(requirement["value"]);
        Assert.Null(requirement["safeDisplayValue"]);
        Assert.Null(requirement["defaultValue"]);
        Assert.Equal(1, requirement["kind"]!.GetValue<int>());
    }

    [Fact]
    public void ControlPlaneClient_RejectsOrdinaryApplications()
    {
        Assert.Throws<ArgumentException>(() => new ControlPlaneRegistrationClient(
            new HttpClient(new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK))),
            new ControlPlaneRegistrationOptions(
                new Uri("https://operations.example/"),
                "Aegis.Hello",
                "Production",
                Path.Combine(Path.GetTempPath(), "hello.key"))));
    }

    [Fact]
    public async Task ControlPlaneClient_BootstrapsOnlyToProtectedCredentialFile()
    {
        string root = Path.Combine(Path.GetTempPath(), "aegis-control-plane-" + Guid.NewGuid().ToString("N"));
        string credentialFile = Path.Combine(root, "configuration.key");
        int calls = 0;

        try
        {
            var handler = new StubHandler(request =>
            {
                calls++;

                if (request.RequestUri!.AbsolutePath == "/api/registration/control-plane/auto")
                {
                    return Json(HttpStatusCode.OK, new
                    {
                        credential = "control-plane-secret"
                    });
                }

                Assert.Equal("/api/registration/contracts", request.RequestUri.AbsolutePath);
                Assert.Equal("Bearer", request.Headers.Authorization?.Scheme);
                Assert.Equal("control-plane-secret", request.Headers.Authorization?.Parameter);
                return Json(HttpStatusCode.OK, new { registered = true });
            });

            var client = new ControlPlaneRegistrationClient(
                new HttpClient(handler),
                new ControlPlaneRegistrationOptions(
                    new Uri("https://operations.example/"),
                    "Aegis.Configuration",
                    "Production",
                    credentialFile));

            ControlPlaneRegistrationStatus status = await client.RegisterAsync(
                new JsonObject
                {
                    ["applicationId"] = "Aegis.Configuration"
                });

            Assert.True(status.IsRegistered);
            Assert.Equal(2, calls);
            Assert.Equal("control-plane-secret", (await File.ReadAllTextAsync(credentialFile)).Trim());

            if (!OperatingSystem.IsWindows())
            {
                UnixFileMode mode = File.GetUnixFileMode(credentialFile);
                Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, mode);
            }
        }
        finally
        {
            if (Directory.Exists(root))
                Directory.Delete(root, true);
        }
    }

    [Fact]
    public async Task ControlPlaneClient_ReusesProtectedFileWithoutEnvironmentOrAppSettingLookup()
    {
        string root = Path.Combine(Path.GetTempPath(), "aegis-control-plane-" + Guid.NewGuid().ToString("N"));
        string credentialFile = Path.Combine(root, "operations.key");
        Directory.CreateDirectory(root);
        await File.WriteAllTextAsync(credentialFile, "persisted-secret\n");

        try
        {
            int calls = 0;
            var handler = new StubHandler(request =>
            {
                calls++;
                Assert.Equal("/api/registration/contracts", request.RequestUri!.AbsolutePath);
                Assert.Equal("persisted-secret", request.Headers.Authorization?.Parameter);
                return Json(HttpStatusCode.OK, new { registered = true });
            });

            var client = new ControlPlaneRegistrationClient(
                new HttpClient(handler),
                new ControlPlaneRegistrationOptions(
                    new Uri("https://operations.example/"),
                    "Aegis.Operations",
                    "Production",
                    credentialFile));

            ControlPlaneRegistrationStatus status = await client.RegisterAsync(
                new JsonObject
                {
                    ["applicationId"] = "Aegis.Operations"
                });

            Assert.True(status.IsRegistered);
            Assert.Equal(1, calls);
        }
        finally
        {
            if (Directory.Exists(root))
                Directory.Delete(root, true);
        }
    }

    private static HttpResponseMessage Json(HttpStatusCode code, object value)
        => new(code)
        {
            Content = JsonContent.Create(value)
        };

    private sealed class StubHandler(
        Func<HttpRequestMessage, HttpResponseMessage> responder) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
            => Task.FromResult(responder(request));
    }
}
