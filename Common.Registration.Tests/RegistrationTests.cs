using System.Net;
using System.Text.Json.Nodes;
using Common.Registration;
using Xunit;

public sealed class RegistrationTests
{
    [Fact]
    public async Task NonSuccessHttpResponse_IsNeverReportedAsSuccess()
    {
        var client = new HttpClient(new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)));
        var registrar = new ConfigurationRegistrar(client, new RegistrationOptions(new Uri("http://configuration/")));
        var result = await registrar.RegisterAsync(ComponentIdentity.Detect("Test", "Web", Array.Empty<ConfigurationRequirement>()));
        Assert.False(result.Succeeded);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, result.StatusCode);
    }

    [Fact]
    public async Task SuccessfulHttpResponse_IsReportedAsSuccess()
    {
        var client = new HttpClient(new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)));
        var registrar = new ConfigurationRegistrar(client, new RegistrationOptions(new Uri("http://configuration/")));
        var result = await registrar.RegisterAsync(ComponentIdentity.Detect("Test", "Web", Array.Empty<ConfigurationRequirement>()));
        Assert.True(result.Succeeded);
        Assert.Equal(HttpStatusCode.OK, result.StatusCode);
    }

    [Fact]
    public void Identity_UsesDeclaredNeedsWithoutInventingValues()
    {
        var needs = new[] { new ConfigurationRequirement("Database:ConnectionString", true, "Database connection", true) };
        var identity = ComponentIdentity.Detect("Test", "Worker", needs, "Test");
        Assert.Single(identity.ConfigurationNeeds);
        Assert.Equal("Database:ConnectionString", identity.ConfigurationNeeds[0].Key);
        Assert.True(identity.ConfigurationNeeds[0].Secret);
    }

    [Fact]
    public void MetadataOnly_RemovesValueBearingFieldsRecursively()
    {
        JsonObject contract = new()
        {
            ["value"] = "top-secret",
            ["requirements"] = new JsonArray
            {
                new JsonObject
                {
                    ["key"] = "Database:ConnectionString",
                    ["isConfigured"] = true,
                    ["defaultValue"] = "fallback",
                    ["details"] = new JsonObject { ["resolvedValue"] = "resolved-secret" }
                }
            }
        };

        JsonObject sanitized = ConfigurationContractPolicy.MetadataOnly(contract);
        string json = sanitized.ToJsonString();

        Assert.DoesNotContain("top-secret", json, StringComparison.Ordinal);
        Assert.DoesNotContain("fallback", json, StringComparison.Ordinal);
        Assert.DoesNotContain("resolved-secret", json, StringComparison.Ordinal);
        Assert.Contains("Database:ConnectionString", json, StringComparison.Ordinal);
        Assert.Contains("isConfigured", json, StringComparison.Ordinal);
    }

    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> response) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(response(request));
    }
}
