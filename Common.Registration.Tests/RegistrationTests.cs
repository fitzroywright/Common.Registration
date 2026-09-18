using System.Net;
using System.Text.Json.Nodes;
using Common.Registration;
using Xunit;

public sealed class RegistrationTests
{
    [Fact]
    public async Task CredentialResolver_PrefersEnvironment()
    {
        bool secretProviderCalled = false;
        RegistrationCredentialResolution result = await RegistrationCredentialResolver.ResolveAsync(
            () => " environment-key ",
            _ => { secretProviderCalled = true; return Task.FromResult<string?>("secret-key"); },
            () => "app-key");

        Assert.True(result.Succeeded);
        Assert.Equal("environment-key", result.Credential);
        Assert.Equal(RegistrationCredentialSource.Environment, result.Source);
        Assert.False(secretProviderCalled);
    }

    [Fact]
    public async Task CredentialResolver_UsesSecretProviderWhenEnvironmentMissing()
    {
        RegistrationCredentialResolution result = await RegistrationCredentialResolver.ResolveAsync(
            () => null,
            _ => Task.FromResult<string?>("secret-key"),
            () => "app-key");

        Assert.Equal("secret-key", result.Credential);
        Assert.Equal(RegistrationCredentialSource.SecretProvider, result.Source);
    }

    [Fact]
    public async Task CredentialResolver_FallsBackToAppSettingWhenSecretProviderFails()
    {
        RegistrationCredentialResolution result = await RegistrationCredentialResolver.ResolveAsync(
            () => null,
            _ => Task.FromException<string?>(new InvalidOperationException("provider unavailable")),
            () => "app-key");

        Assert.Equal("app-key", result.Credential);
        Assert.Equal(RegistrationCredentialSource.AppSetting, result.Source);
        Assert.Contains("provider unavailable", result.SecretProviderError, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task CredentialResolver_ReportsMissingWithoutInventingSuccess()
    {
        RegistrationCredentialResolution result = await RegistrationCredentialResolver.ResolveAsync(
            () => " ",
            _ => Task.FromResult<string?>(null),
            () => null);

        Assert.False(result.Succeeded);
        Assert.Null(result.Credential);
        Assert.Equal(RegistrationCredentialSource.Missing, result.Source);
    }

    [Fact]
    public void CredentialResolver_UsesStandardSecretName()
    {
        Assert.Equal(
            "configuration/registration/Aegis.Cafeteria.Services",
            RegistrationCredentialResolver.SecretNameFor("Aegis.Cafeteria.Services"));
    }


    [Fact]
    public async Task ApplicationRegistration_UsesDesignatedEnvironmentVariable()
    {
        string? authorization = null;
        var handler = new StubHandler((request, _) =>
        {
            authorization = request.Headers.Authorization?.Parameter;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        });
        var client = new ApplicationRegistrationClient(
            new HttpClient(handler),
            new ApplicationRegistrationOptions(
                new Uri("http://operations/"),
                "Aegis.Cafeteria.Services",
                "kratos"),
            name => name == RegistrationCredentialResolver.EnvironmentVariableName ? "registration-key" : null);

        ApplicationRegistrationStatus result = await client.RegisterAsync(ValidContract());

        Assert.True(result.IsRegistered);
        Assert.Equal("registration-key", authorization);
    }

    [Fact]
    public async Task ApplicationRegistration_DoesNotCreatePendingRegistrationWhenEnvironmentVariableIsMissing()
    {
        bool called = false;
        var handler = new StubHandler((_, _) =>
        {
            called = true;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        });
        var client = new ApplicationRegistrationClient(
            new HttpClient(handler),
            new ApplicationRegistrationOptions(
                new Uri("http://operations/"),
                "Aegis.Cafeteria.Services",
                "kratos"),
            _ => null);

        ApplicationRegistrationStatus result = await client.RegisterAsync(ValidContract());

        Assert.Equal(ApplicationRegistrationState.MissingCredential, result.State);
        Assert.False(called);
    }

    [Fact]
    public async Task ApplicationRegistration_RevokedCredentialRequiresBootstrapToBeRepeated()
    {
        var client = new ApplicationRegistrationClient(
            new HttpClient(new StubHandler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.Gone)))),
            new ApplicationRegistrationOptions(
                new Uri("http://operations/"),
                "Aegis.Cafeteria.Services",
                "kratos"),
            _ => "revoked-key");

        ApplicationRegistrationStatus result = await client.RegisterAsync(ValidContract());

        Assert.Equal(ApplicationRegistrationState.Revoked, result.State);
        Assert.Contains("new pending registration", result.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task NonSuccessHttpResponse_IsNeverReportedAsSuccess()
    {
        var client = new HttpClient(new StubHandler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable))));
        var registrar = new ConfigurationRegistrar(client, new RegistrationOptions(new Uri("http://configuration/")));
        RegistrationResult result = await registrar.RegisterContractAsync(ValidContract());
        Assert.False(result.Succeeded);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, result.StatusCode);
    }

    [Fact]
    public async Task SuccessfulHttpResponse_IsReportedAsSuccess()
    {
        var client = new HttpClient(new StubHandler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK))));
        var registrar = new ConfigurationRegistrar(client, new RegistrationOptions(new Uri("http://configuration/")));
        RegistrationResult result = await registrar.RegisterContractAsync(ValidContract());
        Assert.True(result.Succeeded);
        Assert.Equal(HttpStatusCode.OK, result.StatusCode);
    }

    [Fact]
    public void MetadataOnly_RemovesValues_AndNormalizesRequirementKinds()
    {
        JsonObject contract = new()
        {
            ["value"] = "top-secret",
            ["requirements"] = new JsonArray
            {
                new JsonObject
                {
                    ["id"] = "database",
                    ["kind"] = "ExternalService",
                    ["isConfigured"] = true,
                    ["defaultValue"] = "fallback",
                    ["details"] = new JsonObject { ["resolvedValue"] = "resolved-secret" }
                }
            }
        };

        JsonObject sanitized = ConfigurationContractPolicy.MetadataOnly(contract);
        JsonObject requirement = sanitized["requirements"]!.AsArray()[0]!.AsObject();
        string json = sanitized.ToJsonString();

        Assert.DoesNotContain("top-secret", json, StringComparison.Ordinal);
        Assert.DoesNotContain("fallback", json, StringComparison.Ordinal);
        Assert.DoesNotContain("resolved-secret", json, StringComparison.Ordinal);
        Assert.True(requirement["isConfigured"]!.GetValue<bool>());
        Assert.Equal(2, requirement["kind"]!.GetValue<int>());
        Assert.Equal("top-secret", contract["value"]!.GetValue<string>());
        Assert.Equal("ExternalService", contract["requirements"]!.AsArray()[0]!["kind"]!.GetValue<string>());
    }

    [Fact]
    public async Task RegisterContractAsync_SendsSanitizedPayload()
    {
        string? body = null;
        var client = new HttpClient(new StubHandler(async (request, cancellationToken) =>
        {
            body = await request.Content!.ReadAsStringAsync(cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.OK);
        }));
        var registrar = new ConfigurationRegistrar(client, new RegistrationOptions(new Uri("http://configuration/")));
        JsonObject contract = ValidContract();
        contract["requirements"]!.AsArray()[0]!["safeDisplayValue"] = "must-not-leave-process";

        RegistrationResult result = await registrar.RegisterContractAsync(contract);

        Assert.True(result.Succeeded);
        Assert.NotNull(body);
        Assert.Contains("\"kind\":1", body, StringComparison.Ordinal);
        Assert.Contains("isConfigured", body, StringComparison.Ordinal);
        Assert.DoesNotContain("must-not-leave-process", body, StringComparison.Ordinal);
        Assert.DoesNotContain("safeDisplayValue", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task TransportFailure_IsNeverReportedAsSuccess()
    {
        var client = new HttpClient(new StubHandler((_, _) => Task.FromException<HttpResponseMessage>(new HttpRequestException("offline"))));
        var registrar = new ConfigurationRegistrar(client, new RegistrationOptions(new Uri("http://configuration/")));

        RegistrationResult result = await registrar.RegisterContractAsync(ValidContract());

        Assert.False(result.Succeeded);
        Assert.Null(result.StatusCode);
        Assert.Contains("offline", result.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Timeout_IsNeverReportedAsSuccess()
    {
        var client = new HttpClient(new StubHandler((_, _) => Task.FromException<HttpResponseMessage>(new TaskCanceledException("timeout"))));
        var registrar = new ConfigurationRegistrar(client, new RegistrationOptions(new Uri("http://configuration/")));

        RegistrationResult result = await registrar.RegisterContractAsync(ValidContract());

        Assert.False(result.Succeeded);
        Assert.Null(result.StatusCode);
        Assert.Contains("timed out", result.Error, StringComparison.OrdinalIgnoreCase);
    }

    private static JsonObject ValidContract() => new()
    {
        ["applicationId"] = "Test",
        ["displayName"] = "Test",
        ["version"] = "1.0.0",
        ["requirements"] = new JsonArray
        {
            new JsonObject
            {
                ["id"] = "token",
                ["displayName"] = "Token",
                ["kind"] = "Secret",
                ["required"] = true,
                ["purpose"] = "Test registration contract",
                ["configurationKey"] = "Test:Token",
                ["isConfigured"] = true
            }
        }
    };

    private sealed class StubHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> response) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            response(request, cancellationToken);
    }
}
