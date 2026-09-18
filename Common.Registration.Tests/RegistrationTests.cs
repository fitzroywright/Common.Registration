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
    public async Task ApplicationRegistration_PendingApprovalThenCredentialIsStoredAndUsed()
    {
        int contractCalls = 0;
        string credential = "durable-credential";
        var handler = new StubHandler(async (request, cancellationToken) =>
        {
            if (request.RequestUri!.AbsolutePath.EndsWith("/api/registration/pending"))
                return Json(HttpStatusCode.OK, """{"registrationId":"reg1","pin":"123456"}""");
            if (request.RequestUri.AbsolutePath.EndsWith("/credential"))
                return Json(HttpStatusCode.OK, """{"credential":"durable-credential"}""");
            if (request.RequestUri.AbsolutePath.EndsWith("/api/registration/contracts"))
            {
                contractCalls++;
                Assert.Equal("Bearer", request.Headers.Authorization?.Scheme);
                Assert.Equal(credential, request.Headers.Authorization?.Parameter);
                return Json(HttpStatusCode.OK, """{"registered":true}""");
            }
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });
        var store = new MemoryCredentialStore();
        var client = new ApplicationRegistrationClient(
            new HttpClient(handler),
            new ApplicationRegistrationOptions(new Uri("http://operations/"), "Aegis.Cafeteria.Services", "Cafeteria Services", "kratos"),
            store);

        ApplicationRegistrationStatus result = await client.PublishContractAsync(ValidContract());

        Assert.True(result.IsRegistered);
        Assert.Equal(credential, store.Value);
        Assert.Equal(1, contractCalls);
    }

    [Fact]
    public async Task ApplicationRegistration_InvalidStoredCredentialIsDiscardedAndReturnsPending()
    {
        var store = new MemoryCredentialStore { Value = "old" };
        var handler = new StubHandler((request, _) =>
        {
            if (request.RequestUri!.AbsolutePath.EndsWith("/api/registration/contracts"))
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Unauthorized));
            if (request.RequestUri.AbsolutePath.EndsWith("/api/registration/pending"))
                return Task.FromResult(Json(HttpStatusCode.OK, """{"registrationId":"reg2","pin":"654321"}"""));
            if (request.RequestUri.AbsolutePath.EndsWith("/credential"))
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Accepted));
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        });
        var client = new ApplicationRegistrationClient(
            new HttpClient(handler),
            new ApplicationRegistrationOptions(new Uri("http://operations/"), "Aegis.Cafeteria.Services", "Cafeteria Services", "kratos"),
            store);

        ApplicationRegistrationStatus result = await client.PublishContractAsync(ValidContract());

        Assert.Equal(ApplicationRegistrationState.Pending, result.State);
        Assert.Equal("reg2", result.RegistrationId);
        Assert.Equal("654321", result.Pin);
        Assert.Null(store.Value);
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

    private static HttpResponseMessage Json(HttpStatusCode status, string json) => new(status)
    {
        Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json")
    };

    private sealed class MemoryCredentialStore : IRegistrationCredentialStore
    {
        public string? Value { get; set; }
        public Task<string?> LoadAsync(CancellationToken cancellationToken = default) => Task.FromResult(Value);
        public Task SaveAsync(string credential, CancellationToken cancellationToken = default) { Value = credential; return Task.CompletedTask; }
        public Task DeleteAsync(CancellationToken cancellationToken = default) { Value = null; return Task.CompletedTask; }
    }

    private sealed class StubHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> response) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            response(request, cancellationToken);
    }
}
