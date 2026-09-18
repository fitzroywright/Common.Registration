using System.Net;
using System.Text;
using System.Text.Json;
using Common.Registration;
using Xunit;

public sealed class LifecycleRegistrationTests
{
    [Fact]
    public async Task IdentityStore_CreatesStableInstallationId()
    {
        string root = Path.Combine(Path.GetTempPath(), "aegis-registration-" + Guid.NewGuid().ToString("N"));
        string path = Path.Combine(root, "identity.json");
        try
        {
            var store = new FileRegistrationIdentityStore(path);
            RegistrationIdentityDocument first = await store.LoadOrCreateAsync("Aegis.Hello", "Production");
            RegistrationIdentityDocument second = await store.LoadOrCreateAsync("Aegis.Hello", "Production");

            Assert.Equal(first.InstallationId, second.InstallationId);
            Assert.Equal(64, first.InstallationId.Length);
            Assert.True(File.Exists(path));

            if (!OperatingSystem.IsWindows())
            {
                UnixFileMode mode = File.GetUnixFileMode(path);
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
    public async Task FirstStart_CreatesPendingAndPersistsClaimWithoutPreSharedCredential()
    {
        string root = Path.Combine(Path.GetTempPath(), "aegis-registration-" + Guid.NewGuid().ToString("N"));
        string path = Path.Combine(root, "identity.json");
        try
        {
            var handler = new RecordingHandler((request, _) =>
            {
                Assert.Equal("/api/registration/request", request.RequestUri!.AbsolutePath);
                Assert.Null(request.Headers.Authorization);
                return Json(HttpStatusCode.OK, new
                {
                    registrationId = "reg-1",
                    claimToken = "claim-secret",
                    state = "Pending"
                });
            });

            var client = new RegistrationLifecycleClient(
                new HttpClient(handler),
                new RegistrationLifecycleOptions(
                    new Uri("https://configuration.example/"),
                    "Aegis.Hello",
                    "Production",
                    path));

            RegistrationLifecycleStatus status = await client.StepAsync();

            Assert.Equal(RegistrationLifecycleState.Pending, status.State);
            string persisted = await File.ReadAllTextAsync(path);
            Assert.Contains("reg-1", persisted);
            Assert.Contains("claim-secret", persisted);
            Assert.DoesNotContain("AEGIS_REGISTRATION_KEY", persisted);
        }
        finally
        {
            if (Directory.Exists(root))
                Directory.Delete(root, true);
        }
    }

    [Fact]
    public async Task ApprovedClaim_IsConsumedLocallyAndNextStartAuthenticates()
    {
        string root = Path.Combine(Path.GetTempPath(), "aegis-registration-" + Guid.NewGuid().ToString("N"));
        string path = Path.Combine(root, "identity.json");
        try
        {
            var store = new FileRegistrationIdentityStore(path);
            RegistrationIdentityDocument identity =
                await store.LoadOrCreateAsync("Aegis.Hello", "Production");
            await store.SaveAsync(identity with
            {
                RegistrationId = "reg-1",
                ClaimToken = "claim-secret"
            });

            int calls = 0;
            var handler = new RecordingHandler((request, _) =>
            {
                calls++;
                if (calls == 1)
                {
                    Assert.Equal("/api/registration/reg-1/claim", request.RequestUri!.AbsolutePath);
                    return Json(HttpStatusCode.OK, new
                    {
                        registrationId = "reg-1",
                        credential = "permanent-secret",
                        state = "Registered"
                    });
                }

                Assert.Equal("/api/registration/authenticate", request.RequestUri!.AbsolutePath);
                Assert.Equal("Bearer", request.Headers.Authorization?.Scheme);
                Assert.Equal("permanent-secret", request.Headers.Authorization?.Parameter);
                return Json(HttpStatusCode.OK, new
                {
                    registrationId = "reg-1",
                    state = "Registered"
                });
            });

            var client = new RegistrationLifecycleClient(
                new HttpClient(handler),
                new RegistrationLifecycleOptions(
                    new Uri("https://configuration.example/"),
                    "Aegis.Hello",
                    "Production",
                    path),
                store);

            RegistrationLifecycleStatus claimed = await client.StepAsync();
            RegistrationLifecycleStatus authenticated = await client.StepAsync();

            Assert.Equal(RegistrationLifecycleState.Registered, claimed.State);
            Assert.Equal(RegistrationLifecycleState.Registered, authenticated.State);

            string persisted = await File.ReadAllTextAsync(path);
            Assert.DoesNotContain("claim-secret", persisted);
            Assert.Contains("permanent-secret", persisted);
        }
        finally
        {
            if (Directory.Exists(root))
                Directory.Delete(root, true);
        }
    }


    [Fact]
    public async Task MissingCredential_WithEstablishedRegistration_RequestsRecoveryNotNewRegistration()
    {
        string root = Path.Combine(Path.GetTempPath(), "aegis-registration-" + Guid.NewGuid().ToString("N"));
        string path = Path.Combine(root, "identity.json");
        try
        {
            var store = new FileRegistrationIdentityStore(path);
            RegistrationIdentityDocument identity =
                await store.LoadOrCreateAsync("Aegis.Hello", "Production");
            await store.SaveAsync(identity with
            {
                RegistrationId = "reg-established",
                Credential = null,
                ClaimToken = null
            });

            var handler = new RecordingHandler((request, _) =>
            {
                Assert.Equal("/api/registration/recovery", request.RequestUri!.AbsolutePath);
                return Json(HttpStatusCode.OK, new
                {
                    registrationId = "reg-established",
                    claimToken = "recovery-claim",
                    state = "RecoveryPending"
                });
            });

            var client = new RegistrationLifecycleClient(
                new HttpClient(handler),
                new RegistrationLifecycleOptions(
                    new Uri("https://configuration.example/"),
                    "Aegis.Hello",
                    "Production",
                    path),
                store);

            RegistrationLifecycleStatus status = await client.StepAsync();

            Assert.Equal(RegistrationLifecycleState.RecoveryPending, status.State);
        }
        finally
        {
            if (Directory.Exists(root))
                Directory.Delete(root, true);
        }
    }

    [Fact]
    public async Task InvalidCredential_RequestsRecoveryInsteadOfCreatingDuplicateRegistration()
    {
        string root = Path.Combine(Path.GetTempPath(), "aegis-registration-" + Guid.NewGuid().ToString("N"));
        string path = Path.Combine(root, "identity.json");
        try
        {
            var store = new FileRegistrationIdentityStore(path);
            RegistrationIdentityDocument identity =
                await store.LoadOrCreateAsync("Aegis.Hello", "Production");
            await store.SaveAsync(identity with
            {
                RegistrationId = "reg-1",
                Credential = "old-secret"
            });

            int calls = 0;
            var handler = new RecordingHandler((request, _) =>
            {
                calls++;
                if (calls == 1)
                {
                    Assert.Equal("/api/registration/authenticate", request.RequestUri!.AbsolutePath);
                    return Json(HttpStatusCode.Unauthorized, new { error = "invalid" });
                }

                Assert.Equal("/api/registration/recovery", request.RequestUri!.AbsolutePath);
                return Json(HttpStatusCode.OK, new
                {
                    registrationId = "reg-1",
                    claimToken = "recovery-claim",
                    state = "RecoveryPending"
                });
            });

            var client = new RegistrationLifecycleClient(
                new HttpClient(handler),
                new RegistrationLifecycleOptions(
                    new Uri("https://configuration.example/"),
                    "Aegis.Hello",
                    "Production",
                    path),
                store);

            RegistrationLifecycleStatus status = await client.StepAsync();

            Assert.Equal(RegistrationLifecycleState.RecoveryPending, status.State);
            Assert.Equal(2, calls);
        }
        finally
        {
            if (Directory.Exists(root))
                Directory.Delete(root, true);
        }
    }

    [Fact]
    public async Task RegisteredIdentity_PublishesConfigurationContractDirectlyToConfiguration()
    {
        string root = Path.Combine(Path.GetTempPath(), "aegis-registration-" + Guid.NewGuid().ToString("N"));
        string path = Path.Combine(root, "identity.json");
        try
        {
            var store = new FileRegistrationIdentityStore(path);
            RegistrationIdentityDocument identity =
                await store.LoadOrCreateAsync("Aegis.Hello", "Production");
            await store.SaveAsync(identity with
            {
                RegistrationId = "reg-1",
                Credential = "permanent-secret"
            });

            var handler = new RecordingHandler((request, _) =>
            {
                Assert.Equal("/api/contracts/register", request.RequestUri!.AbsolutePath);
                Assert.Equal("Bearer", request.Headers.Authorization?.Scheme);
                Assert.Equal("permanent-secret", request.Headers.Authorization?.Parameter);
                Assert.Equal("Aegis.Hello", request.Headers.GetValues("X-Aegis-Application-Id").Single());
                Assert.Equal("Production", request.Headers.GetValues("X-Aegis-Instance-Id").Single());
                Assert.Equal(identity.InstallationId, request.Headers.GetValues("X-Aegis-Installation-Id").Single());
                Assert.True(request.Headers.Contains("X-Aegis-Correlation-Id"));
                return new HttpResponseMessage(HttpStatusCode.OK);
            });

            var client = new RegistrationLifecycleClient(
                new HttpClient(handler),
                new RegistrationLifecycleOptions(
                    new Uri("https://configuration.example/"),
                    "Aegis.Hello",
                    "Production",
                    path),
                store);

            HttpStatusCode status = await client.PublishConfigurationContractAsync(
                new System.Text.Json.Nodes.JsonObject
                {
                    ["applicationId"] = "Aegis.Hello",
                    ["instanceId"] = "Production",
                    ["requirements"] = new System.Text.Json.Nodes.JsonArray()
                });

            Assert.Equal(HttpStatusCode.OK, status);
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
            Content = new StringContent(
                JsonSerializer.Serialize(value),
                Encoding.UTF8,
                "application/json")
        };

    private sealed class RecordingHandler(
        Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> responder) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
            => Task.FromResult(responder(request, cancellationToken));
    }
}
