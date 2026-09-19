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

            var store = new FileRegistrationIdentityStore(path);
            var client = new RegistrationLifecycleClient(
                new HttpClient(handler),
                new RegistrationLifecycleOptions(
                    new Uri("https://configuration.example/"),
                    "Aegis.Hello",
                    "Production",
                    path),
                store);

            RegistrationLifecycleStatus status = await client.StepAsync();

            Assert.Equal(RegistrationLifecycleState.Pending, status.State);
            RegistrationIdentityDocument persisted =
                await store.LoadOrCreateAsync("Aegis.Hello", "Production");
            Assert.Equal("reg-1", persisted.RegistrationId);
            Assert.Equal("claim-secret", persisted.ClaimToken);

            byte[] raw = await File.ReadAllBytesAsync(path);
            string rawText = Encoding.UTF8.GetString(raw);
            if (OperatingSystem.IsWindows())
            {
                Assert.DoesNotContain("claim-secret", rawText);
                Assert.DoesNotContain("reg-1", rawText);
            }
            else
            {
                Assert.Contains("reg-1", rawText);
                Assert.Contains("claim-secret", rawText);
            }
            Assert.DoesNotContain("AEGIS_REGISTRATION_KEY", rawText);
        }
        finally
        {
            if (Directory.Exists(root))
                Directory.Delete(root, true);
        }
    }

    [Fact]
    public async Task FirstRegistration_AdvertisesRunbookReferenceWithoutCredentials()
    {
        string root = Path.Combine(Path.GetTempPath(), "aegis-registration-" + Guid.NewGuid().ToString("N"));
        string path = Path.Combine(root, "identity.json");
        try
        {
            var handler = new RecordingHandler((request, _) =>
            {
                string body = request.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
                using JsonDocument document = JsonDocument.Parse(body);
                Assert.Equal(
                    "docs/RUNBOOK.md",
                    document.RootElement.GetProperty("runbookReference").GetString());
                Assert.DoesNotContain("credential", body, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain("claimToken", body, StringComparison.OrdinalIgnoreCase);

                return Json(HttpStatusCode.OK, new
                {
                    registrationId = "reg-runbook",
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
                    path,
                    RunbookReference: "docs/RUNBOOK.md"));

            RegistrationLifecycleStatus status = await client.StepAsync();
            Assert.Equal(RegistrationLifecycleState.Pending, status.State);
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

            RegistrationIdentityDocument persisted =
                await store.LoadOrCreateAsync("Aegis.Hello", "Production");
            Assert.Null(persisted.ClaimToken);
            Assert.Equal("permanent-secret", persisted.Credential);

            byte[] raw = await File.ReadAllBytesAsync(path);
            string rawText = Encoding.UTF8.GetString(raw);
            Assert.DoesNotContain("claim-secret", rawText);
            if (OperatingSystem.IsWindows())
                Assert.DoesNotContain("permanent-secret", rawText);
            else
                Assert.Contains("permanent-secret", rawText);
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
    public void RegistrationClient_RejectsNonTlsNonLoopbackConfigurationEndpoint()
    {
        string path = Path.Combine(Path.GetTempPath(), "aegis-registration-" + Guid.NewGuid().ToString("N"), "identity.json");
        var handler = new RecordingHandler((_, _) => new HttpResponseMessage(HttpStatusCode.OK));

        Assert.Throws<ArgumentException>(() => new RegistrationLifecycleClient(
            new HttpClient(handler),
            new RegistrationLifecycleOptions(
                new Uri("http://configuration.example/"),
                "Aegis.Hello",
                "Production",
                path)));
    }

    [Fact]
    public void RegistrationClient_AllowsLoopbackHttpForLocalDevelopment()
    {
        string path = Path.Combine(Path.GetTempPath(), "aegis-registration-" + Guid.NewGuid().ToString("N"), "identity.json");
        var handler = new RecordingHandler((_, _) => new HttpResponseMessage(HttpStatusCode.OK));

        _ = new RegistrationLifecycleClient(
            new HttpClient(handler),
            new RegistrationLifecycleOptions(
                new Uri("http://127.0.0.1:5200/"),
                "Aegis.Hello",
                "Production",
                path));
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



    [Fact]
    public async Task ClaimToken_IsConsumedOnce_AndNeverReplayedAfterSuccess()
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
                RegistrationId = "reg-once",
                ClaimToken = "one-time-claim"
            });

            int claimCalls = 0;
            int authCalls = 0;
            var handler = new RecordingHandler((request, _) =>
            {
                if (request.RequestUri!.AbsolutePath.EndsWith("/claim", StringComparison.Ordinal))
                {
                    claimCalls++;
                    return Json(HttpStatusCode.OK, new
                    {
                        registrationId = "reg-once",
                        credential = "durable-secret",
                        state = "Registered"
                    });
                }

                if (request.RequestUri.AbsolutePath == "/api/registration/authenticate")
                {
                    authCalls++;
                    Assert.Equal("durable-secret", request.Headers.Authorization?.Parameter);
                    return Json(HttpStatusCode.OK, new
                    {
                        registrationId = "reg-once",
                        state = "Registered"
                    });
                }

                throw new Xunit.Sdk.XunitException("Unexpected request: " + request.RequestUri);
            });

            var client = new RegistrationLifecycleClient(
                new HttpClient(handler),
                new RegistrationLifecycleOptions(
                    new Uri("https://configuration.example/"),
                    "Aegis.Hello",
                    "Production",
                    path),
                store);

            Assert.Equal(RegistrationLifecycleState.Registered, (await client.StepAsync()).State);
            Assert.Equal(RegistrationLifecycleState.Registered, (await client.StepAsync()).State);

            Assert.Equal(1, claimCalls);
            Assert.Equal(1, authCalls);

            RegistrationIdentityDocument persisted =
                await store.LoadOrCreateAsync("Aegis.Hello", "Production");
            Assert.Null(persisted.ClaimToken);
            Assert.Equal("durable-secret", persisted.Credential);
        }
        finally
        {
            if (Directory.Exists(root))
                Directory.Delete(root, true);
        }
    }



    [Fact]
    public async Task ExpiredClaim_TransitionsToRecoveryPending_InsteadOfLooping()
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
                RegistrationId = "reg-expired-claim",
                ClaimToken = "expired-claim"
            });

            int calls = 0;
            var handler = new RecordingHandler((request, _) =>
            {
                calls++;
                return request.RequestUri!.AbsolutePath switch
                {
                    "/api/registration/reg-expired-claim/claim" =>
                        Json(HttpStatusCode.Unauthorized, new { error = "claim expired" }),

                    "/api/registration/recovery" =>
                        Json(HttpStatusCode.OK, new
                        {
                            registrationId = "reg-expired-claim",
                            claimToken = "recovery-claim",
                            state = "RecoveryPending"
                        }),

                    _ => throw new Xunit.Sdk.XunitException("Unexpected request: " + request.RequestUri)
                };
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

            RegistrationIdentityDocument persisted =
                await store.LoadOrCreateAsync("Aegis.Hello", "Production");
            Assert.Equal("recovery-claim", persisted.ClaimToken);
            Assert.Null(persisted.Credential);
            Assert.Equal("reg-expired-claim", persisted.RegistrationId);
        }
        finally
        {
            if (Directory.Exists(root))
                Directory.Delete(root, true);
        }
    }

    [Fact]
    public async Task PurgedServerRecord_ClearsStaleCredential_AndCreatesFreshPending()
    {
        string root = Path.Combine(Path.GetTempPath(), "aegis-registration-" + Guid.NewGuid().ToString("N"));
        string path = Path.Combine(root, "identity.json");
        try
        {
            var store = new FileRegistrationIdentityStore(path);
            RegistrationIdentityDocument identity =
                await store.LoadOrCreateAsync("Aegis.Hello", "Production");
            string installationId = identity.InstallationId;

            await store.SaveAsync(identity with
            {
                RegistrationId = "reg-purged",
                Credential = "stale-secret"
            });

            int calls = 0;
            var handler = new RecordingHandler((request, _) =>
            {
                calls++;
                return request.RequestUri!.AbsolutePath switch
                {
                    "/api/registration/authenticate" =>
                        Json(HttpStatusCode.Unauthorized, new { error = "unknown registration" }),

                    "/api/registration/recovery" =>
                        Json(HttpStatusCode.NotFound, new { error = "No established registration exists for recovery." }),

                    "/api/registration/request" =>
                        Json(HttpStatusCode.OK, new
                        {
                            registrationId = "reg-fresh",
                            claimToken = "fresh-claim",
                            state = "Pending"
                        }),

                    _ => throw new Xunit.Sdk.XunitException("Unexpected request: " + request.RequestUri)
                };
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

            Assert.Equal(RegistrationLifecycleState.Pending, status.State);
            Assert.Equal("reg-fresh", status.RegistrationId);
            Assert.Equal(3, calls);

            RegistrationIdentityDocument persisted =
                await store.LoadOrCreateAsync("Aegis.Hello", "Production");

            Assert.Equal(installationId, persisted.InstallationId);
            Assert.Equal("reg-fresh", persisted.RegistrationId);
            Assert.Equal("fresh-claim", persisted.ClaimToken);
            Assert.Null(persisted.Credential);
        }
        finally
        {
            if (Directory.Exists(root))
                Directory.Delete(root, true);
        }
    }

    [Fact]
    public async Task RevokedCredential_DoesNotTriggerAutomaticReregistration()
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
                RegistrationId = "reg-revoked",
                Credential = "revoked-secret"
            });

            int requests = 0;
            var handler = new RecordingHandler((request, _) =>
            {
                requests++;
                Assert.Equal("/api/registration/authenticate", request.RequestUri!.AbsolutePath);
                return Json(HttpStatusCode.Gone, new
                {
                    registrationId = "reg-revoked",
                    state = "Revoked",
                    error = "Registration is revoked."
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

            Assert.Equal(RegistrationLifecycleState.Revoked, status.State);
            Assert.Equal(1, requests);
            Assert.Equal("reg-revoked", status.RegistrationId);
        }
        finally
        {
            if (Directory.Exists(root))
                Directory.Delete(root, true);
        }
    }

    [Fact]
    public async Task IdentityConflict_IsTerminalForThatStep_AndDoesNotSelfHeal()
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
                RegistrationId = "reg-conflict",
                Credential = "credential"
            });

            int requests = 0;
            var handler = new RecordingHandler((request, _) =>
            {
                requests++;
                Assert.Equal("/api/registration/authenticate", request.RequestUri!.AbsolutePath);
                return Json(HttpStatusCode.Conflict, new
                {
                    registrationId = "reg-conflict",
                    state = "IdentityConflict",
                    error = "Installation identity conflict."
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

            Assert.Equal(RegistrationLifecycleState.IdentityConflict, status.State);
            Assert.Equal(1, requests);
        }
        finally
        {
            if (Directory.Exists(root))
                Directory.Delete(root, true);
        }
    }

    [Fact]
    public async Task RegistrationLifecycle_DoesNotLogClaimOrPermanentCredential()
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
                RegistrationId = "reg-secret-test",
                ClaimToken = "claim-token-must-not-log"
            });

            var logger = new CaptureLogger();
            var handler = new RecordingHandler((request, _) =>
            {
                Assert.Equal("/api/registration/reg-secret-test/claim", request.RequestUri!.AbsolutePath);
                return Json(HttpStatusCode.OK, new
                {
                    registrationId = "reg-secret-test",
                    credential = "permanent-credential-must-not-log",
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
                store,
                logger);

            RegistrationLifecycleStatus status = await client.StepAsync();

            Assert.Equal(RegistrationLifecycleState.Registered, status.State);
            string combined = string.Join("\n", logger.Messages);
            Assert.DoesNotContain("claim-token-must-not-log", combined, StringComparison.Ordinal);
            Assert.DoesNotContain("permanent-credential-must-not-log", combined, StringComparison.Ordinal);
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
    private sealed class CaptureLogger : Microsoft.Extensions.Logging.ILogger
    {
        public List<string> Messages { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull
            => NullScope.Instance;

        public bool IsEnabled(Microsoft.Extensions.Logging.LogLevel logLevel) => true;

        public void Log<TState>(
            Microsoft.Extensions.Logging.LogLevel logLevel,
            Microsoft.Extensions.Logging.EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
            => Messages.Add(formatter(state, exception));

        private sealed class NullScope : IDisposable
        {
            public static readonly NullScope Instance = new();
            public void Dispose() { }
        }
    }

}
