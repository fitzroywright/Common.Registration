using System.Net;
using System.Net.Http;
using System.Text;
using Common.Diagnostics;
using Common.Registration;
using Xunit;

public sealed class LifecycleTelemetryIntegrationTests
{
    [Fact]
    public async Task StepAsync_EmitsStartedAndFinalState_WithoutSecrets()
    {
        var sink = new RecordingSink();
        var handler = new StubHandler(request =>
        {
            Assert.Equal("/api/registration/request", request.RequestUri!.AbsolutePath);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    """{"registrationId":"reg-telemetry","claimToken":"top-secret-claim","state":"Pending"}""",
                    Encoding.UTF8,
                    "application/json")
            };
        });
        var store = new MemoryIdentityStore();

        var client = new RegistrationLifecycleClient(
            new HttpClient(handler),
            new RegistrationLifecycleOptions(
                new Uri("https://configuration.example/"),
                "Aegis.Hello",
                "hello-01",
                "unused.json"),
            store,
            lifecycleEventSink: sink);

        RegistrationLifecycleStatus status = await client.StepAsync();

        Assert.Equal(RegistrationLifecycleState.Pending, status.State);
        Assert.Equal(2, sink.Items.Count);
        Assert.Equal("Step", sink.Items[0].Stage);
        Assert.Equal(LifecycleEventOutcome.Started, sink.Items[0].Outcome);
        Assert.Equal("Pending", sink.Items[1].Stage);
        Assert.Equal("reg-telemetry", sink.Items[1].RelatedBusinessId);

        string serialized = System.Text.Json.JsonSerializer.Serialize(sink.Items);
        Assert.DoesNotContain("top-secret-claim", serialized, StringComparison.Ordinal);
    }


    [Fact]
    public async Task PublishConfigurationContractAsync_EmitsFailure_WhenConfigurationIsUnavailable()
    {
        var sink = new RecordingSink();
        var store = new MemoryIdentityStore();
        RegistrationIdentityDocument identity =
            await store.LoadOrCreateAsync("Aegis.Hello", "hello-01");
        await store.SaveAsync(identity with
        {
            RegistrationId = "reg-contract",
            Credential = "durable-secret"
        });

        var client = new RegistrationLifecycleClient(
            new HttpClient(new ThrowingHandler()),
            new RegistrationLifecycleOptions(
                new Uri("https://configuration.example/"),
                "Aegis.Hello",
                "hello-01",
                "unused.json"),
            store,
            lifecycleEventSink: sink);

        await Assert.ThrowsAsync<HttpRequestException>(() =>
            client.PublishConfigurationContractAsync(
                new System.Text.Json.Nodes.JsonObject
                {
                    ["applicationId"] = "Aegis.Hello",
                    ["instanceId"] = "hello-01",
                    ["requirements"] = new System.Text.Json.Nodes.JsonArray()
                }));

        Assert.Equal(2, sink.Items.Count);
        Assert.Equal("ConfigurationContract", sink.Items[0].Stage);
        Assert.Equal(LifecycleEventOutcome.Started, sink.Items[0].Outcome);
        Assert.Equal("ConfigurationContract", sink.Items[1].Stage);
        Assert.Equal(LifecycleEventOutcome.Failed, sink.Items[1].Outcome);
        Assert.Equal("reg-contract", sink.Items[1].RelatedBusinessId);

        string serialized = System.Text.Json.JsonSerializer.Serialize(sink.Items);
        Assert.DoesNotContain("durable-secret", serialized, StringComparison.Ordinal);
    }

    [Fact]
    public async Task PublishConfigurationContractAsync_EmitsRecoverySuccess_AfterOutage()
    {
        var sink = new RecordingSink();
        var store = new MemoryIdentityStore();
        RegistrationIdentityDocument identity =
            await store.LoadOrCreateAsync("Aegis.Hello", "hello-01");
        await store.SaveAsync(identity with
        {
            RegistrationId = "reg-contract",
            Credential = "durable-secret"
        });

        var client = new RegistrationLifecycleClient(
            new HttpClient(new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK))),
            new RegistrationLifecycleOptions(
                new Uri("https://configuration.example/"),
                "Aegis.Hello",
                "hello-01",
                "unused.json"),
            store,
            lifecycleEventSink: sink);

        HttpStatusCode status = await client.PublishConfigurationContractAsync(
            new System.Text.Json.Nodes.JsonObject
            {
                ["applicationId"] = "Aegis.Hello",
                ["instanceId"] = "hello-01",
                ["requirements"] = new System.Text.Json.Nodes.JsonArray()
            });

        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Equal(2, sink.Items.Count);
        Assert.Equal("ConfigurationContract", sink.Items[0].Stage);
        Assert.Equal(LifecycleEventOutcome.Started, sink.Items[0].Outcome);
        Assert.Equal("ConfigurationContractPublished", sink.Items[1].Stage);
        Assert.Equal(LifecycleEventOutcome.Succeeded, sink.Items[1].Outcome);
        Assert.Equal("reg-contract", sink.Items[1].RelatedBusinessId);
    }

    private sealed class RecordingSink : ILifecycleEventSink
    {
        public List<LifecycleEvent> Items { get; } = [];
        public Task EmitAsync(LifecycleEvent lifecycleEvent, CancellationToken cancellationToken = default)
        {
            Items.Add(lifecycleEvent);
            return Task.CompletedTask;
        }
    }


    private sealed class ThrowingHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
            => throw new HttpRequestException("Configuration unavailable.");
    }

    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(respond(request));
    }

    private sealed class MemoryIdentityStore : IRegistrationIdentityStore
    {
        private RegistrationIdentityDocument? document;

        public Task<RegistrationIdentityDocument> LoadOrCreateAsync(
            string applicationId,
            string instanceId,
            CancellationToken cancellationToken = default)
        {
            document ??= new RegistrationIdentityDocument(
                applicationId,
                instanceId,
                "installation-telemetry",
                null,
                null,
                null,
                DateTimeOffset.UtcNow,
                DateTimeOffset.UtcNow);
            return Task.FromResult(document);
        }

        public Task SaveAsync(RegistrationIdentityDocument document, CancellationToken cancellationToken = default)
        {
            this.document = document;
            return Task.CompletedTask;
        }
    }
}
