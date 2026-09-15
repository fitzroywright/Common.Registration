using System.Net;
using System.Net.Http.Json;
using System.Reflection;
using System.Text.Json.Nodes;

namespace Common.Registration;

public sealed record ConfigurationRequirement(string Key, bool Required, string? Description = null, bool Secret = false);

public sealed record ComponentIdentity(
    string Application,
    string Component,
    string Version,
    string Environment,
    string Host,
    IReadOnlyList<ConfigurationRequirement> ConfigurationNeeds)
{
    public static ComponentIdentity Detect(
        string application,
        string component,
        IEnumerable<ConfigurationRequirement> configurationNeeds,
        string? environment = null,
        Assembly? assembly = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(application);
        ArgumentException.ThrowIfNullOrWhiteSpace(component);
        assembly ??= Assembly.GetEntryAssembly();
        var version = assembly?.GetName().Version?.ToString() ?? "unknown";
        return new ComponentIdentity(
            application,
            component,
            version,
            environment ?? System.Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT") ?? "Production",
            Dns.GetHostName(),
            configurationNeeds.ToArray());
    }
}

public sealed record RegistrationOptions(Uri ConfigurationBaseUri, string? RegistrationKey = null, TimeSpan? RequestTimeout = null, TimeSpan? RetryDelay = null);

public sealed record RegistrationResult(bool Succeeded, HttpStatusCode? StatusCode, DateTimeOffset AttemptedAtUtc, string? Error)
{
    public static RegistrationResult Success(HttpStatusCode code) => new(true, code, DateTimeOffset.UtcNow, null);
    public static RegistrationResult Failure(string error, HttpStatusCode? code = null) => new(false, code, DateTimeOffset.UtcNow, error);
}

public interface IComponentRegistrar
{
    Task<RegistrationResult> RegisterAsync(ComponentIdentity identity, CancellationToken cancellationToken = default);
}

public interface IConfigurationContractRegistrar
{
    Task<RegistrationResult> RegisterContractAsync(JsonObject contract, CancellationToken cancellationToken = default);
}

public static class ConfigurationContractPolicy
{
    private static readonly HashSet<string> ValueBearingFields = new(StringComparer.OrdinalIgnoreCase)
    {
        "value",
        "currentValue",
        "resolvedValue",
        "effectiveValue",
        "safeDisplayValue",
        "defaultValue",
        "example"
    };

    public static JsonObject MetadataOnly(JsonObject contract)
    {
        ArgumentNullException.ThrowIfNull(contract);
        var copy = JsonNode.Parse(contract.ToJsonString())?.AsObject()
            ?? throw new InvalidOperationException("Configuration contract could not be cloned.");

        RemoveValueBearingFields(copy);
        return copy;
    }

    private static void RemoveValueBearingFields(JsonNode? node)
    {
        switch (node)
        {
            case JsonObject obj:
                foreach (string field in ValueBearingFields)
                    obj.Remove(field);

                foreach (JsonNode? child in obj.Select(property => property.Value).ToArray())
                    RemoveValueBearingFields(child);
                break;

            case JsonArray array:
                foreach (JsonNode? child in array)
                    RemoveValueBearingFields(child);
                break;
        }
    }
}

public sealed class ConfigurationRegistrar : IComponentRegistrar, IConfigurationContractRegistrar
{
    private readonly HttpClient _http;
    private readonly RegistrationOptions _options;

    public ConfigurationRegistrar(HttpClient http, RegistrationOptions options)
    {
        _http = http;
        _options = options;
        _http.BaseAddress = options.ConfigurationBaseUri;
        _http.Timeout = options.RequestTimeout ?? TimeSpan.FromSeconds(5);
    }

    public Task<RegistrationResult> RegisterAsync(ComponentIdentity identity, CancellationToken cancellationToken = default)
        => SendAsync(JsonContent.Create(identity), cancellationToken);

    public Task<RegistrationResult> RegisterContractAsync(JsonObject contract, CancellationToken cancellationToken = default)
        => SendAsync(JsonContent.Create(ConfigurationContractPolicy.MetadataOnly(contract)), cancellationToken);

    private async Task<RegistrationResult> SendAsync(HttpContent content, CancellationToken cancellationToken)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, "api/contracts/register") { Content = content };
            if (!string.IsNullOrWhiteSpace(_options.RegistrationKey))
                request.Headers.TryAddWithoutValidation("X-Aegis-Registration-Key", _options.RegistrationKey);

            using var response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
                return RegistrationResult.Failure($"Configuration rejected registration with HTTP {(int)response.StatusCode}.", response.StatusCode);

            return RegistrationResult.Success(response.StatusCode);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return RegistrationResult.Failure("Configuration registration timed out.");
        }
        catch (HttpRequestException ex)
        {
            return RegistrationResult.Failure($"Configuration registration failed: {ex.Message}");
        }
    }
}

public sealed class RegistrationRetryLoop
{
    private readonly IComponentRegistrar _registrar;
    private readonly TimeSpan _retryDelay;

    public RegistrationRetryLoop(IComponentRegistrar registrar, TimeSpan? retryDelay = null)
    {
        _registrar = registrar;
        _retryDelay = retryDelay ?? TimeSpan.FromSeconds(30);
    }

    public async Task<RegistrationResult> RunUntilRegisteredAsync(
        ComponentIdentity identity,
        Action<RegistrationResult>? observeAttempt = null,
        CancellationToken cancellationToken = default)
    {
        while (true)
        {
            var result = await _registrar.RegisterAsync(identity, cancellationToken).ConfigureAwait(false);
            observeAttempt?.Invoke(result);
            if (result.Succeeded)
                return result;
            await Task.Delay(_retryDelay, cancellationToken).ConfigureAwait(false);
        }
    }
}
