using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;

namespace Common.Registration;

public sealed record RegistrationOptions(Uri ConfigurationBaseUri, string? RegistrationKey = null, TimeSpan? RequestTimeout = null);

public sealed record RegistrationResult(bool Succeeded, HttpStatusCode? StatusCode, DateTimeOffset AttemptedAtUtc, string? Error)
{
    public static RegistrationResult Success(HttpStatusCode code) => new(true, code, DateTimeOffset.UtcNow, null);
    public static RegistrationResult Failure(string error, HttpStatusCode? code = null) => new(false, code, DateTimeOffset.UtcNow, error);
}

public enum RegistrationCredentialSource
{
    Missing = 0,
    Environment = 1,
    SecretProvider = 2,
    AppSetting = 3
}

public sealed record RegistrationCredentialResolution(
    string? Credential,
    RegistrationCredentialSource Source,
    string? SecretProviderError = null)
{
    public bool Succeeded => !string.IsNullOrWhiteSpace(Credential);
}

public static class RegistrationCredentialResolver
{
    public const string EnvironmentVariableName = "AEGIS_CONFIGURATION_REGISTRATION_KEY";
    public const string AppSettingKey = "Aegis:Configuration:RegistrationKey";

    public static string SecretNameFor(string applicationId)
    {
        if (string.IsNullOrWhiteSpace(applicationId))
            throw new ArgumentException("Application id is required.", nameof(applicationId));

        return $"configuration/registration/{applicationId.Trim()}";
    }

    public static async Task<RegistrationCredentialResolution> ResolveAsync(
        Func<string?> environmentValue,
        Func<CancellationToken, Task<string?>>? secretProviderValue,
        Func<string?> appSettingValue,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(environmentValue);
        ArgumentNullException.ThrowIfNull(appSettingValue);

        string? environment = Normalize(environmentValue());
        if (environment is not null)
            return new(environment, RegistrationCredentialSource.Environment);

        string? secretProviderError = null;
        if (secretProviderValue is not null)
        {
            try
            {
                string? secret = Normalize(await secretProviderValue(cancellationToken).ConfigureAwait(false));
                if (secret is not null)
                    return new(secret, RegistrationCredentialSource.SecretProvider);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                // Secret-provider failure is deliberately non-fatal for bootstrap registration.
                // Registration must still be able to fall back to the app setting and report truthfully.
                secretProviderError = $"{exception.GetType().Name}: {exception.Message}";
            }
        }

        string? appSetting = Normalize(appSettingValue());
        if (appSetting is not null)
            return new(appSetting, RegistrationCredentialSource.AppSetting, secretProviderError);

        return new(null, RegistrationCredentialSource.Missing, secretProviderError);
    }

    private static string? Normalize(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
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

    private static readonly IReadOnlyDictionary<string, int> RequirementKindWireValues =
        new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
        {
            ["Configuration"] = 0,
            ["Secret"] = 1,
            ["ExternalService"] = 2
        };

    public static JsonObject MetadataOnly(JsonObject contract)
    {
        ArgumentNullException.ThrowIfNull(contract);
        var copy = JsonNode.Parse(contract.ToJsonString())?.AsObject()
            ?? throw new InvalidOperationException("Configuration contract could not be cloned.");

        NormalizeForConfigurationWire(copy);
        return copy;
    }

    private static void NormalizeForConfigurationWire(JsonNode? node)
    {
        switch (node)
        {
            case JsonObject obj:
                foreach (string field in ValueBearingFields)
                    obj.Remove(field);

                if (obj["kind"] is JsonValue kindValue &&
                    kindValue.TryGetValue<string>(out string? kindName) &&
                    kindName is not null &&
                    RequirementKindWireValues.TryGetValue(kindName, out int wireValue))
                {
                    obj["kind"] = wireValue;
                }

                foreach (JsonNode? child in obj.Select(property => property.Value).ToArray())
                    NormalizeForConfigurationWire(child);
                break;

            case JsonArray array:
                foreach (JsonNode? child in array)
                    NormalizeForConfigurationWire(child);
                break;
        }
    }
}

public sealed class ConfigurationRegistrar : IConfigurationContractRegistrar
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
