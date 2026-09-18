using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;

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
    public const string EnvironmentVariableName = "AEGIS_REGISTRATION_KEY";
    public const string AppSettingKey = "Aegis:Registration:Key";

    public static string SecretNameFor(string applicationId)
    {
        if (string.IsNullOrWhiteSpace(applicationId))
            throw new ArgumentException("Application id is required.", nameof(applicationId));

        return $"registration/{applicationId.Trim()}";
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

public enum ApplicationRegistrationState
{
    MissingCredential = 0,
    Registered = 1,
    Revoked = 2,
    InvalidCredential = 3,
    Unavailable = 4
}

public sealed record ApplicationRegistrationStatus(
    ApplicationRegistrationState State,
    DateTimeOffset AttemptedAtUtc,
    string? Error = null,
    HttpStatusCode? StatusCode = null)
{
    public bool IsRegistered => State == ApplicationRegistrationState.Registered;
}

public sealed record ApplicationRegistrationOptions(
    Uri OperationsBaseUri,
    string ApplicationId,
    string InstanceId,
    string RegistrationEnvironmentVariable = RegistrationCredentialResolver.EnvironmentVariableName,
    TimeSpan? RequestTimeout = null,
    bool AutoProvisionControlPlane = false,
    string? CredentialFilePath = null);

/// <summary>
/// Application-side registration client. Normal applications consume an Operations-issued
/// registration credential. Trusted control-plane services may request local auto-provisioning
/// and persist the real issued credential to protected storage.
/// </summary>
public sealed class ApplicationRegistrationClient
{
    private readonly HttpClient _http;
    private readonly ApplicationRegistrationOptions _options;
    private readonly Func<string, string?> _environmentValue;
    private readonly ILogger _logger;

    public ApplicationRegistrationClient(
        HttpClient http,
        ApplicationRegistrationOptions options,
        Func<string, string?>? environmentValue = null,
        ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(options);

        if (string.IsNullOrWhiteSpace(options.ApplicationId))
            throw new ArgumentException("Application id is required.", nameof(options));
        if (string.IsNullOrWhiteSpace(options.InstanceId))
            throw new ArgumentException("Instance id is required.", nameof(options));
        if (string.IsNullOrWhiteSpace(options.RegistrationEnvironmentVariable))
            throw new ArgumentException("Registration environment variable is required.", nameof(options));

        _http = http;
        _options = options;
        _environmentValue = environmentValue ?? Environment.GetEnvironmentVariable;
        _logger = logger ?? Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance;
        _http.BaseAddress = options.OperationsBaseUri;
        _http.Timeout = options.RequestTimeout ?? TimeSpan.FromSeconds(10);
    }

    private async Task<string?> AutoProvisionControlPlaneAsync(CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await _http.PostAsJsonAsync(
            "api/registration/control-plane/auto",
            new
            {
                applicationId = _options.ApplicationId,
                displayName = _options.ApplicationId,
                instanceId = _options.InstanceId
            },
            cancellationToken).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            _logger.LogWarning(
                "Control-plane auto-provisioning was rejected by Operations with HTTP {StatusCode}.",
                (int)response.StatusCode);
            return null;
        }

        ControlPlaneCredentialResponse? result =
            await response.Content.ReadFromJsonAsync<ControlPlaneCredentialResponse>(cancellationToken: cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(result?.Credential))
            return null;

        string credential = result.Credential.Trim();
        if (!string.IsNullOrWhiteSpace(_options.CredentialFilePath))
        {
            string fullPath = Path.GetFullPath(_options.CredentialFilePath);
            Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
            await File.WriteAllTextAsync(fullPath, credential + Environment.NewLine, cancellationToken).ConfigureAwait(false);
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(fullPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        return credential;
    }

    private sealed record ControlPlaneCredentialResponse(string Credential);

    public async Task<ApplicationRegistrationStatus> RegisterAsync(
        JsonObject contract,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(contract);

        string attemptId = Guid.NewGuid().ToString("N");
        using IDisposable? scope = _logger.BeginScope(new Dictionary<string, object?>
        {
            ["Activity"] = "Registration",
            ["Application"] = _options.ApplicationId,
            ["RegistrationAttemptId"] = attemptId
        });
        void Step(LogLevel level, string stage, string message, params object?[] args)
        {
            using IDisposable? stageScope = _logger.BeginScope(new Dictionary<string, object?> { ["Stage"] = stage });
            _logger.Log(level, message, args);
        }

        Step(LogLevel.Information, "Started", "Registration attempt started for instance {InstanceId}.", _options.InstanceId);
        Step(LogLevel.Information, "RegistrationKeyLookup", "Looking for registration key in environment variable {RegistrationEnvironmentVariable}.", _options.RegistrationEnvironmentVariable);
        string? credential = _environmentValue(_options.RegistrationEnvironmentVariable)?.Trim();
        if (string.IsNullOrWhiteSpace(credential) && !string.IsNullOrWhiteSpace(_options.CredentialFilePath) && File.Exists(_options.CredentialFilePath))
            credential = (await File.ReadAllTextAsync(_options.CredentialFilePath, cancellationToken).ConfigureAwait(false)).Trim();

        if (string.IsNullOrWhiteSpace(credential) && _options.AutoProvisionControlPlane)
        {
            Step(LogLevel.Information, "ControlPlaneAutoProvision", "No registration key exists; requesting local control-plane auto-provisioning.");
            credential = await AutoProvisionControlPlaneAsync(cancellationToken).ConfigureAwait(false);
        }

        if (string.IsNullOrWhiteSpace(credential))
        {
            Step(LogLevel.Warning, "RegistrationKeyMissing", "Registration key was not found.");
            Step(LogLevel.Warning, "Failed", "Registration attempt failed because the registration key is missing.");
            return new(
                ApplicationRegistrationState.MissingCredential,
                DateTimeOffset.UtcNow,
                $"Registration key is missing from environment variable {_options.RegistrationEnvironmentVariable} and no control-plane credential could be provisioned.");
        }

        Step(LogLevel.Information, "RegistrationKeyFound", "Registration key was found.");
        try
        {
            Step(LogLevel.Information, "RequestPreparing", "Preparing registration contract request to Operations.");
            using var request = new HttpRequestMessage(HttpMethod.Post, "api/registration/contracts")
            {
                Content = JsonContent.Create(ConfigurationContractPolicy.MetadataOnly(contract))
            };
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", credential);
            request.Headers.TryAddWithoutValidation("X-Aegis-Application-Id", _options.ApplicationId);
            request.Headers.TryAddWithoutValidation("X-Aegis-Instance-Id", _options.InstanceId);
            request.Headers.TryAddWithoutValidation("X-Aegis-Registration-Attempt-Id", attemptId);

            Step(LogLevel.Information, "RequestSending", "Sending registration contract request to Operations.");
            using HttpResponseMessage response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
            Step(LogLevel.Information, "ResponseReceived", "Operations returned HTTP {StatusCode}.", (int)response.StatusCode);
            if (response.IsSuccessStatusCode)
            {
                Uri? finalUri = response.RequestMessage?.RequestUri;
                bool redirectedToLogin = finalUri is not null &&
                    finalUri.AbsolutePath.StartsWith("/login", StringComparison.OrdinalIgnoreCase);
                bool htmlResponse = response.Content.Headers.ContentType?.MediaType?.Equals(
                    "text/html",
                    StringComparison.OrdinalIgnoreCase) == true;

                if (redirectedToLogin || htmlResponse)
                {
                    Step(
                        LogLevel.Warning,
                        "InteractiveLoginRedirect",
                        "Registration did not complete because the Operations API redirected to an interactive login endpoint.");
                    return new(
                        ApplicationRegistrationState.Unavailable,
                        DateTimeOffset.UtcNow,
                        "Operations redirected the registration API request to interactive login instead of processing the registration.",
                        response.StatusCode);
                }

                Step(LogLevel.Information, "Succeeded", "Registration succeeded and the configuration contract was accepted.");
                return new(ApplicationRegistrationState.Registered, DateTimeOffset.UtcNow, StatusCode: response.StatusCode);
            }

            if (response.StatusCode == HttpStatusCode.Gone)
            {
                Step(LogLevel.Warning, "Revoked", "Registration failed because the registration was revoked.");
                return new(ApplicationRegistrationState.Revoked, DateTimeOffset.UtcNow, "Registration has been revoked. Create a new pending registration in Operations and replace the environment variable.", response.StatusCode);
            }

            if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            {
                Step(LogLevel.Warning, "InvalidCredential", "Registration failed because Operations rejected the registration key.");
                return new(ApplicationRegistrationState.InvalidCredential, DateTimeOffset.UtcNow, "Registration key is invalid. Create a new pending registration in Operations and replace the environment variable.", response.StatusCode);
            }

            Step(LogLevel.Warning, "Rejected", "Registration failed because Operations rejected the request with HTTP {StatusCode}.", (int)response.StatusCode);
            return new(
                ApplicationRegistrationState.Unavailable,
                DateTimeOffset.UtcNow,
                $"Operations rejected registration with HTTP {(int)response.StatusCode}.",
                response.StatusCode);
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            using IDisposable? stageScope = _logger.BeginScope(new Dictionary<string, object?> { ["Stage"] = "TimedOut" });
            _logger.LogWarning(ex, "Registration request timed out.");
            return new(ApplicationRegistrationState.Unavailable, DateTimeOffset.UtcNow, "Operations registration request timed out.");
        }
        catch (HttpRequestException ex)
        {
            using IDisposable? stageScope = _logger.BeginScope(new Dictionary<string, object?> { ["Stage"] = "RequestFailed" });
            _logger.LogWarning(ex, "Registration request to Operations failed.");
            return new(ApplicationRegistrationState.Unavailable, DateTimeOffset.UtcNow, $"Operations registration is unavailable: {ex.Message}");
        }
    }
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
