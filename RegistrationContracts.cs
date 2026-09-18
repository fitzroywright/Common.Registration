using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
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
    Unknown = 0,
    Pending = 1,
    Registered = 2,
    Revoked = 3,
    InvalidCredential = 4,
    Unavailable = 5
}

public sealed record ApplicationRegistrationStatus(
    ApplicationRegistrationState State,
    DateTimeOffset AttemptedAtUtc,
    string? RegistrationId = null,
    string? Pin = null,
    string? Error = null,
    HttpStatusCode? StatusCode = null)
{
    public bool IsRegistered => State == ApplicationRegistrationState.Registered;
}

public sealed record ApplicationRegistrationOptions(
    Uri OperationsBaseUri,
    string ApplicationId,
    string DisplayName,
    string InstanceId,
    string? CredentialPath = null,
    TimeSpan? RequestTimeout = null);

public interface IRegistrationCredentialStore
{
    Task<string?> LoadAsync(CancellationToken cancellationToken = default);
    Task SaveAsync(string credential, CancellationToken cancellationToken = default);
    Task DeleteAsync(CancellationToken cancellationToken = default);
}

public sealed class FileRegistrationCredentialStore : IRegistrationCredentialStore
{
    private readonly string _path;

    public FileRegistrationCredentialStore(string applicationId, string? path = null)
    {
        if (string.IsNullOrWhiteSpace(applicationId))
            throw new ArgumentException("Application id is required.", nameof(applicationId));

        _path = string.IsNullOrWhiteSpace(path) ? DefaultPath(applicationId) : Path.GetFullPath(path);
    }

    public async Task<string?> LoadAsync(CancellationToken cancellationToken = default)
    {
        if (!File.Exists(_path))
            return null;

        string value = (await File.ReadAllTextAsync(_path, cancellationToken).ConfigureAwait(false)).Trim();
        return string.IsNullOrWhiteSpace(value) ? null : value;
    }

    public async Task SaveAsync(string credential, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(credential))
            throw new ArgumentException("Credential is required.", nameof(credential));

        string? directory = Path.GetDirectoryName(_path);
        if (string.IsNullOrWhiteSpace(directory))
            throw new InvalidOperationException("Registration credential path has no parent directory.");

        Directory.CreateDirectory(directory);
        SecureDirectory(directory);

        string temp = _path + "." + Convert.ToHexString(RandomNumberGenerator.GetBytes(6)).ToLowerInvariant() + ".tmp";
        await File.WriteAllTextAsync(temp, credential.Trim(), cancellationToken).ConfigureAwait(false);
        SecureFile(temp);
        File.Move(temp, _path, true);
        SecureFile(_path);
    }

    public Task DeleteAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (File.Exists(_path))
            File.Delete(_path);
        return Task.CompletedTask;
    }

    private static string DefaultPath(string applicationId)
    {
        string root = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(root))
            root = AppContext.BaseDirectory;

        string safe = string.Concat(applicationId.Select(ch => char.IsLetterOrDigit(ch) || ch is '.' or '-' or '_' ? ch : '_'));
        return Path.Combine(root, "Aegis", "Registration", safe + ".credential");
    }

    private static void SecureDirectory(string path)
    {
        if (OperatingSystem.IsWindows())
            return;

        File.SetUnixFileMode(path,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }

    private static void SecureFile(string path)
    {
        if (OperatingSystem.IsWindows())
            return;

        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }
}

public sealed class ApplicationRegistrationClient
{
    private readonly HttpClient _http;
    private readonly ApplicationRegistrationOptions _options;
    private readonly IRegistrationCredentialStore _credentialStore;

    public ApplicationRegistrationClient(
        HttpClient http,
        ApplicationRegistrationOptions options,
        IRegistrationCredentialStore? credentialStore = null)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(options);

        if (string.IsNullOrWhiteSpace(options.ApplicationId))
            throw new ArgumentException("Application id is required.", nameof(options));
        if (string.IsNullOrWhiteSpace(options.DisplayName))
            throw new ArgumentException("Display name is required.", nameof(options));
        if (string.IsNullOrWhiteSpace(options.InstanceId))
            throw new ArgumentException("Instance id is required.", nameof(options));

        _http = http;
        _options = options;
        _credentialStore = credentialStore ?? new FileRegistrationCredentialStore(options.ApplicationId, options.CredentialPath);
        _http.BaseAddress = options.OperationsBaseUri;
        _http.Timeout = options.RequestTimeout ?? TimeSpan.FromSeconds(10);
    }

    public async Task<ApplicationRegistrationStatus> PublishContractAsync(
        JsonObject contract,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(contract);

        string? credential = await _credentialStore.LoadAsync(cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(credential))
        {
            ApplicationRegistrationStatus published = await SendContractAsync(
                credential,
                contract,
                cancellationToken).ConfigureAwait(false);

            if (published.IsRegistered)
                return published;

            if (published.State is not (ApplicationRegistrationState.InvalidCredential or ApplicationRegistrationState.Revoked))
                return published;

            await _credentialStore.DeleteAsync(cancellationToken).ConfigureAwait(false);
        }

        PendingRegistration pending = await EnsurePendingAsync(cancellationToken).ConfigureAwait(false);
        if (!pending.Succeeded)
            return new(
                pending.State,
                DateTimeOffset.UtcNow,
                pending.RegistrationId,
                pending.Pin,
                pending.Error,
                pending.StatusCode);

        CredentialRetrieval retrieval = await TryRetrieveCredentialAsync(
            pending.RegistrationId!,
            pending.Pin!,
            cancellationToken).ConfigureAwait(false);

        if (!retrieval.Succeeded)
        {
            return new(
                retrieval.State,
                DateTimeOffset.UtcNow,
                pending.RegistrationId,
                pending.Pin,
                retrieval.Error,
                retrieval.StatusCode);
        }

        await _credentialStore.SaveAsync(retrieval.Credential!, cancellationToken).ConfigureAwait(false);
        return await SendContractAsync(retrieval.Credential!, contract, cancellationToken).ConfigureAwait(false);
    }

    private async Task<PendingRegistration> EnsurePendingAsync(CancellationToken cancellationToken)
    {
        try
        {
            using HttpResponseMessage response = await _http.PostAsJsonAsync(
                "api/registration/pending",
                new
                {
                    applicationId = _options.ApplicationId,
                    displayName = _options.DisplayName,
                    instanceId = _options.InstanceId
                },
                cancellationToken).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
                return PendingRegistration.Failure(
                    ApplicationRegistrationState.Unavailable,
                    $"Operations rejected pending registration with HTTP {(int)response.StatusCode}.",
                    response.StatusCode);

            JsonObject payload = await ReadObjectAsync(response, cancellationToken).ConfigureAwait(false);
            string? id = payload["registrationId"]?.GetValue<string>();
            string? pin = payload["pin"]?.GetValue<string>();
            if (string.IsNullOrWhiteSpace(id) || string.IsNullOrWhiteSpace(pin))
                return PendingRegistration.Failure(
                    ApplicationRegistrationState.Unavailable,
                    "Operations returned an incomplete pending registration response.",
                    response.StatusCode);

            return PendingRegistration.Success(id, pin, response.StatusCode);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return PendingRegistration.Failure(ApplicationRegistrationState.Unavailable, "Operations registration request timed out.");
        }
        catch (HttpRequestException ex)
        {
            return PendingRegistration.Failure(ApplicationRegistrationState.Unavailable, $"Operations registration is unavailable: {ex.Message}");
        }
    }

    private async Task<CredentialRetrieval> TryRetrieveCredentialAsync(
        string registrationId,
        string pin,
        CancellationToken cancellationToken)
    {
        try
        {
            string path = $"api/registration/pending/{Uri.EscapeDataString(registrationId)}/credential?pin={Uri.EscapeDataString(pin)}";
            using HttpResponseMessage response = await _http.GetAsync(path, cancellationToken).ConfigureAwait(false);

            if (response.StatusCode == HttpStatusCode.Accepted)
                return CredentialRetrieval.Pending(response.StatusCode);
            if (response.StatusCode == HttpStatusCode.Gone)
                return CredentialRetrieval.Failure(ApplicationRegistrationState.Revoked, "Registration was revoked.", response.StatusCode);
            if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
                return CredentialRetrieval.Failure(ApplicationRegistrationState.InvalidCredential, "Registration PIN was rejected.", response.StatusCode);
            if (!response.IsSuccessStatusCode)
                return CredentialRetrieval.Failure(ApplicationRegistrationState.Unavailable, $"Credential retrieval failed with HTTP {(int)response.StatusCode}.", response.StatusCode);

            JsonObject payload = await ReadObjectAsync(response, cancellationToken).ConfigureAwait(false);
            string? credential = payload["credential"]?.GetValue<string>();
            if (string.IsNullOrWhiteSpace(credential))
                return CredentialRetrieval.Failure(ApplicationRegistrationState.Unavailable, "Operations did not return the approved credential.", response.StatusCode);

            return CredentialRetrieval.Success(credential, response.StatusCode);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return CredentialRetrieval.Failure(ApplicationRegistrationState.Unavailable, "Credential retrieval timed out.");
        }
        catch (HttpRequestException ex)
        {
            return CredentialRetrieval.Failure(ApplicationRegistrationState.Unavailable, $"Credential retrieval failed: {ex.Message}");
        }
    }

    private async Task<ApplicationRegistrationStatus> SendContractAsync(
        string credential,
        JsonObject contract,
        CancellationToken cancellationToken)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, "api/registration/contracts")
            {
                Content = JsonContent.Create(ConfigurationContractPolicy.MetadataOnly(contract))
            };
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", credential);
            request.Headers.TryAddWithoutValidation("X-Aegis-Application-Id", _options.ApplicationId);
            request.Headers.TryAddWithoutValidation("X-Aegis-Instance-Id", _options.InstanceId);

            using HttpResponseMessage response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
            if (response.IsSuccessStatusCode)
                return new(ApplicationRegistrationState.Registered, DateTimeOffset.UtcNow, StatusCode: response.StatusCode);

            if (response.StatusCode == HttpStatusCode.Gone)
                return new(ApplicationRegistrationState.Revoked, DateTimeOffset.UtcNow, Error: "Registration was revoked.", StatusCode: response.StatusCode);

            if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
                return new(ApplicationRegistrationState.InvalidCredential, DateTimeOffset.UtcNow, Error: "Registration credential is invalid.", StatusCode: response.StatusCode);

            return new(
                ApplicationRegistrationState.Unavailable,
                DateTimeOffset.UtcNow,
                Error: $"Operations rejected contract publication with HTTP {(int)response.StatusCode}.",
                StatusCode: response.StatusCode);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new(ApplicationRegistrationState.Unavailable, DateTimeOffset.UtcNow, Error: "Operations contract publication timed out.");
        }
        catch (HttpRequestException ex)
        {
            return new(ApplicationRegistrationState.Unavailable, DateTimeOffset.UtcNow, Error: $"Operations contract publication failed: {ex.Message}");
        }
    }

    private static async Task<JsonObject> ReadObjectAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        JsonNode? node = await JsonNode.ParseAsync(
            await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false),
            cancellationToken: cancellationToken).ConfigureAwait(false);
        return node?.AsObject() ?? new JsonObject();
    }

    private sealed record PendingRegistration(
        bool Succeeded,
        ApplicationRegistrationState State,
        string? RegistrationId,
        string? Pin,
        string? Error,
        HttpStatusCode? StatusCode)
    {
        public static PendingRegistration Success(string id, string pin, HttpStatusCode code) =>
            new(true, ApplicationRegistrationState.Pending, id, pin, null, code);

        public static PendingRegistration Failure(ApplicationRegistrationState state, string error, HttpStatusCode? code = null) =>
            new(false, state, null, null, error, code);
    }

    private sealed record CredentialRetrieval(
        bool Succeeded,
        ApplicationRegistrationState State,
        string? Credential,
        string? Error,
        HttpStatusCode? StatusCode)
    {
        public static CredentialRetrieval Success(string credential, HttpStatusCode code) =>
            new(true, ApplicationRegistrationState.Registered, credential, null, code);

        public static CredentialRetrieval Pending(HttpStatusCode code) =>
            new(false, ApplicationRegistrationState.Pending, null, null, code);

        public static CredentialRetrieval Failure(ApplicationRegistrationState state, string error, HttpStatusCode? code = null) =>
            new(false, state, null, error, code);
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
