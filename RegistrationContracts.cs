using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;

namespace Common.Registration;

public sealed record ApplicationPresentationMetadata(
    string? IconUrl = null,
    string? ShortName = null,
    string? Accent = null)
{
    public string FallbackInitials(string applicationId, string? displayName = null)
    {
        string source = string.IsNullOrWhiteSpace(ShortName)
            ? (string.IsNullOrWhiteSpace(displayName) ? applicationId : displayName!)
            : ShortName!;

        string[] words = source
            .Replace("Aegis.", string.Empty, StringComparison.OrdinalIgnoreCase)
            .Replace("Aegis ", string.Empty, StringComparison.OrdinalIgnoreCase)
            .Split([' ', '.', '-', '_'], StringSplitOptions.RemoveEmptyEntries);

        if (words.Length == 0) return "AE";
        if (words.Length == 1) return words[0][..Math.Min(2, words[0].Length)].ToUpperInvariant();
        return string.Concat(words.Take(2).Select(x => char.ToUpperInvariant(x[0])));
    }

    public static bool IsSafeIconUrl(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return true;
        string icon = value.Trim();
        if (icon.StartsWith("/", StringComparison.Ordinal) && !icon.StartsWith("//", StringComparison.Ordinal))
            return !icon.Contains("..", StringComparison.Ordinal);
        return Uri.TryCreate(icon, UriKind.Absolute, out Uri? uri) &&
               uri.Scheme == Uri.UriSchemeHttps;
    }
}

public enum ControlPlaneRegistrationState
{
    Registered = 0,
    MissingCredential = 1,
    InvalidCredential = 2,
    Unavailable = 3
}

public sealed record ControlPlaneRegistrationStatus(
    ControlPlaneRegistrationState State,
    DateTimeOffset AttemptedAtUtc,
    string? Error = null,
    HttpStatusCode? StatusCode = null)
{
    public bool IsRegistered => State == ControlPlaneRegistrationState.Registered;
}

public sealed record ControlPlaneRegistrationOptions(
    Uri OperationsBaseUri,
    string ApplicationId,
    string InstanceId,
    string CredentialFilePath,
    TimeSpan? RequestTimeout = null);

/// <summary>
/// Bootstrap client reserved for the trusted Aegis control plane
/// (Operations, Configuration and Diagnostics).
///
/// This is deliberately separate from the normal application registration lifecycle.
/// It never reads registration credentials from environment variables, appsettings,
/// source-controlled configuration or a secret provider. The issued bootstrap
/// credential is persisted only in the protected local credential file.
/// </summary>
public sealed class ControlPlaneRegistrationClient
{
    private static readonly string[] AllowedApplications =
    [
        "Aegis.Operations",
        "Aegis.Configuration",
        "Aegis.Diagnostics"
    ];

    private readonly HttpClient _http;
    private readonly ControlPlaneRegistrationOptions _options;
    private readonly ILogger _logger;

    public ControlPlaneRegistrationClient(
        HttpClient http,
        ControlPlaneRegistrationOptions options,
        ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(options);

        if (!AllowedApplications.Contains(options.ApplicationId, StringComparer.OrdinalIgnoreCase))
            throw new ArgumentException(
                "Control-plane bootstrap is restricted to Operations, Configuration and Diagnostics.",
                nameof(options));

        if (string.IsNullOrWhiteSpace(options.InstanceId))
            throw new ArgumentException("Instance id is required.", nameof(options));

        if (string.IsNullOrWhiteSpace(options.CredentialFilePath))
            throw new ArgumentException("Credential file path is required.", nameof(options));

        if (!options.OperationsBaseUri.IsAbsoluteUri)
            throw new ArgumentException("Operations base URI must be absolute.", nameof(options));

        if (options.OperationsBaseUri.Scheme != Uri.UriSchemeHttps &&
            !options.OperationsBaseUri.IsLoopback)
        {
            throw new ArgumentException(
                "Control-plane bootstrap requires HTTPS except for loopback endpoints.",
                nameof(options));
        }

        _http = http;
        _options = options;
        _logger = logger ?? Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance;
        _http.BaseAddress = new Uri(options.OperationsBaseUri.AbsoluteUri.TrimEnd('/') + "/");
        _http.Timeout = options.RequestTimeout ?? TimeSpan.FromSeconds(10);
    }

    public async Task<ControlPlaneRegistrationStatus> RegisterAsync(
        JsonObject contract,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(contract);

        string attemptId = Guid.NewGuid().ToString("N");
        using IDisposable? scope = _logger.BeginScope(new Dictionary<string, object?>
        {
            ["Activity"] = "ControlPlaneRegistration",
            ["ApplicationId"] = _options.ApplicationId,
            ["InstanceId"] = _options.InstanceId,
            ["CorrelationId"] = attemptId
        });

        string? credential = await ReadCredentialAsync(cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(credential))
        {
            _logger.LogInformation("No local control-plane credential exists; requesting restricted bootstrap.");
            credential = await ProvisionAsync(cancellationToken).ConfigureAwait(false);
        }

        if (string.IsNullOrWhiteSpace(credential))
        {
            return new(
                ControlPlaneRegistrationState.MissingCredential,
                DateTimeOffset.UtcNow,
                "Control-plane bootstrap did not provide a credential.");
        }

        try
        {
            HttpResponseMessage response = await SendContractAsync(
                credential,
                contract,
                attemptId,
                cancellationToken).ConfigureAwait(false);

            if (response.StatusCode is HttpStatusCode.Unauthorized or
                HttpStatusCode.Forbidden or
                HttpStatusCode.Gone)
            {
                response.Dispose();

                _logger.LogWarning(
                    "Stored control-plane credential was rejected; performing one controlled local rotation.");

                await DeleteCredentialAsync().ConfigureAwait(false);
                credential = await ProvisionAsync(cancellationToken).ConfigureAwait(false);

                if (string.IsNullOrWhiteSpace(credential))
                {
                    return new(
                        ControlPlaneRegistrationState.InvalidCredential,
                        DateTimeOffset.UtcNow,
                        "Control-plane credential rotation failed.");
                }

                response = await SendContractAsync(
                    credential,
                    contract,
                    attemptId,
                    cancellationToken).ConfigureAwait(false);
            }

            using (response)
            {
                if (response.IsSuccessStatusCode)
                {
                    _logger.LogInformation("Control-plane registration is active.");
                    return new(
                        ControlPlaneRegistrationState.Registered,
                        DateTimeOffset.UtcNow,
                        StatusCode: response.StatusCode);
                }

                ControlPlaneRegistrationState state =
                    response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden
                        ? ControlPlaneRegistrationState.InvalidCredential
                        : ControlPlaneRegistrationState.Unavailable;

                return new(
                    state,
                    DateTimeOffset.UtcNow,
                    $"Operations rejected control-plane registration with HTTP {(int)response.StatusCode}.",
                    response.StatusCode);
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new(
                ControlPlaneRegistrationState.Unavailable,
                DateTimeOffset.UtcNow,
                "Control-plane registration timed out.");
        }
        catch (HttpRequestException ex)
        {
            _logger.LogWarning(ex, "Control-plane registration request failed.");
            return new(
                ControlPlaneRegistrationState.Unavailable,
                DateTimeOffset.UtcNow,
                $"Control-plane registration is unavailable: {ex.Message}");
        }
    }

    private async Task<string?> ProvisionAsync(CancellationToken cancellationToken)
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
                "Restricted control-plane bootstrap was rejected with HTTP {StatusCode}.",
                (int)response.StatusCode);
            return null;
        }

        ControlPlaneCredentialResponse? result =
            await response.Content.ReadFromJsonAsync<ControlPlaneCredentialResponse>(
                cancellationToken: cancellationToken).ConfigureAwait(false);

        if (string.IsNullOrWhiteSpace(result?.Credential))
            return null;

        string credential = result.Credential.Trim();
        await WriteCredentialAsync(credential, cancellationToken).ConfigureAwait(false);
        return credential;
    }

    private async Task<HttpResponseMessage> SendContractAsync(
        string credential,
        JsonObject contract,
        string attemptId,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "api/registration/contracts")
        {
            Content = JsonContent.Create(ConfigurationContractPolicy.MetadataOnly(contract))
        };

        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", credential);
        request.Headers.TryAddWithoutValidation("X-Aegis-Application-Id", _options.ApplicationId);
        request.Headers.TryAddWithoutValidation("X-Aegis-Instance-Id", _options.InstanceId);
        request.Headers.TryAddWithoutValidation("X-Aegis-Registration-Attempt-Id", attemptId);

        return await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }

    private async Task<string?> ReadCredentialAsync(CancellationToken cancellationToken)
    {
        string path = Path.GetFullPath(_options.CredentialFilePath);
        if (!File.Exists(path))
            return null;

        string value = (await File.ReadAllTextAsync(path, cancellationToken).ConfigureAwait(false)).Trim();
        return string.IsNullOrWhiteSpace(value) ? null : value;
    }

    private async Task WriteCredentialAsync(
        string credential,
        CancellationToken cancellationToken)
    {
        string path = Path.GetFullPath(_options.CredentialFilePath);
        string? directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrWhiteSpace(directory))
            Directory.CreateDirectory(directory);

        string temp = path + ".tmp-" + Guid.NewGuid().ToString("N");
        await File.WriteAllTextAsync(temp, credential + Environment.NewLine, cancellationToken)
            .ConfigureAwait(false);

        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(temp, UnixFileMode.UserRead | UnixFileMode.UserWrite);

        File.Move(temp, path, true);

        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    private Task DeleteCredentialAsync()
    {
        string path = Path.GetFullPath(_options.CredentialFilePath);
        if (File.Exists(path))
            File.Delete(path);
        return Task.CompletedTask;
    }

    private sealed record ControlPlaneCredentialResponse(string Credential);
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
