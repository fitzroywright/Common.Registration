using Common.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;

namespace Common.Registration;

public enum RegistrationLifecycleState
{
    Unregistered = 0,
    Pending = 1,
    Registered = 2,
    RecoveryPending = 3,
    Revoked = 4,
    IdentityConflict = 5,
    Rejected = 6,
    Error = 7
}

public sealed record RegistrationIdentity(
    string ApplicationId,
    string InstanceId,
    string InstallationId);

public sealed record RegistrationIdentityDocument(
    string ApplicationId,
    string InstanceId,
    string InstallationId,
    string? RegistrationId,
    string? ClaimToken,
    string? Credential,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc);

public sealed record RegistrationLifecycleStatus(
    RegistrationLifecycleState State,
    RegistrationIdentity Identity,
    DateTimeOffset ObservedAtUtc,
    string? RegistrationId = null,
    string? Error = null,
    HttpStatusCode? StatusCode = null,
    string? CorrelationId = null)
{
    public bool IsRegistered => State == RegistrationLifecycleState.Registered;
}

public sealed record RegistrationLifecycleOptions(
    Uri ConfigurationBaseUri,
    string ApplicationId,
    string InstanceId,
    string IdentityFilePath,
    TimeSpan? RequestTimeout = null,
    string? RunbookReference = null);

public interface IRegistrationIdentityStore
{
    Task<RegistrationIdentityDocument> LoadOrCreateAsync(
        string applicationId,
        string instanceId,
        CancellationToken cancellationToken = default);

    Task SaveAsync(
        RegistrationIdentityDocument document,
        CancellationToken cancellationToken = default);
}

public sealed class FileRegistrationIdentityStore : IRegistrationIdentityStore
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    private readonly string _path;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public FileRegistrationIdentityStore(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException("Identity file path is required.", nameof(path));

        _path = Path.GetFullPath(path);
    }

    public async Task<RegistrationIdentityDocument> LoadOrCreateAsync(
        string applicationId,
        string instanceId,
        CancellationToken cancellationToken = default)
    {
        ValidateIdentity(applicationId, instanceId);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (File.Exists(_path))
            {
                RegistrationIdentityDocument? existing;
                if (OperatingSystem.IsWindows())
                {
                    byte[] protectedBytes =
                        await File.ReadAllBytesAsync(_path, cancellationToken).ConfigureAwait(false);
                    byte[] jsonBytes = ProtectedData.Unprotect(
                        protectedBytes,
                        optionalEntropy: null,
                        DataProtectionScope.CurrentUser);
                    existing = JsonSerializer.Deserialize<RegistrationIdentityDocument>(
                        jsonBytes,
                        JsonOptions);
                    CryptographicOperations.ZeroMemory(jsonBytes);
                }
                else
                {
                    await using FileStream stream = File.OpenRead(_path);
                    existing =
                        await JsonSerializer.DeserializeAsync<RegistrationIdentityDocument>(
                            stream,
                            JsonOptions,
                            cancellationToken).ConfigureAwait(false);
                }

                if (existing is null)
                    throw new InvalidOperationException("Registration identity file is empty or invalid.");

                if (!string.Equals(existing.ApplicationId, applicationId, StringComparison.Ordinal) ||
                    !string.Equals(existing.InstanceId, instanceId, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(
                        "Registration identity file belongs to a different ApplicationId/InstanceId.");
                }

                return existing;
            }

            DateTimeOffset now = DateTimeOffset.UtcNow;
            var created = new RegistrationIdentityDocument(
                applicationId,
                instanceId,
                Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant(),
                null,
                null,
                null,
                now,
                now);

            await SaveUnsafeAsync(created, cancellationToken).ConfigureAwait(false);
            return created;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task SaveAsync(
        RegistrationIdentityDocument document,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(document);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await SaveUnsafeAsync(
                document with { UpdatedAtUtc = DateTimeOffset.UtcNow },
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task SaveUnsafeAsync(
        RegistrationIdentityDocument document,
        CancellationToken cancellationToken)
    {
        string? directory = Path.GetDirectoryName(_path);
        if (!string.IsNullOrWhiteSpace(directory))
            Directory.CreateDirectory(directory);

        string temporary = _path + ".tmp-" + Guid.NewGuid().ToString("N");

        if (OperatingSystem.IsWindows())
        {
            byte[] jsonBytes = JsonSerializer.SerializeToUtf8Bytes(document, JsonOptions);
            byte[] protectedBytes = ProtectedData.Protect(
                jsonBytes,
                optionalEntropy: null,
                DataProtectionScope.CurrentUser);
            try
            {
                await File.WriteAllBytesAsync(
                    temporary,
                    protectedBytes,
                    cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(jsonBytes);
                CryptographicOperations.ZeroMemory(protectedBytes);
            }
        }
        else
        {
            await using FileStream stream = new(
                temporary,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                4096,
                FileOptions.WriteThrough);
            await JsonSerializer.SerializeAsync(
                stream,
                document,
                JsonOptions,
                cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            File.SetUnixFileMode(temporary, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        File.Move(temporary, _path, true);

        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(_path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    private static void ValidateIdentity(string applicationId, string instanceId)
    {
        if (string.IsNullOrWhiteSpace(applicationId))
            throw new ArgumentException("Application id is required.", nameof(applicationId));
        if (string.IsNullOrWhiteSpace(instanceId))
            throw new ArgumentException("Instance id is required.", nameof(instanceId));
    }
}

public sealed class RegistrationLifecycleClient
{
    private readonly HttpClient _http;
    private readonly RegistrationLifecycleOptions _options;
    private readonly IRegistrationIdentityStore _identityStore;
    private readonly ILogger _logger;
    private readonly ILifecycleEventSink _lifecycle;

    public RegistrationLifecycleClient(
        HttpClient http,
        RegistrationLifecycleOptions options,
        IRegistrationIdentityStore? identityStore = null,
        ILogger? logger = null,
        ILifecycleEventSink? lifecycleEventSink = null)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(options);

        if (!options.ConfigurationBaseUri.IsAbsoluteUri)
            throw new ArgumentException("Configuration base URI must be absolute.", nameof(options));
        if (options.ConfigurationBaseUri.Scheme != Uri.UriSchemeHttps && !options.ConfigurationBaseUri.IsLoopback)
            throw new ArgumentException("Registration requires HTTPS except for loopback development endpoints.", nameof(options));

        _http = http;
        _options = options;
        _identityStore = identityStore ?? new FileRegistrationIdentityStore(options.IdentityFilePath);
        _logger = logger ?? Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance;
        _lifecycle = lifecycleEventSink ?? new NullLifecycleEventSink();
        _http.BaseAddress = new Uri(options.ConfigurationBaseUri.AbsoluteUri.TrimEnd('/') + "/");
        _http.Timeout = options.RequestTimeout ?? TimeSpan.FromSeconds(10);
    }

    public async Task<RegistrationLifecycleStatus> StepAsync(
        JsonObject? metadata = null,
        CancellationToken cancellationToken = default)
    {
        RegistrationIdentityDocument document =
            await _identityStore.LoadOrCreateAsync(
                _options.ApplicationId,
                _options.InstanceId,
                cancellationToken).ConfigureAwait(false);

        var identity = new RegistrationIdentity(
            document.ApplicationId,
            document.InstanceId,
            document.InstallationId);

        string correlationId = Guid.NewGuid().ToString("N");
        using IDisposable? scope = _logger.BeginScope(new Dictionary<string, object?>
        {
            ["Activity"] = "Registration",
            ["ApplicationId"] = identity.ApplicationId,
            ["InstanceId"] = identity.InstanceId,
            ["InstallationId"] = identity.InstallationId,
            ["CorrelationId"] = correlationId
        });

        await EmitLifecycleAsync(identity, "Step", LifecycleEventOutcome.Started, correlationId, null, cancellationToken).ConfigureAwait(false);

        if (!string.IsNullOrWhiteSpace(document.Credential))
        {
            RegistrationLifecycleStatus authenticated =
                await AuthenticateAsync(document, identity, correlationId, cancellationToken).ConfigureAwait(false);

            if (authenticated.State != RegistrationLifecycleState.Unregistered)
                return await CompleteAsync(identity, authenticated, correlationId, cancellationToken).ConfigureAwait(false);

            document = await _identityStore.LoadOrCreateAsync(
                _options.ApplicationId,
                _options.InstanceId,
                cancellationToken).ConfigureAwait(false);
        }

        if (!string.IsNullOrWhiteSpace(document.RegistrationId) &&
            !string.IsNullOrWhiteSpace(document.ClaimToken))
        {
            RegistrationLifecycleStatus claimed =
                await TryClaimAsync(document, identity, correlationId, cancellationToken).ConfigureAwait(false);

            if (claimed.State == RegistrationLifecycleState.Error &&
                claimed.StatusCode == HttpStatusCode.Unauthorized)
            {
                document = document with { ClaimToken = null };
                await _identityStore.SaveAsync(document, cancellationToken).ConfigureAwait(false);

                _logger.LogWarning(
                    "Registration claim is no longer usable; requesting explicit credential recovery.");

                RegistrationLifecycleStatus recovery = await RequestRecoveryAsync(
                    document,
                    identity,
                    correlationId,
                    cancellationToken).ConfigureAwait(false);
                return await CompleteAsync(identity, recovery, correlationId, cancellationToken).ConfigureAwait(false);
            }

            if (claimed.State != RegistrationLifecycleState.Error ||
                claimed.StatusCode != HttpStatusCode.NotFound)
                return await CompleteAsync(identity, claimed, correlationId, cancellationToken).ConfigureAwait(false);

            // A missing server-side registration means the authoritative record was purged.
            // Only then is a fresh introduction appropriate.
            document = document with { RegistrationId = null, ClaimToken = null };
            await _identityStore.SaveAsync(document, cancellationToken).ConfigureAwait(false);
        }

        if (!string.IsNullOrWhiteSpace(document.RegistrationId))
        {
            // The installation has an established identity but no usable credential.
            // This is recovery, never a second normal registration.
            RegistrationLifecycleStatus recovery = await RequestRecoveryAsync(
                document,
                identity,
                correlationId,
                cancellationToken).ConfigureAwait(false);
            return await CompleteAsync(identity, recovery, correlationId, cancellationToken).ConfigureAwait(false);
        }

        RegistrationLifecycleStatus requested = await RequestRegistrationAsync(
            document,
            identity,
            metadata,
            correlationId,
            cancellationToken).ConfigureAwait(false);
        return await CompleteAsync(identity, requested, correlationId, cancellationToken).ConfigureAwait(false);
    }

    private async Task<RegistrationLifecycleStatus> CompleteAsync(
        RegistrationIdentity identity,
        RegistrationLifecycleStatus status,
        string correlationId,
        CancellationToken cancellationToken)
    {
        LifecycleEventOutcome outcome = status.State switch
        {
            RegistrationLifecycleState.Registered => LifecycleEventOutcome.Succeeded,
            RegistrationLifecycleState.Error or RegistrationLifecycleState.IdentityConflict or RegistrationLifecycleState.Rejected => LifecycleEventOutcome.Failed,
            _ => LifecycleEventOutcome.Warning
        };

        await EmitLifecycleAsync(identity, status.State.ToString(), outcome, status.CorrelationId ?? correlationId, status.RegistrationId, cancellationToken).ConfigureAwait(false);
        return status;
    }

    private async Task EmitLifecycleAsync(
        RegistrationIdentity identity,
        string stage,
        LifecycleEventOutcome outcome,
        string correlationId,
        string? registrationId,
        CancellationToken cancellationToken)
    {
        try
        {
            await _lifecycle.EmitAsync(
                LifecycleEvent.Create(
                    identity.ApplicationId,
                    identity.InstanceId,
                    "Registration",
                    stage,
                    outcome,
                    correlationId,
                    relatedBusinessId: registrationId),
                cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Registration lifecycle telemetry emission failed; registration continues.");
        }
    }

    public async Task<HttpStatusCode> PublishConfigurationContractAsync(
        JsonObject contract,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(contract);

        RegistrationIdentityDocument document =
            await _identityStore.LoadOrCreateAsync(
                _options.ApplicationId,
                _options.InstanceId,
                cancellationToken).ConfigureAwait(false);

        if (string.IsNullOrWhiteSpace(document.Credential))
            return HttpStatusCode.Unauthorized;

        string correlationId = Guid.NewGuid().ToString("N");
        using var request = new HttpRequestMessage(HttpMethod.Post, "api/contracts/register")
        {
            Content = JsonContent.Create(ConfigurationContractPolicy.MetadataOnly(contract))
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", document.Credential);
        request.Headers.TryAddWithoutValidation("X-Aegis-Application-Id", document.ApplicationId);
        request.Headers.TryAddWithoutValidation("X-Aegis-Instance-Id", document.InstanceId);
        request.Headers.TryAddWithoutValidation("X-Aegis-Installation-Id", document.InstallationId);
        request.Headers.TryAddWithoutValidation("X-Aegis-Correlation-Id", correlationId);

        var identity = new RegistrationIdentity(
            document.ApplicationId,
            document.InstanceId,
            document.InstallationId);

        await EmitLifecycleAsync(
            identity,
            "ConfigurationContract",
            LifecycleEventOutcome.Started,
            correlationId,
            document.RegistrationId,
            cancellationToken).ConfigureAwait(false);

        try
        {
            using HttpResponseMessage response =
                await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);

            if (response.IsSuccessStatusCode)
            {
                _logger.LogInformation(
                    "Configuration contract published through authenticated durable identity.");

                await EmitLifecycleAsync(
                    identity,
                    "ConfigurationContractPublished",
                    LifecycleEventOutcome.Succeeded,
                    correlationId,
                    document.RegistrationId,
                    cancellationToken).ConfigureAwait(false);
            }
            else
            {
                _logger.LogWarning(
                    "Configuration contract publication failed with HTTP {StatusCode}.",
                    (int)response.StatusCode);

                await EmitLifecycleAsync(
                    identity,
                    "ConfigurationContract",
                    LifecycleEventOutcome.Failed,
                    correlationId,
                    document.RegistrationId,
                    cancellationToken).ConfigureAwait(false);
            }

            return response.StatusCode;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            _logger.LogWarning(
                "Configuration contract publication failed because Configuration is unavailable: {FailureType}.",
                ex.GetType().Name);

            await EmitLifecycleAsync(
                identity,
                "ConfigurationContract",
                LifecycleEventOutcome.Failed,
                correlationId,
                document.RegistrationId,
                cancellationToken).ConfigureAwait(false);

            throw;
        }
    }

    private async Task<RegistrationLifecycleStatus> RequestRegistrationAsync(
        RegistrationIdentityDocument document,
        RegistrationIdentity identity,
        JsonObject? metadata,
        string correlationId,
        CancellationToken cancellationToken)
    {
        _logger.LogInformation("Submitting zero-trust registration introduction.");

        using var request = new HttpRequestMessage(HttpMethod.Post, "api/registration/request")
        {
            Content = JsonContent.Create(new
            {
                identity.ApplicationId,
                identity.InstanceId,
                identity.InstallationId,
                runbookReference = string.IsNullOrWhiteSpace(_options.RunbookReference)
                    ? null
                    : _options.RunbookReference.Trim(),
                metadata
            })
        };
        request.Headers.TryAddWithoutValidation("X-Aegis-Correlation-Id", correlationId);

        using HttpResponseMessage response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);

        RegistrationRequestResponse? payload =
            await ReadJsonOrDefaultAsync<RegistrationRequestResponse>(response, cancellationToken).ConfigureAwait(false);

        if (response.StatusCode == HttpStatusCode.Conflict &&
            string.Equals(payload?.State, "IdentityConflict", StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning("Registration identity conflict detected.");
            return Status(RegistrationLifecycleState.IdentityConflict, identity, payload?.RegistrationId,
                payload?.Error ?? "The logical instance is already bound to a different InstallationId.",
                response.StatusCode, correlationId);
        }

        if (!response.IsSuccessStatusCode)
        {
            return Status(RegistrationLifecycleState.Error, identity, payload?.RegistrationId,
                payload?.Error ?? $"Configuration rejected registration request with HTTP {(int)response.StatusCode}.",
                response.StatusCode, correlationId);
        }

        if (payload is null ||
            string.IsNullOrWhiteSpace(payload.RegistrationId) ||
            string.IsNullOrWhiteSpace(payload.ClaimToken))
        {
            return Status(RegistrationLifecycleState.Error, identity, null,
                "Configuration accepted the request but did not return a claim handle.",
                response.StatusCode, correlationId);
        }

        await _identityStore.SaveAsync(document with
        {
            RegistrationId = payload.RegistrationId,
            ClaimToken = payload.ClaimToken
        }, cancellationToken).ConfigureAwait(false);

        _logger.LogInformation("Registration is pending administrator approval. RegistrationId={RegistrationId}.",
            payload.RegistrationId);

        return Status(
            RegistrationLifecycleState.Pending,
            identity,
            payload.RegistrationId,
            null,
            response.StatusCode,
            correlationId);
    }

    private async Task<RegistrationLifecycleStatus> TryClaimAsync(
        RegistrationIdentityDocument document,
        RegistrationIdentity identity,
        string correlationId,
        CancellationToken cancellationToken)
    {
        _logger.LogInformation("Checking pending registration claim state.");

        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            $"api/registration/{Uri.EscapeDataString(document.RegistrationId!)}/claim")
        {
            Content = JsonContent.Create(new
            {
                identity.ApplicationId,
                identity.InstanceId,
                identity.InstallationId,
                claimToken = document.ClaimToken
            })
        };
        request.Headers.TryAddWithoutValidation("X-Aegis-Correlation-Id", correlationId);

        using HttpResponseMessage response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);

        ClaimResponse? payload =
            await ReadJsonOrDefaultAsync<ClaimResponse>(response, cancellationToken).ConfigureAwait(false);

        if (response.StatusCode == HttpStatusCode.Accepted)
            return Status(RegistrationLifecycleState.Pending, identity, document.RegistrationId, null,
                response.StatusCode, correlationId);

        if (response.StatusCode == HttpStatusCode.Forbidden)
            return Status(RegistrationLifecycleState.Rejected, identity, document.RegistrationId,
                payload?.Error ?? "Registration was rejected.", response.StatusCode, correlationId);

        if (response.StatusCode == HttpStatusCode.Conflict &&
            string.Equals(payload?.State, "IdentityConflict", StringComparison.OrdinalIgnoreCase))
            return Status(RegistrationLifecycleState.IdentityConflict, identity, document.RegistrationId,
                payload?.Error ?? "Installation identity conflict.", response.StatusCode, correlationId);

        if (!response.IsSuccessStatusCode)
            return Status(RegistrationLifecycleState.Error, identity, document.RegistrationId,
                payload?.Error ?? $"Claim failed with HTTP {(int)response.StatusCode}.",
                response.StatusCode, correlationId);

        if (string.IsNullOrWhiteSpace(payload?.Credential))
            return Status(RegistrationLifecycleState.Error, identity, document.RegistrationId,
                "Approved claim did not contain a credential.", response.StatusCode, correlationId);

        await _identityStore.SaveAsync(document with
        {
            Credential = payload.Credential,
            ClaimToken = null
        }, cancellationToken).ConfigureAwait(false);

        _logger.LogInformation("Credential claimed and stored in the protected local identity store.");

        return Status(RegistrationLifecycleState.Registered, identity, document.RegistrationId,
            null, response.StatusCode, correlationId);
    }

    private async Task<RegistrationLifecycleStatus> AuthenticateAsync(
        RegistrationIdentityDocument document,
        RegistrationIdentity identity,
        string correlationId,
        CancellationToken cancellationToken)
    {
        _logger.LogInformation("Authenticating durable application identity.");

        using var request = new HttpRequestMessage(HttpMethod.Post, "api/registration/authenticate");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", document.Credential);
        request.Headers.TryAddWithoutValidation("X-Aegis-Application-Id", identity.ApplicationId);
        request.Headers.TryAddWithoutValidation("X-Aegis-Instance-Id", identity.InstanceId);
        request.Headers.TryAddWithoutValidation("X-Aegis-Installation-Id", identity.InstallationId);
        request.Headers.TryAddWithoutValidation("X-Aegis-Correlation-Id", correlationId);

        using HttpResponseMessage response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        AuthenticationResponse? payload =
            await ReadJsonOrDefaultAsync<AuthenticationResponse>(response, cancellationToken).ConfigureAwait(false);

        if (response.IsSuccessStatusCode)
        {
            _logger.LogInformation("Durable identity authenticated.");
            return Status(RegistrationLifecycleState.Registered, identity,
                payload?.RegistrationId ?? document.RegistrationId, null, response.StatusCode, correlationId);
        }

        if (response.StatusCode == HttpStatusCode.Conflict)
            return Status(RegistrationLifecycleState.IdentityConflict, identity, document.RegistrationId,
                payload?.Error ?? "Installation identity conflict.", response.StatusCode, correlationId);

        if (response.StatusCode == HttpStatusCode.Gone)
            return Status(RegistrationLifecycleState.Revoked, identity, document.RegistrationId,
                payload?.Error ?? "Registration credential is revoked.", response.StatusCode, correlationId);

        if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
        {
            RegistrationLifecycleStatus recovery =
                await RequestRecoveryAsync(
                    document,
                    identity,
                    correlationId,
                    cancellationToken).ConfigureAwait(false);

            if (recovery.State == RegistrationLifecycleState.Error &&
                recovery.StatusCode == HttpStatusCode.NotFound)
            {
                await _identityStore.SaveAsync(document with
                {
                    RegistrationId = null,
                    ClaimToken = null,
                    Credential = null
                }, cancellationToken).ConfigureAwait(false);

                _logger.LogWarning(
                    "Server-side registration no longer exists; preserving InstallationId and returning to zero-trust introduction.");

                return Status(
                    RegistrationLifecycleState.Unregistered,
                    identity,
                    null,
                    "Server-side registration was purged; a fresh pending registration is required.",
                    HttpStatusCode.NotFound,
                    correlationId);
            }

            return recovery;
        }

        return Status(RegistrationLifecycleState.Error, identity, document.RegistrationId,
            payload?.Error ?? $"Authentication failed with HTTP {(int)response.StatusCode}.",
            response.StatusCode, correlationId);
    }

    private async Task<RegistrationLifecycleStatus> RequestRecoveryAsync(
        RegistrationIdentityDocument document,
        RegistrationIdentity identity,
        string correlationId,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "api/registration/recovery")
        {
            Content = JsonContent.Create(new
            {
                identity.ApplicationId,
                identity.InstanceId,
                identity.InstallationId,
                document.RegistrationId
            })
        };
        request.Headers.TryAddWithoutValidation("X-Aegis-Correlation-Id", correlationId);

        using HttpResponseMessage response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        RegistrationRequestResponse? payload =
            await ReadJsonOrDefaultAsync<RegistrationRequestResponse>(response, cancellationToken).ConfigureAwait(false);

        if (response.StatusCode == HttpStatusCode.Conflict &&
            string.Equals(payload?.State, "IdentityConflict", StringComparison.OrdinalIgnoreCase))
            return Status(RegistrationLifecycleState.IdentityConflict, identity, document.RegistrationId,
                payload?.Error ?? "Installation identity conflict.", response.StatusCode, correlationId);

        if (!response.IsSuccessStatusCode ||
            string.IsNullOrWhiteSpace(payload?.RegistrationId) ||
            string.IsNullOrWhiteSpace(payload.ClaimToken))
        {
            return Status(RegistrationLifecycleState.Error, identity, document.RegistrationId,
                payload?.Error ?? $"Credential recovery request failed with HTTP {(int)response.StatusCode}.",
                response.StatusCode, correlationId);
        }

        await _identityStore.SaveAsync(document with
        {
            Credential = null,
            RegistrationId = payload.RegistrationId,
            ClaimToken = payload.ClaimToken
        }, cancellationToken).ConfigureAwait(false);

        _logger.LogWarning("Credential recovery is pending administrator approval.");

        return Status(RegistrationLifecycleState.RecoveryPending, identity, payload.RegistrationId,
            null, response.StatusCode, correlationId);
    }

    private static RegistrationLifecycleStatus Status(
        RegistrationLifecycleState state,
        RegistrationIdentity identity,
        string? registrationId,
        string? error,
        HttpStatusCode? statusCode,
        string correlationId)
        => new(state, identity, DateTimeOffset.UtcNow, registrationId, error, statusCode, correlationId);

    private static async Task<T?> ReadJsonOrDefaultAsync<T>(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        if (response.Content.Headers.ContentLength == 0)
            return default;

        try
        {
            return await response.Content.ReadFromJsonAsync<T>(
                cancellationToken: cancellationToken).ConfigureAwait(false);
        }
        catch (JsonException)
        {
            return default;
        }
    }

    private sealed record RegistrationRequestResponse(
        string? RegistrationId,
        string? ClaimToken,
        string? State,
        string? Error);

    private sealed record ClaimResponse(
        string? RegistrationId,
        string? Credential,
        string? State,
        string? Error);

    private sealed record AuthenticationResponse(
        string? RegistrationId,
        string? State,
        string? Error);
}
