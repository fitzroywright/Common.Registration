using Common.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json.Nodes;

namespace Common.Registration;

public sealed class RegistrationConfigurationLevelXTest(RegistrationLifecycleOptions options) : ILevelXLocalTest
{
    private readonly RegistrationLifecycleOptions options = options ?? throw new ArgumentNullException(nameof(options));
    public string TestId => "COMMON.REGISTRATION.L5.CONFIG.VALID";
    public string Name => "Registration configuration valid";
    public string Owner => "Common.Registration";
    public EngineeringDiagnosticLevel Level => EngineeringDiagnosticLevel.Level5Scan;
    public bool IsDestructive => false;

    public Task<EngineeringDiagnosticCheckResult> RunAsync(CancellationToken cancellationToken)
    {
        List<string> invalid = [];
        if (!options.ConfigurationBaseUri.IsAbsoluteUri) invalid.Add(nameof(options.ConfigurationBaseUri));
        else if (options.ConfigurationBaseUri.Scheme != Uri.UriSchemeHttps && !options.ConfigurationBaseUri.IsLoopback)
            invalid.Add("ConfigurationBaseUri.Https");
        if (string.IsNullOrWhiteSpace(options.ApplicationId)) invalid.Add(nameof(options.ApplicationId));
        if (string.IsNullOrWhiteSpace(options.InstanceId)) invalid.Add(nameof(options.InstanceId));
        if (string.IsNullOrWhiteSpace(options.IdentityFilePath)) invalid.Add(nameof(options.IdentityFilePath));
        if (options.RequestTimeout is { } timeout && timeout <= TimeSpan.Zero) invalid.Add(nameof(options.RequestTimeout));

        return Task.FromResult(invalid.Count == 0
            ? EngineeringDiagnosticPolicy.Passed(TestId, Name, "Registration configuration is valid.")
            : EngineeringDiagnosticPolicy.Failed(TestId, Name, "Registration configuration contains invalid values.", $"Invalid={string.Join(",", invalid)}"));
    }
}

public sealed class RegistrationIdentityFileLevelXTest(RegistrationLifecycleOptions options) : ILevelXLocalTest
{
    private readonly RegistrationLifecycleOptions options = options ?? throw new ArgumentNullException(nameof(options));
    public string TestId => "COMMON.REGISTRATION.L4.IDENTITY.FILE";
    public string Name => "Registration identity file state";
    public string Owner => "Common.Registration";
    public EngineeringDiagnosticLevel Level => EngineeringDiagnosticLevel.Level4Analysis;
    public bool IsDestructive => false;

    public Task<EngineeringDiagnosticCheckResult> RunAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        string path = Path.GetFullPath(options.IdentityFilePath);
        if (!File.Exists(path))
            return Task.FromResult(EngineeringDiagnosticPolicy.Warning(TestId, Name, "Registration identity file does not yet exist.", $"Path={path}"));

        try
        {
            FileInfo info = new(path);
            if (info.Length <= 0)
                return Task.FromResult(EngineeringDiagnosticPolicy.Failed(TestId, Name, "Registration identity file is empty.", $"Path={path}"));

            if (!OperatingSystem.IsWindows())
            {
                UnixFileMode mode = File.GetUnixFileMode(path);
                UnixFileMode disallowed = UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
                                          UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;
                if ((mode & disallowed) != 0)
                    return Task.FromResult(EngineeringDiagnosticPolicy.Failed(TestId, Name, "Registration identity file permissions are too broad.", $"Mode={mode}"));
            }

            return Task.FromResult(EngineeringDiagnosticPolicy.Passed(TestId, Name, "Registration identity file exists and basic protection checks passed.", $"Bytes={info.Length}"));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Task.FromResult(EngineeringDiagnosticPolicy.Failed(TestId, Name, "Registration identity file could not be inspected.", $"FailureType={ex.GetType().Name}"));
        }
    }
}

public sealed class RegistrationConfigurationDnsLevelXTest(RegistrationLifecycleOptions options) : ILevelXLocalTest
{
    private readonly RegistrationLifecycleOptions options = options ?? throw new ArgumentNullException(nameof(options));
    public string TestId => "COMMON.REGISTRATION.L4.CONFIGURATION.DNS";
    public string Name => "Configuration endpoint DNS resolves";
    public string Owner => "Common.Registration";
    public EngineeringDiagnosticLevel Level => EngineeringDiagnosticLevel.Level4Analysis;
    public bool IsDestructive => false;

    public async Task<EngineeringDiagnosticCheckResult> RunAsync(CancellationToken cancellationToken)
    {
        string host = options.ConfigurationBaseUri.Host;
        if (options.ConfigurationBaseUri.IsLoopback)
            return EngineeringDiagnosticPolicy.Passed(TestId, Name, "Configuration endpoint is loopback; DNS resolution is not required.", $"Host={host}");

        try
        {
            IPAddress[] addresses = await Dns.GetHostAddressesAsync(host, cancellationToken).ConfigureAwait(false);
            return addresses.Length > 0
                ? EngineeringDiagnosticPolicy.Passed(TestId, Name, "Configuration endpoint DNS resolved.", $"Host={host}; Addresses={addresses.Length}")
                : EngineeringDiagnosticPolicy.Failed(TestId, Name, "Configuration endpoint DNS returned no addresses.", $"Host={host}");
        }
        catch (Exception ex) when (ex is SocketException or ArgumentException)
        {
            return EngineeringDiagnosticPolicy.Failed(TestId, Name, "Configuration endpoint DNS resolution failed.", $"Host={host}; FailureType={ex.GetType().Name}");
        }
    }
}

public sealed class RegistrationConfigurationTcpLevelXTest(RegistrationLifecycleOptions options) : ILevelXLocalTest
{
    private readonly RegistrationLifecycleOptions options = options ?? throw new ArgumentNullException(nameof(options));
    public string TestId => "COMMON.REGISTRATION.L4.CONFIGURATION.TCP";
    public string Name => "Configuration endpoint TCP reachable";
    public string Owner => "Common.Registration";
    public EngineeringDiagnosticLevel Level => EngineeringDiagnosticLevel.Level4Analysis;
    public bool IsDestructive => false;

    public async Task<EngineeringDiagnosticCheckResult> RunAsync(CancellationToken cancellationToken)
    {
        Uri uri = options.ConfigurationBaseUri;
        int port = uri.IsDefaultPort ? (uri.Scheme == Uri.UriSchemeHttps ? 443 : 80) : uri.Port;
        try
        {
            using TcpClient client = new();
            using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(options.RequestTimeout ?? TimeSpan.FromSeconds(10));
            await client.ConnectAsync(uri.Host, port, timeout.Token).ConfigureAwait(false);
            return EngineeringDiagnosticPolicy.Passed(TestId, Name, "Configuration endpoint TCP connection succeeded.", $"Host={uri.Host}; Port={port}");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException)
        {
            return EngineeringDiagnosticPolicy.Failed(TestId, Name, "Configuration endpoint TCP connection failed.", $"Host={uri.Host}; Port={port}; FailureType={ex.GetType().Name}");
        }
    }
}

public sealed class RegistrationContractRedactionLevelXTest : ILevelXLocalTest
{
    public string TestId => "COMMON.REGISTRATION.L5.CONTRACT.REDACTION";
    public string Name => "Configuration contract strips value-bearing fields";
    public string Owner => "Common.Registration";
    public EngineeringDiagnosticLevel Level => EngineeringDiagnosticLevel.Level5Scan;
    public bool IsDestructive => false;

    public Task<EngineeringDiagnosticCheckResult> RunAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        JsonObject sample = new()
        {
            ["name"] = "Probe",
            ["value"] = "must-not-survive",
            ["currentValue"] = "must-not-survive",
            ["kind"] = "Secret",
            ["nested"] = new JsonObject { ["resolvedValue"] = "must-not-survive" }
        };
        JsonObject sanitized = ConfigurationContractPolicy.MetadataOnly(sample);
        string json = sanitized.ToJsonString();
        bool leaked = json.Contains("must-not-survive", StringComparison.Ordinal);
        return Task.FromResult(leaked
            ? EngineeringDiagnosticPolicy.Failed(TestId, Name, "Configuration contract policy retained a value-bearing field.")
            : EngineeringDiagnosticPolicy.Passed(TestId, Name, "Configuration contract policy removed value-bearing fields."));
    }
}

public sealed class RegistrationIdentityStoreRoundTripLevelXTest : ILevelXLocalTest
{
    public string TestId => "COMMON.REGISTRATION.L3.IDENTITY.STORE_ROUNDTRIP";
    public string Name => "Registration identity store diagnostic round trip";
    public string Owner => "Common.Registration";
    public EngineeringDiagnosticLevel Level => EngineeringDiagnosticLevel.Level3Verification;
    public bool IsDestructive => true;

    public async Task<EngineeringDiagnosticCheckResult> RunAsync(CancellationToken cancellationToken)
    {
        string directory = Path.Combine(Path.GetTempPath(), "aegis-levelx-registration", Guid.NewGuid().ToString("N"));
        string path = Path.Combine(directory, "identity.json");
        try
        {
            Directory.CreateDirectory(directory);
            var store = new FileRegistrationIdentityStore(path);
            RegistrationIdentityDocument first = await store.LoadOrCreateAsync("LevelX.Probe", "probe", cancellationToken).ConfigureAwait(false);
            RegistrationIdentityDocument second = await store.LoadOrCreateAsync("LevelX.Probe", "probe", cancellationToken).ConfigureAwait(false);
            bool stable = string.Equals(first.InstallationId, second.InstallationId, StringComparison.Ordinal);
            return stable
                ? EngineeringDiagnosticPolicy.Passed(TestId, Name, "Diagnostic identity persisted and reloaded with a stable InstallationId.")
                : EngineeringDiagnosticPolicy.Failed(TestId, Name, "Diagnostic identity InstallationId changed across reload.");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or CryptographicException)
        {
            return EngineeringDiagnosticPolicy.Failed(TestId, Name, "Diagnostic identity store round trip failed.", $"FailureType={ex.GetType().Name}");
        }
        finally
        {
            try { if (Directory.Exists(directory)) Directory.Delete(directory, true); } catch { }
        }
    }
}


public sealed class RegistrationLevelXRequestCredentialProvider(
    RegistrationLifecycleOptions options) : ILevelXRequestCredentialProvider
{
    private readonly RegistrationLifecycleOptions options =
        options ?? throw new ArgumentNullException(nameof(options));

    public async ValueTask<string?> GetCredentialAsync(
        Microsoft.AspNetCore.Http.HttpContext context,
        CancellationToken cancellationToken = default)
    {
        RegistrationIdentityDocument document = await new FileRegistrationIdentityStore(options.IdentityFilePath)
            .LoadOrCreateAsync(options.ApplicationId, options.InstanceId, cancellationToken)
            .ConfigureAwait(false);

        return string.IsNullOrWhiteSpace(document.Credential)
            ? null
            : document.Credential.Trim();
    }
}

public static class RegistrationLevelXServiceCollectionExtensions
{
    public static IServiceCollection AddCommonRegistrationLevelX(
        this IServiceCollection services,
        RegistrationLifecycleOptions options)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(options);
        services.AddSingleton(options);
        services.AddSingleton<ILevelXLocalTest, RegistrationConfigurationLevelXTest>();
        services.AddSingleton<ILevelXLocalTest, RegistrationIdentityFileLevelXTest>();
        services.AddSingleton<ILevelXLocalTest, RegistrationConfigurationDnsLevelXTest>();
        services.AddSingleton<ILevelXLocalTest, RegistrationConfigurationTcpLevelXTest>();
        services.AddSingleton<ILevelXLocalTest, RegistrationContractRedactionLevelXTest>();
        services.AddSingleton<ILevelXLocalTest, RegistrationIdentityStoreRoundTripLevelXTest>();
        services.Replace(ServiceDescriptor.Singleton<ILevelXRequestCredentialProvider, RegistrationLevelXRequestCredentialProvider>());
        return services;
    }
}
