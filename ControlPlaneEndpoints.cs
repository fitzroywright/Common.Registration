using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Common.Registration;

public enum AegisControlPlaneService
{
    Operations,
    Configuration,
    Diagnostics
}

public enum AegisControlPlaneEndpointScope
{
    Internal,
    Public
}

public static class AegisControlPlaneEndpoints
{
    public const string OperationsInternalUrl = "http://127.0.0.1:5100";
    public const string ConfigurationInternalUrl = "http://127.0.0.1:5200";
    public const string DiagnosticsInternalUrl = "http://127.0.0.1:5300";

    public const string OperationsPublicUrl = "https://operations.ffpja.org";
    public const string ConfigurationPublicUrl = "https://config.ffpja.org";
    public const string DiagnosticsPublicUrl = "https://diagnostics.ffpja.org";

    public static string ResolveInternal(
        IConfiguration configuration,
        AegisControlPlaneService service,
        ILogger? logger = null,
        string? configurationKey = null) =>
        Resolve(configuration, service, AegisControlPlaneEndpointScope.Internal, logger, configurationKey);

    public static string ResolvePublic(
        IConfiguration configuration,
        AegisControlPlaneService service,
        ILogger? logger = null,
        string? configurationKey = null) =>
        Resolve(configuration, service, AegisControlPlaneEndpointScope.Public, logger, configurationKey);

    public static string Resolve(
        IConfiguration configuration,
        AegisControlPlaneService service,
        AegisControlPlaneEndpointScope scope,
        ILogger? logger = null,
        string? configurationKey = null)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        string key = string.IsNullOrWhiteSpace(configurationKey)
            ? DefaultConfigurationKey(service, scope)
            : configurationKey.Trim();

        string? configured = configuration[key]?.Trim();
        if (!string.IsNullOrWhiteSpace(configured))
        {
            string value = configured.TrimEnd('/');
            logger?.LogInformation(
                "{Service} {Scope} endpoint {ConfigurationKey} resolved from configured value {ConfiguredValue}.",
                service,
                scope,
                key,
                value);
            return value;
        }

        string fallback = DefaultUrl(service, scope);
        logger?.LogWarning(
            "{Service} {Scope} endpoint {ConfigurationKey} is not configured. {FallbackType} FALLBACK ACTIVE -> {FallbackValue}.",
            service,
            scope,
            key,
            scope == AegisControlPlaneEndpointScope.Internal ? "INTERNAL" : "PUBLIC",
            fallback);
        return fallback;
    }

    public static string DefaultUrl(
        AegisControlPlaneService service,
        AegisControlPlaneEndpointScope scope) =>
        (service, scope) switch
        {
            (AegisControlPlaneService.Operations, AegisControlPlaneEndpointScope.Internal) => OperationsInternalUrl,
            (AegisControlPlaneService.Configuration, AegisControlPlaneEndpointScope.Internal) => ConfigurationInternalUrl,
            (AegisControlPlaneService.Diagnostics, AegisControlPlaneEndpointScope.Internal) => DiagnosticsInternalUrl,
            (AegisControlPlaneService.Operations, AegisControlPlaneEndpointScope.Public) => OperationsPublicUrl,
            (AegisControlPlaneService.Configuration, AegisControlPlaneEndpointScope.Public) => ConfigurationPublicUrl,
            (AegisControlPlaneService.Diagnostics, AegisControlPlaneEndpointScope.Public) => DiagnosticsPublicUrl,
            _ => throw new ArgumentOutOfRangeException(nameof(service), service, null)
        };

    public static string DefaultConfigurationKey(
        AegisControlPlaneService service,
        AegisControlPlaneEndpointScope scope)
    {
        string name = service.ToString();
        return scope == AegisControlPlaneEndpointScope.Internal
            ? $"Aegis:{name}:Url"
            : $"Aegis:{name}:PublicUrl";
    }
}
