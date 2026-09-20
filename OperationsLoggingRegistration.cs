using Common.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;

namespace Common.Registration;

public sealed class RegistrationOperationsLogCredentialSource : IOperationsLogCredentialSource
{
    private readonly FileRegistrationIdentityStore store;
    private readonly string applicationId;
    private readonly string instanceId;

    public RegistrationOperationsLogCredentialSource(
        string identityFile,
        string applicationId,
        string instanceId)
    {
        store = new FileRegistrationIdentityStore(identityFile);
        this.applicationId = applicationId;
        this.instanceId = instanceId;
    }

    public async ValueTask<OperationsLogCredential?> GetAsync(
        CancellationToken cancellationToken = default)
    {
        try
        {
            RegistrationIdentityDocument identity =
                await store.LoadOrCreateAsync(applicationId, instanceId, cancellationToken)
                    .ConfigureAwait(false);

            if (string.IsNullOrWhiteSpace(identity.Credential))
                return null;

            return new(
                identity.ApplicationId,
                identity.InstanceId,
                identity.InstallationId,
                identity.Credential);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return null;
        }
    }
}

public static class OperationsLoggingRegistrationExtensions
{
    public static IServiceCollection AddAegisOperationsLogging(
        this IServiceCollection services,
        IConfiguration configuration,
        string applicationId,
        string instanceId,
        string identityFile,
        string environment,
        LogLevel minimumLevel = LogLevel.Information)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        string? operationsUrl = configuration["Aegis:Operations:Url"]
            ?? configuration["Operations:Url"];
        if (string.IsNullOrWhiteSpace(operationsUrl))
            return services;

        if (!Uri.TryCreate(
            operationsUrl.TrimEnd('/') + "/api/operations/logs/observe",
            UriKind.Absolute,
            out Uri? endpoint))
            return services;

        var options = new OperationsLogPublisherOptions
        {
            Endpoint = endpoint,
            ApplicationId = applicationId,
            InstanceId = instanceId,
            Environment = environment,
            Host = Environment.MachineName,
            MinimumLevel = minimumLevel,
            QueueCapacity = Math.Clamp(
                configuration.GetValue("Aegis:Operations:Logging:QueueCapacity", 5000),
                100,
                100000),
            BatchSize = Math.Clamp(
                configuration.GetValue("Aegis:Operations:Logging:BatchSize", 100),
                1,
                1000),
            FlushInterval = TimeSpan.FromMilliseconds(Math.Clamp(
                configuration.GetValue("Aegis:Operations:Logging:FlushMilliseconds", 1000),
                100,
                30000))
        };

        var credentialSource =
            new RegistrationOperationsLogCredentialSource(identityFile, applicationId, instanceId);

        services.TryAddEnumerable(ServiceDescriptor.Singleton<ILoggerProvider>(
            new OperationsLogLoggerProvider(options, credentialSource)));

        return services;
    }
}
