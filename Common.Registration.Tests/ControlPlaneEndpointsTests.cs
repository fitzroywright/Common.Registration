using Microsoft.Extensions.Configuration;
using Xunit;

namespace Common.Registration.Tests;

public sealed class ControlPlaneEndpointsTests
{
    [Fact]
    public void Canonical_internal_ports_are_centralized()
    {
        Assert.Equal("http://127.0.0.1:5100", AegisControlPlaneEndpoints.OperationsInternalUrl);
        Assert.Equal("http://127.0.0.1:5200", AegisControlPlaneEndpoints.ConfigurationInternalUrl);
        Assert.Equal("http://127.0.0.1:5300", AegisControlPlaneEndpoints.DiagnosticsInternalUrl);
    }

    [Fact]
    public void Canonical_public_urls_are_centralized()
    {
        Assert.Equal("https://operations.ffpja.org", AegisControlPlaneEndpoints.OperationsPublicUrl);
        Assert.Equal("https://config.ffpja.org", AegisControlPlaneEndpoints.ConfigurationPublicUrl);
        Assert.Equal("https://diagnostics.ffpja.org", AegisControlPlaneEndpoints.DiagnosticsPublicUrl);
    }

    [Fact]
    public void Resolve_internal_prefers_configuration_and_trims_trailing_slash()
    {
        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Aegis:Configuration:Url"] = "http://10.0.0.20:5200/"
            })
            .Build();

        string value = AegisControlPlaneEndpoints.ResolveInternal(
            configuration,
            AegisControlPlaneService.Configuration);

        Assert.Equal("http://10.0.0.20:5200", value);
    }

    [Fact]
    public void Resolve_public_uses_shared_default_when_missing()
    {
        IConfiguration configuration = new ConfigurationBuilder().Build();

        string value = AegisControlPlaneEndpoints.ResolvePublic(
            configuration,
            AegisControlPlaneService.Diagnostics);

        Assert.Equal(AegisControlPlaneEndpoints.DiagnosticsPublicUrl, value);
    }

    [Fact]
    public void Override_key_allows_external_apps_to_use_public_default_with_existing_url_key()
    {
        IConfiguration configuration = new ConfigurationBuilder().Build();

        string value = AegisControlPlaneEndpoints.ResolvePublic(
            configuration,
            AegisControlPlaneService.Operations,
            configurationKey: "Aegis:Operations:Url");

        Assert.Equal(AegisControlPlaneEndpoints.OperationsPublicUrl, value);
    }
}
