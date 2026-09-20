using Xunit;

namespace Common.Registration.Tests;

public sealed class ApplicationPresentationMetadataTests
{
    [Theory]
    [InlineData("/assets/icons/studio.svg")]
    [InlineData("https://studio.example.org/assets/icon.svg")]
    public void Safe_icon_urls_are_accepted(string value)
    {
        Assert.True(ApplicationPresentationMetadata.IsSafeIconUrl(value));
    }

    [Theory]
    [InlineData("javascript:alert(1)")]
    [InlineData("http://example.org/icon.svg")]
    [InlineData("//evil.example/icon.svg")]
    [InlineData("/assets/../secret.svg")]
    public void Unsafe_icon_urls_are_rejected(string value)
    {
        Assert.False(ApplicationPresentationMetadata.IsSafeIconUrl(value));
    }

    [Fact]
    public void Fallback_initials_use_short_name_when_present()
    {
        var metadata = new ApplicationPresentationMetadata(ShortName: "Studio");
        Assert.Equal("ST", metadata.FallbackInitials("Aegis.Studio", "Aegis Studio"));
    }
}
