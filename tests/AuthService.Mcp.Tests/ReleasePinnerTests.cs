using AuthService.Mcp;
using Xunit;
using static AuthService.Mcp.ReleasePinner;

namespace AuthService.Mcp.Tests;

public class ReleasePinnerTests
{
    [Theory]
    [InlineData("v0.3.2")]
    [InlineData("v1.0.0")]
    [InlineData("v0.10.0")]
    public void IsServiceTag_AcceptsTheImagesTags(string tag)
    {
        Assert.True(IsServiceTag(tag));
    }

    [Theory]
    [InlineData("mcp-v0.1.0")]
    [InlineData("latest")]
    [InlineData("v")]
    [InlineData("vnext")]
    [InlineData("")]
    [InlineData(null)]
    public void IsServiceTag_RejectsEverythingElse(string? tag)
    {
        Assert.False(IsServiceTag(tag));
    }

    [Fact]
    public void NewestServiceTag_SkipsTheInstallersReleases_WhenOneIsNewer()
    {
        var releases = new[] { new GitHubRelease("mcp-v0.1.0"), new GitHubRelease("v0.3.2"), new GitHubRelease("v0.3.0") };

        Assert.Equal("v0.3.2", NewestServiceTag(releases));
    }

    [Fact]
    public void NewestServiceTag_PicksTheHighestVersion_WhateverTheOrder()
    {
        var releases = new[] { new GitHubRelease("v0.9.1"), new GitHubRelease("v0.10.0"), new GitHubRelease("v0.2.0") };

        Assert.Equal("v0.10.0", NewestServiceTag(releases));
    }

    [Fact]
    public void NewestServiceTag_SkipsDraftsAndPrereleases()
    {
        var releases = new[]
        {
            new GitHubRelease("v0.5.0", Draft: true),
            new GitHubRelease("v0.4.0", Prerelease: true),
            new GitHubRelease("v0.3.2")
        };

        Assert.Equal("v0.3.2", NewestServiceTag(releases));
    }

    [Fact]
    public void NewestServiceTag_ReturnsNull_WhenOnlyTheInstallerHasReleases()
    {
        Assert.Null(NewestServiceTag([new GitHubRelease("mcp-v0.1.0")]));
    }
}
