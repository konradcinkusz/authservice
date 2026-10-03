using System.Net;
using AuthService.Tests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace AuthService.Tests;

/// <summary>
/// Which forwarded headers the application believes, and from whom, as the <c>Network</c> section
/// declares it. The middleware's own behaviour is the framework's, and the in-memory test server
/// has no peer address to check it against, so these read the options the application builds from
/// the settings: what is trusted, what is ignored, and what a malformed entry does.
/// </summary>
public class ForwardedHeadersConfigurationTests
{
    private sealed class FactoryWith(IReadOnlyDictionary<string, string?> settings) : AuthServiceFactory
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);

            foreach (var (key, value) in settings)
                builder.UseSetting(key, value);
        }
    }

    private static ForwardedHeadersOptions OptionsFor(params (string Key, string Value)[] settings)
    {
        var values = new Dictionary<string, string?>();
        foreach (var (key, value) in settings)
            values[key] = value;

        using var factory = new FactoryWith(values);

        return factory.Services.GetRequiredService<IOptions<ForwardedHeadersOptions>>().Value;
    }

    private static bool Trusts(ForwardedHeadersOptions options, string address) =>
        options.KnownProxies.Contains(IPAddress.Parse(address)) ||
        options.KnownIPNetworks.Any(network => network.Contains(IPAddress.Parse(address)));

    [Fact]
    public void Nothing_beyond_the_frameworks_default_is_trusted_unless_the_deployment_says_so()
    {
        var options = OptionsFor();
        var framework = new ForwardedHeadersOptions();

        Assert.Equal(framework.KnownProxies, options.KnownProxies);
        Assert.Equal(framework.KnownIPNetworks, options.KnownIPNetworks);
        Assert.Equal(1, options.ForwardLimit);
        Assert.Equal(
            ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost,
            options.ForwardedHeaders);
        Assert.False(Trusts(options, "203.0.113.9"));
    }

    [Fact]
    public void Proxies_named_by_address_are_trusted_and_a_malformed_entry_is_skipped()
    {
        var options = OptionsFor(
            ("Network:KnownProxies:0", "203.0.113.9"),
            ("Network:KnownProxies:1", "not-an-address"),
            ("Network:KnownProxies:2", "2001:db8::1"));

        Assert.True(Trusts(options, "203.0.113.9"));
        Assert.True(Trusts(options, "2001:db8::1"));
        Assert.Equal(new ForwardedHeadersOptions().KnownProxies.Count + 2, options.KnownProxies.Count);
        Assert.False(Trusts(options, "203.0.113.10"));
    }

    [Fact]
    public void Networks_in_cidr_form_are_trusted_as_a_whole()
    {
        var options = OptionsFor(
            ("Network:KnownNetworks:0", "10.0.0.0/8"),
            ("Network:KnownNetworks:1", "192.168.1.0/24"));

        Assert.True(Trusts(options, "10.200.3.4"));
        Assert.True(Trusts(options, "192.168.1.77"));
        Assert.False(Trusts(options, "192.168.2.1"));
        Assert.False(Trusts(options, "172.16.0.1"));
    }

    [Theory]
    [InlineData("10.0.0.0/33")]     // prefix longer than an address
    [InlineData("10.0.0.0/-1")]
    [InlineData("10.0.0.0")]        // no prefix
    [InlineData("10.0.0.0/8/8")]
    [InlineData("not-a-network/8")]
    [InlineData("10.0.0.0/eight")]
    [InlineData("")]
    public void A_network_entry_that_is_malformed_is_skipped_rather_than_stopping_the_application(string entry)
    {
        var options = OptionsFor(("Network:KnownNetworks:0", entry));

        Assert.Equal(new ForwardedHeadersOptions().KnownIPNetworks, options.KnownIPNetworks);
        Assert.False(Trusts(options, "10.0.0.5"));
    }

    [Fact]
    public void One_malformed_network_does_not_cost_the_valid_ones_next_to_it()
    {
        var options = OptionsFor(
            ("Network:KnownNetworks:0", "10.0.0.0/33"),
            ("Network:KnownNetworks:1", "192.168.1.0/24"));

        Assert.True(Trusts(options, "192.168.1.9"));
        Assert.False(Trusts(options, "10.0.0.5"));
    }

    [Fact]
    public void A_network_written_with_host_bits_set_is_taken_as_the_whole_network_that_contains_it()
    {
        // 10.0.0.5/8 is not a network address. System.Net.IPNetwork masks it, as the HttpOverrides
        // type it replaced did, so what is trusted is all of 10.0.0.0/8, not one host. Pinned so a
        // runtime that began refusing such an entry would show up here, not as proxies that
        // silently stopped being trusted.
        var options = OptionsFor(("Network:KnownNetworks:0", "10.0.0.5/8"));

        Assert.True(Trusts(options, "10.200.3.4"));
        Assert.False(Trusts(options, "11.0.0.1"));
    }

    [Theory]
    [InlineData("2", 2)]
    [InlineData("3", 3)]
    public void The_number_of_proxy_hops_to_walk_back_is_the_one_configured(string configured, int expected)
    {
        Assert.Equal(expected, OptionsFor(("Network:ForwardLimit", configured)).ForwardLimit);
    }

    [Fact]
    public void Trusting_all_proxies_drops_every_restriction_whatever_else_is_configured()
    {
        var options = OptionsFor(
            ("Network:TrustAllProxies", "true"),
            ("Network:KnownProxies:0", "203.0.113.9"),
            ("Network:KnownNetworks:0", "10.0.0.0/8"),
            ("Network:ForwardLimit", "2"));

        Assert.Empty(options.KnownProxies);
        Assert.Empty(options.KnownIPNetworks);
        Assert.Null(options.ForwardLimit);
    }
}
