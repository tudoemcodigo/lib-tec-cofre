using System.Net;
using Azure.Core.Pipeline;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using TEC.Cofre.Abstractions;
using TEC.Cofre.AzureKeyVault;
using TEC.Cofre.Common;
using TEC.Cofre.DependencyInjection;
using TEC.Cofre.HealthChecks;
using TEC.Cofre.Tests.Fakes;
using TEC.Core.Common.Results;

namespace TEC.Cofre.Tests;

/// <summary>Sonda do health check: registrada em qualquer combinação de stores e verificando só os stores registrados.</summary>
public class HealthProbeTests
{
    [Test]
    public async Task Somente_UseKeyStore_registra_a_sonda_e_fica_saudavel()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddTecCofre(c => c.UseKeyStore<KeyReaderStub>());
        services.AddHealthChecks().AddTecCofre();
        using var provider = services.BuildServiceProvider();

        var report = await provider.GetRequiredService<HealthCheckService>().CheckHealthAsync();

        await Assert.That(report.Entries["cofre"].Status).IsEqualTo(HealthStatus.Healthy);
        await Assert.That(provider.GetRequiredService<KeyReaderStub>().ListKeysCalls).IsEqualTo(1);
    }

    [Test]
    public async Task Health_check_entra_no_readiness_por_padrao_e_tags_informadas_substituem()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddTecCofre(c => c.UseKeyStore<KeyReaderStub>());
        services.AddHealthChecks()
            .AddTecCofre()
            .AddTecCofre(name: "cofre-proprio", tags: ["critico"]);
        using var provider = services.BuildServiceProvider();

        var report = await provider.GetRequiredService<HealthCheckService>().CheckHealthAsync();

        // "ready" é a tag do readiness do TEC.Observability (/health/ready); nunca "live"
        await Assert.That(report.Entries["cofre"].Tags).IsEquivalentTo(new[] { "ready", "vault" });
        await Assert.That(report.Entries["cofre-proprio"].Tags).IsEquivalentTo(new[] { "critico" });
    }

    [Test]
    public async Task Sonda_propria_registrada_antes_e_mantida()
    {
        var own = new ProbeStub(Result.Success());
        var services = new ServiceCollection();
        services.AddSingleton<IVaultHealthProbe>(own);
        services.AddTecCofre(c => c.UseSecretStore<SecretReaderStub>());
        using var provider = services.BuildServiceProvider();

        await Assert.That(provider.GetRequiredService<IVaultHealthProbe>()).IsSameReferenceAs(own);
    }

    [Test]
    public async Task Falha_de_um_dos_stores_deixa_a_sonda_com_falha()
    {
        var probe = new CofreHealthProbe([_ => Task.FromResult(Result.Success()), _ => Task.FromResult(Result.Failure(CofreErrors.AccessDenied()))]);

        var result = await probe.CheckAccessAsync();

        await Assert.That(result.Error!.Code).IsEqualTo(CofreErrors.AccessDeniedCode);
    }

    [Test]
    public async Task Azure_somente_chaves_registra_so_IKeyStore_e_a_sonda_lista_so_chaves()
    {
        var vault = new FakeKeyVault((_, _) => (HttpStatusCode.OK, """{"value":[]}"""));
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddTecCofre(c => c.UseAzureKeyVault(o =>
        {
            Fake(o, vault);
            o.Stores = CofreStores.Keys;
        }));
        using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateOnBuild = true });

        var result = await provider.GetRequiredService<IVaultHealthProbe>().CheckAccessAsync();

        await Assert.That(result.IsSuccess).IsTrue();
        await Assert.That(provider.GetService<ISecretStore>()).IsNull();
        await Assert.That(provider.GetService<ICertificateStore>()).IsNull();
        await Assert.That(provider.GetService<IKeyStore>()).IsNotNull();
        await Assert.That(vault.Requests.All(r => r.Uri.AbsolutePath.TrimEnd('/') == "/keys")).IsTrue();
    }

    [Test]
    public async Task Azure_somente_chaves_nao_depende_de_permissao_de_segredos()
    {
        // Identidade com papel só de chaves: listar segredos daria 403
        var vault = new FakeKeyVault((request, _) => request.RequestUri!.AbsolutePath.StartsWith("/keys", StringComparison.Ordinal)
            ? (HttpStatusCode.OK, """{"value":[]}""")
            : (HttpStatusCode.Forbidden, FakeKeyVault.ErrorJson("Forbidden", "Caller is not authorized.", "ForbiddenByRbac")));
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddTecCofre(c => c.UseAzureKeyVault(o =>
        {
            Fake(o, vault);
            o.Stores = CofreStores.Keys;
        }));
        services.AddHealthChecks().AddTecCofre();
        using var provider = services.BuildServiceProvider();

        var report = await provider.GetRequiredService<HealthCheckService>().CheckHealthAsync();

        await Assert.That(report.Entries["cofre"].Status).IsEqualTo(HealthStatus.Healthy);
    }

    [Test]
    public async Task Azure_com_todos_os_stores_verifica_segredos_chaves_e_certificados()
    {
        var vault = new FakeKeyVault((_, _) => (HttpStatusCode.OK, """{"value":[]}"""));
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddTecCofre(c => c.UseAzureKeyVault(o => Fake(o, vault)));
        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IVaultHealthProbe>().CheckAccessAsync();
        var paths = vault.Requests.Where(r => r.Authorized).Select(r => r.Uri.AbsolutePath.TrimEnd('/')).Distinct().Order().ToList();

        await Assert.That(result.IsSuccess).IsTrue();
        await Assert.That(paths).IsEquivalentTo(new[] { "/certificates", "/keys", "/secrets" });
    }

    [Test]
    public async Task Azure_Stores_vazio_e_recusado_na_inicializacao()
    {
        var services = new ServiceCollection();

        await Assert.That(() => services.AddTecCofre(c => c.UseAzureKeyVault(o =>
        {
            o.VaultUri = new Uri(FakeKeyVault.VaultUri);
            o.Credential = new FakeCredential();
            o.Stores = CofreStores.None;
        }))).Throws<InvalidOperationException>();
    }

    private static void Fake(AzureKeyVaultOptions options, FakeKeyVault vault)
    {
        options.VaultUri = new Uri(FakeKeyVault.VaultUri);
        options.Credential = new FakeCredential();
        options.MaxRetries = 0;
        options.Transport = new HttpClientTransport(new HttpClient(vault));
    }

    private sealed class ProbeStub(Result result) : IVaultHealthProbe
    {
        public Task<Result> CheckAccessAsync(CancellationToken cancellationToken = default) => Task.FromResult(result);
    }
}
