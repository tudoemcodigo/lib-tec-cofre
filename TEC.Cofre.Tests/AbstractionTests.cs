using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using TEC.Cofre.Abstractions;
using TEC.Cofre.Caching;
using TEC.Cofre.Common;
using TEC.Cofre.Configuration;
using TEC.Cofre.DependencyInjection;
using TEC.Cofre.HealthChecks;
using TEC.Cofre.InMemory;
using TEC.Cofre.Keys;
using TEC.Cofre.Secrets;
using TEC.Cofre.Tests.Fakes;
using TEC.Core.Common.Results;

namespace TEC.Cofre.Tests;

/// <summary>Recursos independentes de provedor (cache, configuração, geração, rotação, envelope, DI, health check).</summary>
public class AbstractionTests
{
    // ---------- Cache ----------

    [Test]
    public async Task Cache_evita_nova_leitura_e_e_limpo_na_escrita()
    {
        var inner = new ScriptedSecretStore(Memory.Secrets());
        await inner.SetSecretAsync("a", "1");
        using var cache = new CachingSecretReader(inner, TimeSpan.FromMinutes(5));
        var writer = new CacheInvalidatingSecretStore(inner, cache);

        await cache.GetSecretAsync("a");
        await writer.GetSecretAsync("a");   // leitura pelo ISecretStore também passa pelo cache
        await Assert.That(inner.GetCalls).IsEqualTo(1);

        await writer.SetSecretAsync("a", "2");
        var result = await cache.GetSecretAsync("a");

        await Assert.That(inner.GetCalls).IsEqualTo(2);
        await Assert.That(result.Value.Value).IsEqualTo("2");
    }

    [Test]
    public async Task Cache_e_limpo_pela_lixeira_e_pela_restauracao()
    {
        var memory = Memory.Secrets();
        await memory.SetSecretAsync("a", "1");
        var inner = new ScriptedSecretStore(memory);
        using var cache = new CachingSecretReader(inner, TimeSpan.FromMinutes(5));
        var bin = new CacheInvalidatingSecretRecycleBin(memory, cache);
        var backup = new CacheInvalidatingSecretBackup(memory, cache);

        await cache.GetSecretAsync("a");
        long before = cache.Generation;
        await memory.DeleteSecretAsync("a");
        await bin.RecoverDeletedSecretAsync("a");
        var token = await backup.BackupSecretAsync("a");
        await backup.RestoreSecretBackupAsync(token.Value);   // conflito (nome existe), mas limpa mesmo assim

        await Assert.That(cache.Generation).IsEqualTo(before + 2);
    }

    [Test]
    public async Task Cache_nao_guarda_falhas()
    {
        var inner = new ScriptedSecretStore(Memory.Secrets());
        using var cache = new CachingSecretReader(inner, TimeSpan.FromMinutes(5));

        await cache.GetSecretAsync("x");
        await cache.GetSecretAsync("x");

        await Assert.That(inner.GetCalls).IsEqualTo(2);
    }

    [Test]
    public async Task Cache_nao_guarda_alem_da_expiracao_do_segredo()
    {
        var now = DateTimeOffset.UtcNow;
        var inner = new ScriptedSecretStore(Memory.Secrets());
        await inner.SetSecretAsync("a", "1", new SecretWriteOptions { ExpiresOn = now.AddMinutes(1) });
        using var cache = new CachingSecretReader(inner, TimeSpan.FromMinutes(5), new FixedTimeProvider(now.AddMinutes(2)));

        await cache.GetSecretAsync("a");
        await cache.GetSecretAsync("a");

        await Assert.That(inner.GetCalls).IsEqualTo(2);
    }

    [Test]
    [Arguments(0)]
    [Arguments(-1)]
    [Arguments(3601)]
    public async Task Cache_com_duracao_invalida_e_recusado(int seconds) =>
        await Assert.That(() => new CachingSecretReader(Memory.Secrets(), TimeSpan.FromSeconds(seconds)))
            .Throws<ArgumentOutOfRangeException>();

    // ---------- Geração e rotação ----------

    [Test]
    [Arguments(SecretGenerationKind.Password, 32, 32)]
    [Arguments(SecretGenerationKind.Token, 32, 43)]
    [Arguments(SecretGenerationKind.Hex, 16, 32)]
    public async Task GenerateSecret_grava_valor_forte_sem_retornar_o_valor(SecretGenerationKind kind, int length, int expectedChars)
    {
        var store = Memory.Secrets();

        var result = await store.GenerateSecretAsync("gerado", new SecretGenerationOptions { Kind = kind, Length = length });
        var stored = await store.GetSecretAsync("gerado");

        await Assert.That(result.IsSuccess).IsTrue();
        await Assert.That(result.Value).IsTypeOf<SecretProperties>();
        await Assert.That(stored.Value.Value.Length).IsEqualTo(expectedChars);
    }

    [Test]
    [Arguments(8)]
    [Arguments(2000)]
    public async Task GenerateSecret_recusa_tamanho_fraco_ou_exagerado(int length)
    {
        var result = await Memory.Secrets().GenerateSecretAsync("x", new SecretGenerationOptions { Length = length });

        await Assert.That(result.Error!.Code).IsEqualTo(CofreErrors.InvalidInputCode);
    }

    [Test]
    public async Task RotateSecret_mantem_metadados_e_pode_desabilitar_versoes_antigas()
    {
        var store = Memory.Secrets();
        var tags = new Dictionary<string, string> { ["dono"] = "ti" };
        var v1 = await store.SetSecretAsync("api", "antigo", new SecretWriteOptions { ContentType = "text/plain", Tags = tags });

        var v2 = await store.RotateSecretAsync("api", validity: TimeSpan.FromDays(30), disablePreviousVersions: true);
        var versions = await store.ListSecretVersionsAsync("api");
        var current = await store.GetSecretAsync("api");
        var old = await store.GetSecretAsync("api", v1.Value.Version);

        await Assert.That(v2.Value.IsComplete).IsTrue();
        await Assert.That(v2.Value.DisabledVersions).IsEquivalentTo(new[] { v1.Value.Version! });
        await Assert.That(v2.Value.Current.ContentType).IsEqualTo("text/plain");
        await Assert.That(v2.Value.Current.Tags["dono"]).IsEqualTo("ti");
        await Assert.That(v2.Value.Current.ExpiresOn).IsNotNull();
        await Assert.That(current.Value.Value).IsNotEqualTo("antigo");
        await Assert.That(versions.Value.Count).IsEqualTo(2);
        await Assert.That(old.Error!.Code).IsEqualTo(CofreErrors.DisabledCode);
    }

    [Test]
    public async Task RotateSecret_com_falha_parcial_informa_a_nova_versao_e_pode_ser_concluida_sem_nova_versao()
    {
        var store = new ScriptedSecretStore(Memory.Secrets());
        var v1 = await store.SetSecretAsync("api", "antigo");
        store.FailUpdateFor = version => version == v1.Value.Version;

        var rotated = await store.RotateSecretAsync("api", disablePreviousVersions: true);

        await Assert.That(rotated.IsSuccess).IsTrue();
        await Assert.That(rotated.Value.IsComplete).IsFalse();
        await Assert.That(rotated.Value.FailedVersions).IsEquivalentTo(new[] { v1.Value.Version! });
        await Assert.That(rotated.Value.Errors.Single().Code).IsEqualTo(CofreErrors.UnavailableCode);
        await Assert.That((await store.GetSecretAsync("api")).Value.Version).IsEqualTo(rotated.Value.Current.Version);

        // Conclusão idempotente: desabilita o que faltou sem gravar outra versão
        store.FailUpdateFor = null;
        var completed = await store.DisablePreviousSecretVersionsAsync("api", rotated.Value.Current.Version!);
        var again = await store.DisablePreviousSecretVersionsAsync("api", rotated.Value.Current.Version!);

        await Assert.That(completed.Value.IsComplete).IsTrue();
        await Assert.That(completed.Value.DisabledVersions).IsEquivalentTo(new[] { v1.Value.Version! });
        await Assert.That(again.Value.DisabledVersions).IsEmpty();
        await Assert.That((await store.ListSecretVersionsAsync("api")).Value.Count).IsEqualTo(2);
        await Assert.That((await store.GetSecretAsync("api", v1.Value.Version)).Error!.Code).IsEqualTo(CofreErrors.DisabledCode);
    }

    [Test]
    public async Task RotateSecret_com_versoes_criadas_no_mesmo_segundo_usa_a_versao_atual()
    {
        var store = Memory.Secrets(new FixedTimeProvider(new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero)));
        await store.SetSecretAsync("api", "1", new SecretWriteOptions { ContentType = "antigo" });
        await store.SetSecretAsync("api", "2", new SecretWriteOptions { ContentType = "atual" });

        var rotated = await store.RotateSecretAsync("api");

        await Assert.That(rotated.Value.Current.ContentType).IsEqualTo("atual");
    }

    [Test]
    public async Task RotateSecret_calcula_a_expiracao_pelo_TimeProvider()
    {
        var now = new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var store = Memory.Secrets();
        await store.SetSecretAsync("api", "1");

        var rotated = await store.RotateSecretAsync("api", validity: TimeSpan.FromDays(1), timeProvider: new FixedTimeProvider(now));

        await Assert.That(rotated.Value.Current.ExpiresOn).IsEqualTo(now.AddDays(1));
    }

    [Test]
    public async Task DisablePreviousSecretVersions_com_versao_inexistente_retorna_NotFound()
    {
        var store = Memory.Secrets();
        await store.SetSecretAsync("api", "1");

        var result = await store.DisablePreviousSecretVersionsAsync("api", "0123456789abcdef0123456789abcdef");

        await Assert.That(result.Error!.Code).IsEqualTo(CofreErrors.NotFoundCode);
    }

    [Test]
    public async Task RotateSecret_de_segredo_inexistente_retorna_NotFound()
    {
        var result = await Memory.Secrets().RotateSecretAsync("nao-existe");

        await Assert.That(result.Error!.Code).IsEqualTo(CofreErrors.NotFoundCode);
    }

    // ---------- Criptografia envelope ----------

    [Test]
    public async Task Envelope_cifra_e_decifra_com_o_mesmo_contexto()
    {
        IKeyCryptography keys = await Memory.KeysWithKekAsync();
        byte[] data = Encoding.UTF8.GetBytes(new string('x', 100_000));
        byte[] context = "cliente:42"u8.ToArray();

        var encrypted = await keys.EncryptEnvelopeAsync("kek", data, context);
        var decrypted = await keys.DecryptEnvelopeAsync(encrypted.Value, context);

        await Assert.That(decrypted.Value).IsEquivalentTo(data);
        await Assert.That(encrypted.Value.Ciphertext).IsNotEquivalentTo(data);
    }

    [Test]
    public async Task Envelope_com_outro_contexto_ou_adulterado_falha()
    {
        IKeyCryptography keys = await Memory.KeysWithKekAsync();
        var encrypted = (await keys.EncryptEnvelopeAsync("kek", "dado"u8.ToArray(), "cliente:42"u8.ToArray())).Value;
        var tampered = encrypted with { Ciphertext = [.. encrypted.Ciphertext] };
        tampered.Ciphertext[^1] ^= 0xFF;

        var otherContext = await keys.DecryptEnvelopeAsync(encrypted, "cliente:43"u8.ToArray());
        var altered = await keys.DecryptEnvelopeAsync(tampered, "cliente:42"u8.ToArray());

        await Assert.That(otherContext.Error!.Field).IsEqualTo("ciphertext");
        await Assert.That(altered.Error!.Field).IsEqualTo("ciphertext");
    }

    // ---------- Configuração (depende só de ISecretReader) ----------

    [Test]
    public async Task Configuracao_carrega_somente_o_prefixo_ativo_e_converte_secoes()
    {
        var store = Memory.Secrets();
        await store.SetSecretAsync("MinhaApi--ConnectionStrings--Default", "Server=db");
        await store.SetSecretAsync("MinhaApi--Desabilitado", "x", new SecretWriteOptions { Enabled = false });
        await store.SetSecretAsync("MinhaApi--Futuro", "x", new SecretWriteOptions { NotBefore = DateTimeOffset.UtcNow.AddDays(1) });
        await store.SetSecretAsync("OutraApi--Senha", "nao-deve-carregar");
        ISecretReader reader = store;

        var configuration = new ConfigurationBuilder().AddTecCofre(reader, o => o.Prefix = "MinhaApi--").Build();

        await Assert.That(configuration["ConnectionStrings:Default"]).IsEqualTo("Server=db");
        await Assert.That(configuration["Desabilitado"]).IsNull();
        await Assert.That(configuration["Futuro"]).IsNull();
        await Assert.That(configuration.AsEnumerable().Any(kv => kv.Value == "nao-deve-carregar")).IsFalse();
    }

    [Test]
    public async Task Configuracao_ignora_itens_gerenciados_pelo_provedor()
    {
        var reader = new ManagedListingReader();

        var configuration = new ConfigurationBuilder().AddTecCofre(reader).Build();

        await Assert.That(configuration["comum"]).IsEqualTo("valor");
        await Assert.That(configuration["cert-api"]).IsNull();
    }

    [Test]
    public async Task Configuracao_falha_fechada_quando_passa_do_limite()
    {
        var store = Memory.Secrets();
        for (int i = 0; i < 3; i++)
            await store.SetSecretAsync($"s{i}", "v");

        await Assert.That(() => new ConfigurationBuilder().AddTecCofre(store, o => o.MaxSecrets = 2).Build())
            .Throws<InvalidOperationException>();
        await Assert.That(new ConfigurationBuilder().AddTecCofre(store, o => { o.MaxSecrets = 2; o.Optional = true; }).Build().AsEnumerable())
            .IsEmpty();
    }

    [Test]
    public async Task Configuracao_recarrega_valores_rotacionados()
    {
        var store = Memory.Secrets();
        await store.SetSecretAsync("Senha", "v1");
        var configuration = new ConfigurationBuilder().AddTecCofre(store).Build();
        var provider = (CofreConfigurationProvider)configuration.Providers.Single();

        await store.SetSecretAsync("Senha", "v2");
        await provider.ReloadAsync();

        await Assert.That(configuration["Senha"]).IsEqualTo("v2");
    }

    [Test]
    public async Task Configuracao_recusa_recarga_menor_que_1_minuto() =>
        await Assert.That(() => new CofreConfigurationOptions { ReloadInterval = TimeSpan.FromSeconds(10) })
            .Throws<ArgumentOutOfRangeException>();

    // ---------- DI e health check ----------

    [Test]
    public async Task AddTecCofre_sem_provedor_falha()
    {
        await Assert.That(() => new ServiceCollection().AddTecCofre(_ => { })).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task AddTecCofre_duas_vezes_falha()
    {
        var services = new ServiceCollection();
        services.AddTecCofre(c => c.UseSecretStore<SecretReaderStub>());

        await Assert.That(() => services.AddTecCofre(c => c.UseSecretStore<SecretReaderStub>())).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task Dois_provedores_para_a_mesma_familia_falham()
    {
        await Assert.That(() => new ServiceCollection().AddTecCofre(c => c
                .UseSecretStore<SecretReaderStub>()
                .UseInMemory(o => o.AllowOutsideDevelopment = true)))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task UseKeyStore_com_tipo_sem_interface_de_chaves_e_recusado() =>
        await Assert.That(() => new ServiceCollection().AddTecCofre(c => c.UseKeyStore<SecretReaderStub>())).Throws<ArgumentException>();

    [Test]
    public async Task AddTecCofre_registra_cada_interface_apontando_para_a_mesma_instancia()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddTecCofre(c => c.UseInMemory(o => o.AllowOutsideDevelopment = true));
        using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateOnBuild = true, ValidateScopes = true });

        var secrets = provider.GetRequiredService<ISecretReader>();
        await Assert.That(secrets).IsTypeOf<InMemorySecretStore>();
        await Assert.That(provider.GetRequiredService<ISecretStore>()).IsSameReferenceAs(secrets);
        await Assert.That(provider.GetRequiredService<ISecretRecycleBin>()).IsSameReferenceAs(secrets);
        await Assert.That(provider.GetRequiredService<ISecretBackup>()).IsSameReferenceAs(secrets);

        var keys = provider.GetRequiredService<IKeyReader>();
        await Assert.That(provider.GetRequiredService<IKeyStore>()).IsSameReferenceAs(keys);
        await Assert.That(provider.GetRequiredService<IKeyCryptography>()).IsSameReferenceAs(keys);
        await Assert.That(provider.GetRequiredService<IKeyRecycleBin>()).IsSameReferenceAs(keys);
        await Assert.That(provider.GetRequiredService<IKeyBackup>()).IsSameReferenceAs(keys);

        var certificates = provider.GetRequiredService<ICertificateReader>();
        await Assert.That(provider.GetRequiredService<ICertificateStore>()).IsSameReferenceAs(certificates);
        await Assert.That(provider.GetRequiredService<ICertificateRecycleBin>()).IsSameReferenceAs(certificates);
        await Assert.That(provider.GetRequiredService<ICertificateBackup>()).IsSameReferenceAs(certificates);
    }

    [Test]
    public async Task Provedor_so_de_leitura_registra_apenas_ISecretReader()
    {
        var services = new ServiceCollection();
        services.AddTecCofre(c => c.UseSecretStore<SecretReaderStub>());
        using var provider = services.BuildServiceProvider();

        await Assert.That(provider.GetRequiredService<ISecretReader>()).IsTypeOf<SecretReaderStub>();
        await Assert.That(provider.GetService<ISecretStore>()).IsNull();
        await Assert.That(provider.GetService<ISecretRecycleBin>()).IsNull();
        await Assert.That(provider.GetService<ISecretBackup>()).IsNull();
    }

    [Test]
    public async Task AddTecCofre_com_cache_decora_o_leitor_e_as_escritas_limpam_o_cache()
    {
        var services = new ServiceCollection();
        services.AddTecCofre(c => c.UseInMemory(o => { o.AllowOutsideDevelopment = true; o.Stores = CofreStores.Secrets; })
            .EnableSecretCache(TimeSpan.FromMinutes(1)));
        using var provider = services.BuildServiceProvider();

        var reader = provider.GetRequiredService<ISecretReader>();
        var store = provider.GetRequiredService<ISecretStore>();
        await store.SetSecretAsync("a", "1");
        await reader.GetSecretAsync("a");
        await store.SetSecretAsync("a", "2");

        await Assert.That(reader).IsTypeOf<CachingSecretReader>();
        await Assert.That(store).IsTypeOf<CacheInvalidatingSecretStore>();
        await Assert.That(provider.GetRequiredService<ISecretRecycleBin>()).IsTypeOf<CacheInvalidatingSecretRecycleBin>();
        await Assert.That(provider.GetRequiredService<ISecretBackup>()).IsTypeOf<CacheInvalidatingSecretBackup>();
        await Assert.That((await reader.GetSecretAsync("a")).Value.Value).IsEqualTo("2");
    }

    [Test]
    public async Task HealthCheck_nao_expoe_detalhes()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IVaultHealthProbe>(new FailingProbe());
        services.AddHealthChecks().AddTecCofre();
        using var provider = services.BuildServiceProvider();

        var report = await provider.GetRequiredService<HealthCheckService>().CheckHealthAsync();
        var entry = report.Entries["cofre"];

        await Assert.That(entry.Status).IsEqualTo(HealthStatus.Unhealthy);
        await Assert.That(entry.Description).IsEqualTo("Cofre inacessível.");
        await Assert.That(entry.Exception).IsNull();
    }

    private sealed class FailingProbe : IVaultHealthProbe
    {
        public Task<Result> CheckAccessAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(Result.Failure(CofreErrors.AccessDenied()));
    }

    /// <summary>Lista um segredo comum e um gerenciado (ex.: o segredo de um certificado no Azure).</summary>
    private sealed class ManagedListingReader : ISecretReader
    {
        public string ProviderName => "Teste";

        public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretsAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<Result<IReadOnlyList<SecretProperties>>>(new SecretProperties[]
            {
                new() { Name = "comum", Enabled = true },
                new() { Name = "cert-api", Enabled = true, ManagedBy = "certificate" }
            });

        public Task<Result<VaultSecret>> GetSecretAsync(string name, string? version = null, CancellationToken cancellationToken = default) =>
            Task.FromResult<Result<VaultSecret>>(new VaultSecret(new SecretProperties { Name = name, Enabled = true }, "valor"));

        public Task<Result<bool>> ExistsAsync(string name, CancellationToken cancellationToken = default) => Task.FromResult<Result<bool>>(true);

        public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretVersionsAsync(string name, CancellationToken cancellationToken = default) =>
            Task.FromResult<Result<IReadOnlyList<SecretProperties>>>(CofreErrors.NotFound());
    }
}
