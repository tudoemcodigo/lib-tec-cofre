using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using TEC.Cofre.Common;
using TEC.Cofre.Configuration;
using TEC.Cofre.Tests.Fakes;

namespace TEC.Cofre.Tests;

/// <summary>Provedor de <c>IConfiguration</c>: log de falhas, tempo limite, recarga incremental e leituras com paralelismo limitado.</summary>
public class ConfigurationProviderTests
{
    [Test]
    public async Task Falha_na_carga_inicial_e_registrada_em_Error_com_o_codigo()
    {
        var logs = new CapturingLoggerProvider();
        using var factory = LoggerFactory.Create(b => b.AddProvider(logs));
        var store = new ScriptedSecretStore(Memory.Secrets()) { ListFailure = CofreErrors.AccessDenied() };

        var exception = await Assert.That(() => new ConfigurationBuilder().AddTecCofre(store, loggerFactory: factory).Build())
            .Throws<InvalidOperationException>();

        await Assert.That(exception!.Message).Contains(CofreErrors.AccessDeniedCode);
        await Assert.That(logs.Entries.Any(e => e.Level == LogLevel.Error && e.Text.Contains(CofreErrors.AccessDeniedCode))).IsTrue();
    }

    [Test]
    public async Task Estouro_de_MaxSecrets_e_registrado_em_Error()
    {
        var logs = new CapturingLoggerProvider();
        using var factory = LoggerFactory.Create(b => b.AddProvider(logs));
        var store = Memory.Secrets();
        for (int i = 0; i < 3; i++)
            await store.SetSecretAsync($"s{i}", "v");

        await Assert.That(() => new ConfigurationBuilder().AddTecCofre(store, o => o.MaxSecrets = 2, loggerFactory: factory).Build())
            .Throws<InvalidOperationException>();

        await Assert.That(logs.Entries.Any(e => e.Level == LogLevel.Error && e.Text.Contains("MaxSecrets") && e.Text.Contains('3'))).IsTrue();
    }

    [Test]
    public async Task Carga_inicial_respeita_o_tempo_limite()
    {
        var logs = new CapturingLoggerProvider();
        using var factory = LoggerFactory.Create(b => b.AddProvider(logs));
        var store = new ScriptedSecretStore(Memory.Secrets()) { BeforeList = ct => Task.Delay(Timeout.Infinite, ct) };

        var started = TimeProvider.System.GetTimestamp();
        await Assert.That(() => new ConfigurationBuilder()
                .AddTecCofre(store, o => o.LoadTimeout = TimeSpan.FromMilliseconds(200), loggerFactory: factory).Build())
            .Throws<InvalidOperationException>();

        await Assert.That(TimeProvider.System.GetElapsedTime(started)).IsLessThan(TimeSpan.FromSeconds(10));
        await Assert.That(logs.Entries.Any(e => e.Level == LogLevel.Error && e.Text.Contains("tempo limite"))).IsTrue();
    }

    [Test]
    public async Task Tempo_limite_com_Optional_sobe_com_configuracao_vazia()
    {
        var store = new ScriptedSecretStore(Memory.Secrets()) { BeforeList = ct => Task.Delay(Timeout.Infinite, ct) };

        var configuration = new ConfigurationBuilder()
            .AddTecCofre(store, o => { o.LoadTimeout = TimeSpan.FromMilliseconds(100); o.Optional = true; }).Build();

        await Assert.That(configuration.AsEnumerable()).IsEmpty();
    }

    [Test]
    public async Task Recarga_incremental_rele_somente_segredos_alterados()
    {
        var memory = new ScriptedSecretStore(Memory.Secrets());
        await memory.SetSecretAsync("A", "1");
        await memory.SetSecretAsync("B", "1");
        await memory.SetSecretAsync("C", "1");
        var configuration = new ConfigurationBuilder().AddTecCofre(memory).Build();
        var provider = (CofreConfigurationProvider)configuration.Providers.Single();
        await Assert.That(memory.GetCalls).IsEqualTo(3);

        await memory.SetSecretAsync("B", "2");
        await provider.ReloadAsync();

        await Assert.That(memory.GetCalls).IsEqualTo(4);
        await Assert.That(configuration["A"]).IsEqualTo("1");
        await Assert.That(configuration["B"]).IsEqualTo("2");

        await provider.ReloadAsync();
        await Assert.That(memory.GetCalls).IsEqualTo(4);
    }

    [Test]
    public async Task Recarga_completa_periodica_rele_todos()
    {
        var memory = new ScriptedSecretStore(Memory.Secrets());
        await memory.SetSecretAsync("A", "1");
        var configuration = new ConfigurationBuilder().AddTecCofre(memory).Build();
        var provider = (CofreConfigurationProvider)configuration.Providers.Single();

        for (int i = 0; i < CofreConfigurationOptions.FullReloadEvery; i++)
            await provider.ReloadAsync();

        // 1 (carga inicial) + 1 (recarga completa); as incrementais não releem o segredo inalterado
        await Assert.That(memory.GetCalls).IsEqualTo(2);
    }

    [Test]
    public async Task Segredo_removido_some_da_configuracao_na_recarga()
    {
        var memory = new ScriptedSecretStore(Memory.Secrets());
        await memory.SetSecretAsync("A", "1");
        await memory.SetSecretAsync("B", "1");
        var configuration = new ConfigurationBuilder().AddTecCofre(memory).Build();
        var provider = (CofreConfigurationProvider)configuration.Providers.Single();

        await memory.DeleteSecretAsync("B");
        await provider.ReloadAsync();

        await Assert.That(configuration["A"]).IsEqualTo("1");
        await Assert.That(configuration["B"]).IsNull();
    }

    [Test]
    public async Task Falha_na_recarga_mantem_valores_e_e_registrada()
    {
        var logs = new CapturingLoggerProvider();
        using var factory = LoggerFactory.Create(b => b.AddProvider(logs));
        var memory = new ScriptedSecretStore(Memory.Secrets());
        await memory.SetSecretAsync("A", "1");
        var store = new ScriptedSecretStore(memory);
        var configuration = new ConfigurationBuilder().AddTecCofre(store, loggerFactory: factory).Build();
        var provider = (CofreConfigurationProvider)configuration.Providers.Single();

        store.ListFailure = CofreErrors.Unavailable();
        await provider.ReloadAsync();

        await Assert.That(configuration["A"]).IsEqualTo("1");
        await Assert.That(logs.Entries.Any(e => e.Level == LogLevel.Warning && e.Text.Contains(CofreErrors.UnavailableCode))).IsTrue();
    }

    [Test]
    public async Task Reload_com_Optional_e_cofre_fora_do_ar_mantem_os_segredos_ja_carregados()
    {
        var logs = new CapturingLoggerProvider();
        using var factory = LoggerFactory.Create(b => b.AddProvider(logs));
        var memory = new ScriptedSecretStore(Memory.Secrets());
        await memory.SetSecretAsync("A", "1");
        var store = new ScriptedSecretStore(memory);
        var configuration = new ConfigurationBuilder().AddTecCofre(store, o => o.Optional = true, loggerFactory: factory).Build();
        await Assert.That(configuration["A"]).IsEqualTo("1");

        store.ListFailure = CofreErrors.Unavailable();
        configuration.Reload();                       // antes: Data era trocado por vazio e a aplicação perdia os segredos

        await Assert.That(configuration["A"]).IsEqualTo("1");
        await Assert.That(logs.Entries.Any(e => e.Level == LogLevel.Error && e.Text.Contains(CofreErrors.UnavailableCode))).IsTrue();

        store.ListFailure = null;
        await memory.SetSecretAsync("A", "2");
        configuration.Reload();                       // cofre de volta: a carga volta a valer

        await Assert.That(configuration["A"]).IsEqualTo("2");
    }

    [Test]
    public async Task Reload_sem_Optional_e_cofre_fora_do_ar_lanca_e_mantem_os_valores()
    {
        var memory = new ScriptedSecretStore(Memory.Secrets());
        await memory.SetSecretAsync("A", "1");
        var store = new ScriptedSecretStore(memory);
        var configuration = new ConfigurationBuilder().AddTecCofre(store).Build();

        store.ListFailure = CofreErrors.Unavailable();

        await Assert.That(() => configuration.Reload()).Throws<InvalidOperationException>();
        await Assert.That(configuration["A"]).IsEqualTo("1");
    }

    [Test]
    public async Task Leituras_respeitam_o_limite_de_concorrencia()
    {
        var memory = new ScriptedSecretStore(Memory.Secrets());
        for (int i = 0; i < 12; i++)
            await memory.SetSecretAsync($"S{i}", "v");
        int current = 0, max = 0;
        var store = new ScriptedSecretStore(memory)
        {
            AfterGet = async (_, ct) =>
            {
                int now = Interlocked.Increment(ref current);
                int seen;
                while (now > (seen = Volatile.Read(ref max)) && Interlocked.CompareExchange(ref max, now, seen) != seen)
                {
                }

                await Task.Delay(20, ct);
                Interlocked.Decrement(ref current);
            }
        };

        var configuration = new ConfigurationBuilder().AddTecCofre(store, o => o.MaxConcurrentReads = 2).Build();

        await Assert.That(configuration.AsEnumerable().Count()).IsEqualTo(12);
        await Assert.That(max).IsLessThanOrEqualTo(2);
        await Assert.That(max).IsGreaterThanOrEqualTo(1);
    }

    [Test]
    public async Task Falha_em_uma_leitura_falha_a_carga()
    {
        var memory = new ScriptedSecretStore(Memory.Secrets());
        for (int i = 0; i < 6; i++)
            await memory.SetSecretAsync($"S{i}", "v");
        var store = new ScriptedSecretStore(memory) { GetFailure = name => name == "S3" ? CofreErrors.Throttled() : null };

        var exception = await Assert.That(() => new ConfigurationBuilder().AddTecCofre(store).Build()).Throws<InvalidOperationException>();

        await Assert.That(exception!.Message).Contains(CofreErrors.ThrottledCode);
    }

    [Test]
    [Arguments(0)]
    [Arguments(17)]
    public async Task MaxConcurrentReads_fora_do_intervalo_e_recusado(int value) =>
        await Assert.That(() => new CofreConfigurationOptions { MaxConcurrentReads = value }).Throws<ArgumentOutOfRangeException>();

    [Test]
    public async Task LoadTimeout_invalido_e_recusado() =>
        await Assert.That(() => new CofreConfigurationOptions { LoadTimeout = TimeSpan.Zero }).Throws<ArgumentOutOfRangeException>();
}
