using TEC.Cofre.Caching;
using TEC.Cofre.Tests.Fakes;

namespace TEC.Cofre.Tests;

/// <summary>
/// Concorrência do cache de segredos. Determinísticos: a leitura "lenta" é segurada por um portão (TaskCompletionSource)
/// depois de já ter lido o valor do cofre, sem depender de atrasos ou do agendador.
/// </summary>
public class CacheConcurrencyTests
{
    private static TaskCompletionSource NewSignal() => new(TaskCreationOptions.RunContinuationsAsynchronously);

    [Test]
    public async Task Leitura_que_terminou_depois_de_uma_escrita_nao_grava_valor_antigo_no_cache()
    {
        var memory = Memory.Secrets();
        await memory.SetSecretAsync("a", "antigo");
        var entered = NewSignal();
        var gate = NewSignal();
        var inner = new ScriptedSecretStore(memory) { AfterGet = async (_, _) => { entered.TrySetResult(); await gate.Task; } };
        using var cache = new CachingSecretReader(inner, TimeSpan.FromMinutes(5));

        var slowRead = cache.GetSecretAsync("a");
        await entered.Task;                        // a leitura já tem o valor "antigo" em mãos
        inner.AfterGet = null;
        await new CacheInvalidatingSecretStore(inner, cache).SetSecretAsync("a", "novo");   // a escrita termina e limpa o cache
        gate.SetResult();                          // só agora a leitura antiga termina

        var stale = await slowRead;
        var fresh = await cache.GetSecretAsync("a");

        await Assert.That(stale.Value.Value).IsEqualTo("antigo");
        await Assert.That(fresh.Value.Value).IsEqualTo("novo");
        await Assert.That(inner.GetCalls).IsEqualTo(2);
    }

    [Test]
    public async Task Leitura_iniciada_depois_da_escrita_nao_se_junta_a_leitura_anterior()
    {
        var memory = Memory.Secrets();
        await memory.SetSecretAsync("a", "antigo");
        var entered = NewSignal();
        var gate = NewSignal();
        var inner = new ScriptedSecretStore(memory) { AfterGet = async (_, _) => { entered.TrySetResult(); await gate.Task; } };
        using var cache = new CachingSecretReader(inner, TimeSpan.FromMinutes(5));

        var before = cache.GetSecretAsync("a");
        await entered.Task;
        await new CacheInvalidatingSecretStore(inner, cache).SetSecretAsync("a", "novo");
        var after = cache.GetSecretAsync("a");     // não pode reaproveitar a leitura anterior à escrita
        gate.SetResult();

        await Assert.That((await before).Value.Value).IsEqualTo("antigo");
        await Assert.That((await after).Value.Value).IsEqualTo("novo");
        await Assert.That(inner.GetCalls).IsEqualTo(2);
    }

    [Test]
    public async Task Leituras_simultaneas_da_mesma_chave_fazem_uma_unica_chamada_ao_cofre()
    {
        var memory = Memory.Secrets();
        await memory.SetSecretAsync("a", "valor");
        var gate = NewSignal();
        var inner = new ScriptedSecretStore(memory) { AfterGet = (_, _) => gate.Task };
        using var cache = new CachingSecretReader(inner, TimeSpan.FromMinutes(5));

        var reads = Enumerable.Range(0, 20).Select(_ => cache.GetSecretAsync("a")).ToList();
        gate.SetResult();
        var results = await Task.WhenAll(reads);

        await Assert.That(inner.GetCalls).IsEqualTo(1);
        await Assert.That(results.All(r => r.Value.Value == "valor")).IsTrue();
    }

    [Test]
    public async Task Cancelamento_de_um_chamador_nao_cancela_os_demais()
    {
        var memory = Memory.Secrets();
        await memory.SetSecretAsync("a", "valor");
        var gate = NewSignal();
        var inner = new ScriptedSecretStore(memory) { AfterGet = (_, _) => gate.Task };
        using var cache = new CachingSecretReader(inner, TimeSpan.FromMinutes(5));
        using var cts = new CancellationTokenSource();

        var cancelled = cache.GetSecretAsync("a", cancellationToken: cts.Token);
        var other = cache.GetSecretAsync("a");
        await cts.CancelAsync();

        await Assert.That(async () => { await cancelled; }).Throws<OperationCanceledException>();
        gate.SetResult();
        await Assert.That((await other).Value.Value).IsEqualTo("valor");
        await Assert.That(inner.GetCalls).IsEqualTo(1);
    }

    [Test]
    public async Task Excecao_compartilhada_nao_fica_guardada()
    {
        var memory = Memory.Secrets();
        await memory.SetSecretAsync("a", "valor");
        var gate = NewSignal();
        var inner = new ScriptedSecretStore(memory) { AfterGet = (_, _) => gate.Task, ThrowOnGet = new InvalidOperationException("falha") };
        using var cache = new CachingSecretReader(inner, TimeSpan.FromMinutes(5));

        var first = cache.GetSecretAsync("a");
        var second = cache.GetSecretAsync("a");
        gate.SetResult();
        await Assert.That(async () => { await first; }).Throws<InvalidOperationException>();
        await Assert.That(async () => { await second; }).Throws<InvalidOperationException>();

        inner.ThrowOnGet = null;
        inner.AfterGet = null;
        var recovered = await cache.GetSecretAsync("a");

        await Assert.That(recovered.Value.Value).IsEqualTo("valor");
        await Assert.That(inner.GetCalls).IsEqualTo(2);
    }

    [Test]
    public async Task Leitura_em_andamento_termina_quando_o_cache_e_descartado()
    {
        // Encerramento da aplicação: o container descarta o cache com uma leitura no meio. Antes, guardar o resultado lançava
        // ObjectDisposedException e a tarefa compartilhada nunca terminava (quem aguardava ficava preso)
        var memory = Memory.Secrets();
        await memory.SetSecretAsync("a", "valor");
        var entered = NewSignal();
        var gate = NewSignal();
        var inner = new ScriptedSecretStore(memory) { AfterGet = async (_, _) => { entered.TrySetResult(); await gate.Task; } };
        var cache = new CachingSecretReader(inner, TimeSpan.FromMinutes(5));

        var owner = cache.GetSecretAsync("a");
        var waiter = cache.GetSecretAsync("a");
        await entered.Task;
        cache.Dispose();
        gate.SetResult();

        var results = await Task.WhenAll(owner, waiter).WaitAsync(TimeSpan.FromSeconds(30));
        await Assert.That(results.All(r => r.Value.Value == "valor")).IsTrue();
        await Assert.That(inner.GetCalls).IsEqualTo(1);
    }

    [Test]
    public async Task Escrita_depois_do_descarte_do_cache_devolve_o_proprio_resultado()
    {
        var memory = Memory.Secrets();
        var cache = new CachingSecretReader(memory, TimeSpan.FromMinutes(5));
        var store = new CacheInvalidatingSecretStore(memory, cache);
        await store.SetSecretAsync("a", "1");
        await cache.GetSecretAsync("a");
        cache.Dispose();

        var written = await store.SetSecretAsync("a", "2");       // a limpeza do cache descartado não mascara o resultado
        var failed = await store.SetSecretAsync("nome inválido", "x");
        var read = await cache.GetSecretAsync("a");                // sem cache: vai direto ao provedor

        await Assert.That(written.IsSuccess).IsTrue();
        await Assert.That(failed.IsFailure).IsTrue();
        await Assert.That(read.Value.Value).IsEqualTo("2");
        await Assert.That(() => cache.Invalidate()).ThrowsNothing();
        await Assert.That(() => cache.Dispose()).ThrowsNothing();
    }

    [Test]
    [Arguments(0.001, 1)]      // mínimo de 1 segundo
    [Arguments(10, 10)]        // acompanha durações curtas
    [Arguments(300, 60)]       // no máximo o padrão do MemoryCache (1 minuto)
    public async Task Varredura_de_expirados_acompanha_a_duracao_do_cache(double durationSeconds, int expectedSeconds) =>
        await Assert.That(CachingSecretReader.ScanFrequency(TimeSpan.FromSeconds(durationSeconds))).IsEqualTo(TimeSpan.FromSeconds(expectedSeconds));

    [Test]
    public async Task Falha_compartilhada_nao_e_guardada()
    {
        var gate = NewSignal();
        var inner = new ScriptedSecretStore(Memory.Secrets()) { AfterGet = (_, _) => gate.Task };
        using var cache = new CachingSecretReader(inner, TimeSpan.FromMinutes(5));

        var first = cache.GetSecretAsync("nao-existe");
        var second = cache.GetSecretAsync("nao-existe");
        gate.SetResult();

        await Assert.That((await first).IsFailure).IsTrue();
        await Assert.That((await second).IsFailure).IsTrue();
        await Assert.That(inner.GetCalls).IsEqualTo(1);

        await cache.GetSecretAsync("nao-existe");
        await Assert.That(inner.GetCalls).IsEqualTo(2);
    }
}
