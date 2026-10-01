using System.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using TEC.Cofre.Abstractions;
using TEC.Cofre.Common;
using TEC.Cofre.Internal;
using TEC.Cofre.Secrets;
using TEC.Core.Common.Guards;

namespace TEC.Cofre.Configuration;

/// <summary>Opções do provedor de configuração do cofre.</summary>
public sealed class CofreConfigurationOptions
{
    /// <summary>
    /// Carrega apenas segredos cujo nome começa com este prefixo (sem diferenciar maiúsculas), removendo-o da chave.
    /// Recomendado: um prefixo por aplicação (ex.: "MinhaApi--"), para que cada aplicação só carregue o que é seu.
    /// </summary>
    public string? Prefix { get; set; }

    /// <summary>Separador de seções no nome do segredo. Padrão: "--" ("ConnectionStrings--Default" → "ConnectionStrings:Default").</summary>
    public string SectionSeparator
    {
        get;
        set
        {
            Guard.Against(string.IsNullOrEmpty(value), "Informe o separador.", nameof(SectionSeparator));
            field = value;
        }
    } = "--";

    /// <summary>
    /// Intervalo de recarga (mínimo 1 minuto). <c>null</c> (padrão) = carrega só na inicialização.
    /// Falhas na recarga mantêm os valores anteriores (e são registradas em log).
    /// </summary>
    /// <remarks>
    /// A recarga é incremental: só são lidos os segredos cuja versão (ou data de atualização) mudou desde a última carga.
    /// A cada <see cref="FullReloadEvery"/> recargas, todos são relidos (cobre mudanças no mesmo segundo da carga anterior).
    /// </remarks>
    public TimeSpan? ReloadInterval
    {
        get;
        set => field = value is null || value >= TimeSpan.FromMinutes(1)
            ? value
            : throw new ArgumentOutOfRangeException(nameof(ReloadInterval), "A recarga deve ser de no mínimo 1 minuto.");
    }

    /// <summary>
    /// Se <c>true</c>, falha ao acessar o cofre na inicialização não impede a aplicação de subir (configuração vazia).
    /// Padrão: <c>false</c> (fail closed: sem os segredos a aplicação não sobe).
    /// </summary>
    /// <remarks>
    /// Depois de uma carga bem-sucedida, uma nova carga que falhe (ex.: <c>IConfigurationRoot.Reload()</c> com o cofre fora
    /// do ar) mantém os valores anteriores, como a recarga periódica: os segredos já carregados não são apagados.
    /// </remarks>
    public bool Optional { get; set; }

    /// <summary>Máximo de segredos carregados (proteção contra carga acidental do cofre inteiro). Padrão: 500.</summary>
    public int MaxSecrets
    {
        get;
        set => field = Guard.Positive(value, nameof(MaxSecrets));
    } = 500;

    /// <summary>
    /// Tempo máximo de cada carga (inicial ou recarga), somando a listagem e todas as leituras. Padrão: 30 segundos (máximo 10 minutos).
    /// A carga inicial bloqueia a inicialização da aplicação: sem limite, um cofre lento a travaria indefinidamente.
    /// </summary>
    public TimeSpan LoadTimeout
    {
        get;
        set => field = value > TimeSpan.Zero && value <= TimeSpan.FromMinutes(10)
            ? value
            : throw new ArgumentOutOfRangeException(nameof(LoadTimeout), "O tempo limite deve ser maior que zero e no máximo 10 minutos.");
    } = TimeSpan.FromSeconds(30);

    /// <summary>Máximo de leituras simultâneas de segredos durante a carga (1 a 16). Padrão: 4 (evita throttling do cofre).</summary>
    public int MaxConcurrentReads
    {
        get;
        set => field = Guard.InRange(value, 1, 16, nameof(MaxConcurrentReads));
    } = 4;

    /// <summary>A cada quantas recargas incrementais é feita uma releitura completa.</summary>
    public const int FullReloadEvery = 12;
}

internal sealed class CofreConfigurationSource(ISecretReader store, CofreConfigurationOptions options, TimeProvider time, ILoggerFactory? loggerFactory)
    : IConfigurationSource
{
    public IConfigurationProvider Build(IConfigurationBuilder builder) =>
        new CofreConfigurationProvider(store, options, time, loggerFactory?.CreateLogger<CofreConfigurationProvider>());
}

/// <summary>
/// Carrega segredos habilitados e dentro da validade como configuração. Segredos gerenciados (de certificados) são ignorados.
/// </summary>
internal sealed class CofreConfigurationProvider : ConfigurationProvider, IDisposable
{
    private readonly ISecretReader _store;
    private readonly CofreConfigurationOptions _options;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private ITimer? _timer;
    private int _reloading;
    private int _reloadsSinceFull;

    // Última carga bem-sucedida: nome do segredo → versão/atualização e valor, para a recarga incremental
    private Dictionary<string, Snapshot> _snapshot = new(StringComparer.OrdinalIgnoreCase);

    private bool _loaded;

    /// <summary>Segredo da última carga. <see cref="ToString"/> e o depurador mascaram o valor (o gerado pelo <c>record</c> o imprimiria).</summary>
    [DebuggerDisplay("{ToString(),nq}")]
    internal readonly record struct Snapshot(string? Version, DateTimeOffset? UpdatedOn, string Key, string Value)
    {
        public override string ToString() => $"Snapshot {{ Version = {Version}, UpdatedOn = {UpdatedOn:O}, Key = {Key}, Value = *** }}";
    }

    public CofreConfigurationProvider(ISecretReader store, CofreConfigurationOptions options, TimeProvider time, ILogger? logger = null)
    {
        _store = store;
        _options = options;
        _time = time;
        _logger = logger ?? NullLogger.Instance;
    }

    public override void Load()
    {
        // O pipeline de configuração é síncrono: a carga inicial bloqueia até ler o cofre (mesmo comportamento do provedor
        // oficial do Azure), limitada por LoadTimeout
        var outcome = LoadDataAsync(incremental: false).GetAwaiter().GetResult();
        if (outcome.Data is null)
        {
            CofreLog.ConfigurationLoadFailed(_logger, _store.ProviderName, outcome.ErrorCode);
            if (!_options.Optional)
            {
                throw new InvalidOperationException(
                    $"Não foi possível carregar a configuração do cofre ({outcome.ErrorCode}). Verifique o log e as permissões da identidade da aplicação.");
            }

            // Optional: sobe com configuração vazia só se nunca houve carga. Depois de uma carga bem-sucedida (Reload() do
            // IConfigurationRoot), a falha mantém os valores anteriores, como a recarga do timer: um cofre fora do ar não
            // pode apagar os segredos já carregados
            if (!_loaded)
                Data = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        }
        else
        {
            Data = outcome.Data;
            _loaded = true;
        }

        if (_options.ReloadInterval is { } interval && _timer is null)
            _timer = _time.CreateTimer(_ => _ = ReloadAsync(), null, interval, interval);
    }

    internal async Task ReloadAsync()
    {
        if (Interlocked.Exchange(ref _reloading, 1) == 1)
            return;

        try
        {
            bool incremental = ++_reloadsSinceFull < CofreConfigurationOptions.FullReloadEvery;
            if (!incremental)
                _reloadsSinceFull = 0;

            var outcome = await LoadDataAsync(incremental).ConfigureAwait(false);
            if (outcome.Data is null)
            {
                CofreLog.ConfigurationReloadFailed(_logger, _store.ProviderName, outcome.ErrorCode);
                return;
            }

            if (HasSameData(outcome.Data))
                return;

            Data = outcome.Data;
            OnReload();
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // Mantém os valores atuais (exceção vinda do provedor ou do OnReload de um assinante)
            CofreLog.ConfigurationReloadException(_logger, ex, _store.ProviderName, ex.GetType().Name);
        }
        finally
        {
            Volatile.Write(ref _reloading, 0);
        }
    }

    /// <summary>Código lógico (não é de <see cref="CofreErrors"/>) para carga interrompida pelo tempo limite.</summary>
    internal const string TimeoutCode = "TEMPO_LIMITE";

    /// <summary>Código lógico para filtro acima de <see cref="CofreConfigurationOptions.MaxSecrets"/>.</summary>
    internal const string TooManySecretsCode = "LIMITE_MAX_SECRETS";

    private readonly record struct LoadOutcome(Dictionary<string, string?>? Data, string ErrorCode);

    private async Task<LoadOutcome> LoadDataAsync(bool incremental)
    {
        long start = Stopwatch.GetTimestamp();
        using var timeout = new CancellationTokenSource(_options.LoadTimeout, _time);
        try
        {
            return await LoadDataCoreAsync(incremental, start, timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested)
        {
            CofreLog.ConfigurationTimeout(_logger, _store.ProviderName, _options.LoadTimeout.TotalSeconds);
            return new LoadOutcome(null, TimeoutCode);
        }
    }

    private async Task<LoadOutcome> LoadDataCoreAsync(bool incremental, long start, CancellationToken cancellationToken)
    {
        var list = await _store.ListSecretsAsync(cancellationToken).ConfigureAwait(false);
        if (list.IsFailure)
            return new LoadOutcome(null, list.Error!.Code);

        var now = _time.GetUtcNow();
        var prefix = _options.Prefix ?? string.Empty;
        var candidates = list.Value
            .Where(p => !p.IsManaged && p.IsActive(now) && p.Name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) && p.Name.Length > prefix.Length)
            .ToList();

        if (candidates.Count > _options.MaxSecrets)
        {
            CofreLog.ConfigurationTooManySecrets(_logger, _store.ProviderName, candidates.Count, _options.MaxSecrets);
            return new LoadOutcome(null, TooManySecretsCode);
        }

        var previous = Volatile.Read(ref _snapshot);
        var snapshot = new Dictionary<string, Snapshot>(StringComparer.OrdinalIgnoreCase);
        var toRead = new List<SecretProperties>();
        foreach (var properties in candidates)
        {
            if (incremental && previous.TryGetValue(properties.Name, out var known) && IsUnchanged(properties, known))
                snapshot[properties.Name] = known;
            else
                toRead.Add(properties);
        }

        // Leituras em paralelo limitado; a primeira falha cancela as demais
        string? failure = null;
        var read = new System.Collections.Concurrent.ConcurrentDictionary<string, Snapshot>(StringComparer.OrdinalIgnoreCase);
        using var abort = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        try
        {
            await Parallel.ForEachAsync(toRead, new ParallelOptions { MaxDegreeOfParallelism = _options.MaxConcurrentReads, CancellationToken = abort.Token },
                async (properties, ct) =>
                {
                    var secret = await _store.GetSecretAsync(properties.Name, cancellationToken: ct).ConfigureAwait(false);
                    if (secret.IsFailure)
                    {
                        Interlocked.CompareExchange(ref failure, secret.Error!.Code, null);
                        await abort.CancelAsync().ConfigureAwait(false);
                        return;
                    }

                    string key = properties.Name[prefix.Length..].Replace(_options.SectionSeparator, ConfigurationPath.KeyDelimiter, StringComparison.Ordinal);
                    read[properties.Name] = new Snapshot(properties.Version, properties.UpdatedOn, key, secret.Value.Value);
                }).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (failure is not null && !cancellationToken.IsCancellationRequested)
        {
            // Cancelamento provocado pela primeira falha: tratado abaixo
        }

        if (failure is not null)
            return new LoadOutcome(null, failure);

        foreach (var (name, item) in read)
            snapshot[name] = item;

        var data = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in snapshot.Values)
            data[item.Key] = item.Value;

        Volatile.Write(ref _snapshot, snapshot);
        CofreLog.ConfigurationLoaded(_logger, _store.ProviderName, data.Count, read.Count, (long)Stopwatch.GetElapsedTime(start).TotalMilliseconds);
        return new LoadOutcome(data, string.Empty);
    }

    /// <summary>
    /// Inalterado se a versão listada é a mesma (versão identifica o valor) ou, quando o provedor não informa a versão na
    /// listagem, se a data de atualização é a mesma. Sem nenhuma das duas, relê sempre.
    /// </summary>
    private static bool IsUnchanged(SecretProperties properties, Snapshot known) =>
        properties.Version is not null
            ? string.Equals(properties.Version, known.Version, StringComparison.OrdinalIgnoreCase)
            : properties.UpdatedOn is not null && properties.UpdatedOn == known.UpdatedOn;

    private bool HasSameData(Dictionary<string, string?> data) =>
        data.Count == Data.Count && data.All(kv => Data.TryGetValue(kv.Key, out var value) && string.Equals(value, kv.Value, StringComparison.Ordinal));

    public void Dispose() => _timer?.Dispose();
}

/// <summary>Registro do cofre como fonte de configuração.</summary>
public static class CofreConfigurationBuilderExtensions
{
    /// <summary>
    /// Adiciona os segredos do cofre à configuração (<c>IConfiguration</c>), com precedência sobre as fontes adicionadas antes.
    /// </summary>
    /// <remarks>
    /// Os valores ficam em memória no <c>IConfiguration</c> durante toda a vida da aplicação. Para segredos de alto valor,
    /// prefira ler sob demanda com <see cref="ISecretReader"/>. A carga falha se o filtro encontrar mais de
    /// <see cref="CofreConfigurationOptions.MaxSecrets"/> segredos ou se passar de <see cref="CofreConfigurationOptions.LoadTimeout"/>.
    /// O <c>IConfiguration</c> é montado antes do container de DI: informe <paramref name="loggerFactory"/> para que as falhas
    /// de carga e recarga sejam registradas (sem ele, só a exceção da carga inicial informa o motivo).
    /// </remarks>
    /// <example>
    /// <code>
    /// builder.Configuration.AddTecCofre(secretStore, o => { o.Prefix = "MinhaApi--"; o.ReloadInterval = TimeSpan.FromMinutes(30); },
    ///     loggerFactory: LoggerFactory.Create(l => l.AddConsole()));
    /// </code>
    /// </example>
    public static IConfigurationBuilder AddTecCofre(this IConfigurationBuilder builder, ISecretReader store,
        Action<CofreConfigurationOptions>? configure = null, TimeProvider? timeProvider = null, ILoggerFactory? loggerFactory = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(store);

        var options = new CofreConfigurationOptions();
        configure?.Invoke(options);
        return builder.Add(new CofreConfigurationSource(store, options, timeProvider ?? TimeProvider.System, loggerFactory));
    }
}
