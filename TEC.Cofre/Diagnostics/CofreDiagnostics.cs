using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace TEC.Cofre.Diagnostics;

/// <summary>Rastreamento e métricas (OpenTelemetry) do cofre.</summary>
/// <remarks>
/// Segurança: nenhum trace ou métrica leva o nome do item (traces e métricas costumam ser enviados a terceiros); o nome fica
/// apenas no log de auditoria. As dimensões são de baixa cardinalidade: provedor, operação e código do erro.
/// </remarks>
/// <example>
/// <code>
/// // Com o TEC.Observability nada é preciso: o AddEnterpriseObservability exporta as fontes "TEC.*". Sem ele:
/// builder.Services.AddOpenTelemetry()
///     .WithTracing(t => t.AddSource(CofreDiagnostics.ActivitySourceName))
///     .WithMetrics(m => m.AddMeter(CofreDiagnostics.MeterName));
/// </code>
/// </example>
public static class CofreDiagnostics
{
    /// <summary>
    /// Nome do <see cref="System.Diagnostics.ActivitySource"/>. Cada operação gera uma <c>Activity</c> (Client) com as tags
    /// <c>cofre.provider</c>, <c>cofre.operation</c>, <c>cofre.success</c>, <c>cofre.error_code</c> e, em falha,
    /// <c>error.type</c> (o mesmo valor da métrica).
    /// </summary>
    public const string ActivitySourceName = "TEC.Cofre";

    /// <summary>
    /// Nome do <see cref="System.Diagnostics.Metrics.Meter"/>. Instrumentos:
    /// <list type="bullet">
    /// <item><description><see cref="OperationDurationName"/> (histograma, segundos): toda operação de provedor, com
    /// <c>cofre.provider</c>, <c>cofre.operation</c> (ex.: <c>secret.get</c>) e, em falha, <c>error.type</c> (código de
    /// <c>CofreErrors</c>, ou <c>canceled</c>). A contagem por tipo/resultado vem do próprio histograma.</description></item>
    /// <item><description><see cref="CacheRequestsName"/> (contador): leituras do cache de segredos, com <c>cofre.provider</c> e
    /// <c>cofre.cache.result</c> = <c>hit</c>, <c>miss</c> (consultou o cofre) ou <c>coalesced</c> (aguardou uma leitura
    /// simultânea da mesma chave).</description></item>
    /// </list>
    /// Exportado sem configuração pelo <c>AddEnterpriseObservability</c> do TEC.Observability (prefixo <c>TEC.*</c>).
    /// </summary>
    public const string MeterName = "TEC.Cofre";

    /// <summary>Histograma da duração das operações (segundos).</summary>
    public const string OperationDurationName = "cofre.operation.duration";

    /// <summary>Contador de leituras do cache de segredos.</summary>
    public const string CacheRequestsName = "cofre.cache.requests";

    internal const string ProviderTag = "cofre.provider";
    internal const string OperationTag = "cofre.operation";
    internal const string ErrorTypeTag = "error.type";
    internal const string CacheResultTag = "cofre.cache.result";

    internal static readonly ActivitySource ActivitySource = new(ActivitySourceName);

    internal static readonly Meter Meter = new(MeterName, typeof(CofreDiagnostics).Assembly.GetName().Version?.ToString());

    internal static readonly Histogram<double> OperationDuration = Meter.CreateHistogram<double>(
        OperationDurationName, unit: "s", description: "Duração das operações do cofre.");

    internal static readonly Counter<long> CacheRequests = Meter.CreateCounter<long>(
        CacheRequestsName, unit: "{request}", description: "Leituras do cache de segredos por resultado.");

    /// <summary>Registra a duração de uma operação. <paramref name="errorType"/> só em falha.</summary>
    internal static void RecordOperation(string provider, string operation, double seconds, string? errorType)
    {
        if (!OperationDuration.Enabled)
            return;

        var tags = new TagList
        {
            { ProviderTag, provider },
            { OperationTag, operation }
        };
        if (errorType is not null)
            tags.Add(ErrorTypeTag, errorType);
        OperationDuration.Record(seconds, tags);
    }

    /// <summary>Registra uma leitura do cache (<c>hit</c>, <c>miss</c> ou <c>coalesced</c>).</summary>
    internal static void RecordCache(string provider, string result)
    {
        if (CacheRequests.Enabled)
            CacheRequests.Add(1, new KeyValuePair<string, object?>(ProviderTag, provider), new KeyValuePair<string, object?>(CacheResultTag, result));
    }
}
