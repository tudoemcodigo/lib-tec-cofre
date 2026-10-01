using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging;
using TEC.Cofre.Abstractions;
using TEC.Cofre.Internal;
using TEC.Core.Common.Results;

namespace TEC.Cofre.HealthChecks;

/// <summary>
/// Health check do cofre: verifica acesso sem ler valores. A resposta nunca traz detalhes (endpoints de health costumam ser
/// públicos); o motivo da falha vai apenas para o log.
/// </summary>
internal sealed class CofreHealthCheck(IVaultHealthProbe probe, ILogger<CofreHealthCheck> logger) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        var result = await probe.CheckAccessAsync(cancellationToken).ConfigureAwait(false);
        if (result.IsSuccess)
            return HealthCheckResult.Healthy("Cofre acessível.");

        CofreLog.HealthCheckFailed(logger, result.Error!.Code);
        return new HealthCheckResult(context.Registration.FailureStatus, "Cofre inacessível.");
    }
}

/// <summary>
/// Sonda registrada por <c>AddTecCofre</c>: verifica todos os stores registrados em paralelo; saudável só se todos responderem.
/// </summary>
internal sealed class CofreHealthProbe(IReadOnlyList<Func<CancellationToken, Task<Result>>> checks) : IVaultHealthProbe
{
    internal int Count => checks.Count;

    public async Task<Result> CheckAccessAsync(CancellationToken cancellationToken = default)
    {
        var results = await Task.WhenAll(checks.Select(check => check(cancellationToken))).ConfigureAwait(false);
        return results.FirstOrDefault(r => r.IsFailure) ?? Result.Success();
    }
}

/// <summary>Registro do health check do cofre.</summary>
public static class CofreHealthChecksBuilderExtensions
{
    /// <summary>
    /// Tag de readiness, a mesma do TEC.Observability (<c>HealthCheckTags.Ready</c>): o check entra no endpoint
    /// <c>/health/ready</c> do <c>UseEnterpriseObservability</c> e nunca no liveness (cofre fora do ar tira a instância do
    /// balanceamento, sem reiniciá-la).
    /// </summary>
    public const string ReadyTag = "ready";

    /// <summary>Tag do tipo de dependência, no padrão das tags do TEC.Observability (<c>database</c>, <c>sso</c>, <c>external</c>).</summary>
    public const string VaultTag = "vault";

    /// <summary>
    /// Adiciona o health check do cofre (exige <c>AddTecCofre</c>, que registra a sonda de todos os stores configurados,
    /// ou um <see cref="IVaultHealthProbe"/> próprio).
    /// </summary>
    /// <param name="builder">Builder de health checks (ex.: <c>services.AddHealthChecks()</c> ou o <c>HealthChecks</c> do TEC.Observability).</param>
    /// <param name="name">Nome da verificação.</param>
    /// <param name="failureStatus">Status em caso de falha. Padrão: <see cref="HealthStatus.Unhealthy"/>.</param>
    /// <param name="tags">Tags. Padrão (<c>null</c>): <see cref="ReadyTag"/> e <see cref="VaultTag"/>; informar substitui as duas.</param>
    /// <param name="timeout">Tempo máximo da verificação. Padrão: 10 segundos.</param>
    /// <example>
    /// <code>
    /// // Com o TEC.Observability: aparece em /health/ready
    /// builder.Services.AddEnterpriseObservability(builder.Configuration).HealthChecks.AddTecCofre();
    ///
    /// // Sem ele
    /// builder.Services.AddHealthChecks().AddTecCofre();
    /// </code>
    /// </example>
    public static IHealthChecksBuilder AddTecCofre(this IHealthChecksBuilder builder, string name = "cofre",
        HealthStatus? failureStatus = null, IEnumerable<string>? tags = null, TimeSpan? timeout = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder.Add(new HealthCheckRegistration(name,
            sp => ActivatorUtilities.CreateInstance<CofreHealthCheck>(sp), failureStatus, tags ?? [ReadyTag, VaultTag],
            timeout ?? TimeSpan.FromSeconds(10)));
    }
}
