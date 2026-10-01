using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using TEC.Cofre.Common;
using TEC.Cofre.Diagnostics;
using TEC.Cofre.Internal;
using TEC.Core.Common.Results;
using TEC.Core.Cryptography.Hashing;

namespace TEC.Cofre.Providers;

/// <summary>Falha do provedor já convertida: o erro padronizado e um detalhe técnico seguro para log (ex.: "403 ForbiddenByRbac").</summary>
/// <param name="Error">Erro padronizado (<see cref="CofreErrors"/>).</param>
/// <param name="Detail">Detalhe para log. Nunca inclua valores, tokens ou corpo de resposta.</param>
public readonly record struct VaultFailure(Error Error, string Detail);

/// <summary>
/// Base para implementar um provedor de cofre (Azure Key Vault, AWS Secrets Manager, GCP Secret Manager, HashiCorp Vault, Infisical...).
/// Garante o mesmo comportamento em todos: validação de entrada antes da chamada, <see cref="Result"/> em vez de exceção,
/// trilha de auditoria em log (sem valores), <see cref="Activity"/> e métricas para OpenTelemetry (<see cref="CofreDiagnostics"/>).
/// </summary>
public abstract class VaultProviderBase
{
    /// <summary>Valor de <c>error.type</c> nas métricas quando o chamador cancela a operação.</summary>
    internal const string CanceledErrorType = "canceled";

    private readonly ILogger _logger;

    /// <summary>Cria a base.</summary>
    /// <param name="providerName">Nome do provedor (ex.: "AzureKeyVault").</param>
    /// <param name="logger">Logger do provedor.</param>
    protected VaultProviderBase(string providerName, ILogger logger)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(providerName);
        ArgumentNullException.ThrowIfNull(logger);
        ProviderName = providerName;
        _logger = logger;
    }

    /// <summary>Nome do provedor.</summary>
    public string ProviderName { get; }

    /// <summary>
    /// Converte uma exceção do SDK do provedor. Retorne <c>null</c> para exceções desconhecidas: elas são registradas com
    /// a pilha e convertidas em <see cref="CofreErrors.ProviderFailure"/>.
    /// </summary>
    protected abstract VaultFailure? MapException(Exception exception);

    /// <summary>Executa uma operação com retorno.</summary>
    /// <param name="operation">Nome da operação (ex.: "secret.get").</param>
    /// <param name="itemName">Nome do item (para auditoria).</param>
    /// <param name="inputError">Erro de validação de entrada; se informado, a operação não é executada.</param>
    /// <param name="isWrite">Operação de escrita (auditada em Information).</param>
    /// <param name="action">Chamada ao SDK.</param>
    /// <param name="cancellationToken">Cancelamento. Cancelamento solicitado pelo chamador lança <see cref="OperationCanceledException"/>.</param>
    protected async Task<Result<T>> ExecuteAsync<T>(string operation, string? itemName, Error? inputError, bool isWrite,
        Func<CancellationToken, Task<Result<T>>> action, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(action);
        cancellationToken.ThrowIfCancellationRequested();
        var item = itemName ?? "*";

        if (inputError is not null)
        {
            // Entrada recusada: o nome não é registrado como veio (pode ser lixo, texto de ataque ou até um valor colado por engano)
            CofreLog.InvalidInput(_logger, ProviderName, operation, DescribeUntrusted(itemName), inputError.Field ?? "-");
            CofreDiagnostics.RecordOperation(ProviderName, operation, 0, inputError.Code);
            return Result<T>.Failure(inputError);
        }

        using var activity = CofreDiagnostics.ActivitySource.StartActivity($"Cofre {operation}", ActivityKind.Client);
        activity?.SetTag("cofre.provider", ProviderName);
        activity?.SetTag("cofre.operation", operation);
        long start = Stopwatch.GetTimestamp();

        Result<T> result;
        string detail;
        try
        {
            result = await action(cancellationToken).ConfigureAwait(false);
            detail = result.IsSuccess ? string.Empty : "validação do provedor";
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            activity?.SetTag(CofreDiagnostics.ErrorTypeTag, CanceledErrorType);
            activity?.SetStatus(ActivityStatusCode.Error, "cancelado");
            CofreDiagnostics.RecordOperation(ProviderName, operation, Stopwatch.GetElapsedTime(start).TotalSeconds, CanceledErrorType);
            throw;
        }
        catch (Exception ex)
        {
            var mapped = MapException(ex);
            if (mapped is null)
            {
                var error = CofreErrors.ProviderFailure();
                CofreLog.UnexpectedException(_logger, ex, ProviderName, operation, item, ex.GetType().Name, error.Code);
                Complete(activity, error);
                CofreDiagnostics.RecordOperation(ProviderName, operation, Stopwatch.GetElapsedTime(start).TotalSeconds, error.Code);
                return Result<T>.Failure(error);
            }

            result = Result<T>.Failure(mapped.Value.Error);
            detail = mapped.Value.Detail;
        }

        var elapsedTime = Stopwatch.GetElapsedTime(start);
        long elapsed = (long)elapsedTime.TotalMilliseconds;
        Complete(activity, result.Error);
        CofreDiagnostics.RecordOperation(ProviderName, operation, elapsedTime.TotalSeconds, result.Error?.Code);

        if (result.IsSuccess)
        {
            if (isWrite)
                CofreLog.WriteSucceeded(_logger, ProviderName, operation, item, elapsed);
            else
                CofreLog.ReadSucceeded(_logger, ProviderName, operation, item, elapsed);
        }
        else
        {
            var error = result.Error!;
            if (error.Type is ErrorType.ExternalService or ErrorType.Failure)
                CofreLog.InfrastructureFailure(_logger, ProviderName, operation, item, error.Code, detail);
            else if (isWrite)
                CofreLog.WriteFailure(_logger, ProviderName, operation, item, error.Code, detail);
            else
                CofreLog.ExpectedFailure(_logger, ProviderName, operation, item, error.Code, detail);
        }

        return result;
    }

    /// <summary>Executa uma operação sem retorno.</summary>
    protected async Task<Result> ExecuteAsync(string operation, string? itemName, Error? inputError, bool isWrite,
        Func<CancellationToken, Task> action, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(action);
        var result = await ExecuteAsync<bool>(operation, itemName, inputError, isWrite, async ct =>
        {
            await action(ct).ConfigureAwait(false);
            return true;
        }, cancellationToken).ConfigureAwait(false);

        return result.IsSuccess ? Result.Success() : result.ToFailure();
    }

    /// <summary>
    /// Cópia das tags para os modelos (o chamador e o SDK não alteram o que foi devolvido ou guardado); sem tags, a instância
    /// vazia compartilhada.
    /// </summary>
    protected static IReadOnlyDictionary<string, string> CopyTags(IEnumerable<KeyValuePair<string, string>>? tags)
    {
        if (tags is null)
            return VaultItemProperties.EmptyTags;

        var copy = new Dictionary<string, string>(tags, StringComparer.Ordinal);
        return copy.Count == 0 ? VaultItemProperties.EmptyTags : copy;
    }

    /// <summary>
    /// Registra em <c>Information</c> (trilha de auditoria) uma leitura sensível bem-sucedida que não é escrita, por exemplo a
    /// leitura de um segredo gerenciado que contém a chave privada de um certificado. Nunca inclua valores em <paramref name="reason"/>.
    /// </summary>
    /// <param name="operation">Nome da operação (ex.: "secret.get").</param>
    /// <param name="itemName">Nome do item (já validado).</param>
    /// <param name="reason">Motivo da auditoria (texto fixo).</param>
    protected void AuditSensitiveRead(string operation, string itemName, string reason) =>
        CofreLog.SensitiveRead(_logger, ProviderName, operation, itemName, reason);

    /// <summary>
    /// Chave do HMAC de <see cref="DescribeUntrusted"/>: aleatória e exclusiva deste processo, nunca gravada nem exposta.
    /// Sem ela o identificador do log não permite confirmar palpites sobre o texto recusado.
    /// </summary>
    private static readonly byte[] UntrustedNameKey = RandomNumberGenerator.GetBytes(32);

    /// <summary>
    /// Descreve um nome recusado na validação sem reproduzi-lo: só o tamanho e um prefixo do HMAC-SHA256 com chave aleatória
    /// do processo. O "nome" pode ser um valor de segredo colado por engano: um hash sem chave permitiria conferir palpites
    /// fora do processo. O prefixo serve só para correlacionar ocorrências do mesmo texto dentro do mesmo processo.
    /// </summary>
    internal static string DescribeUntrusted(string? itemName)
    {
        if (itemName is null)
            return "*";
        if (itemName.Length == 0)
            return "<vazio>";

        byte[] text = Encoding.UTF8.GetBytes(itemName);
        try
        {
            string id = Convert.ToHexString(HashHelper.ComputeHmac(text, UntrustedNameKey), 0, 6);
            return $"<recusado: {itemName.Length} caracteres, hmac:{id}>";
        }
        finally
        {
            CryptographicOperations.ZeroMemory(text);
        }
    }

    private static void Complete(Activity? activity, Error? error)
    {
        if (activity is null)
            return;

        activity.SetTag("cofre.success", error is null);
        if (error is not null)
        {
            activity.SetTag("cofre.error_code", error.Code);
            // Mesmo atributo da métrica cofre.operation.duration (convenção do OpenTelemetry)
            activity.SetTag(CofreDiagnostics.ErrorTypeTag, error.Code);
            activity.SetStatus(ActivityStatusCode.Error, error.Code);
        }
    }
}
