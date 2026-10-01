using TEC.Cofre.Abstractions;
using TEC.Cofre.Common;
using TEC.Cofre.Providers;
using TEC.Core.Common.Results;
using TEC.Core.Cryptography.Generators;

namespace TEC.Cofre.Secrets;

/// <summary>Operações de segredo que funcionam com qualquer provedor.</summary>
public static class SecretStoreExtensions
{
    /// <summary>
    /// Gera um segredo forte (gerador criptográfico do TEC.Core) e grava no cofre. O valor gerado <b>não</b> é retornado:
    /// quem precisar dele lê do cofre, com a própria identidade e permissão (Zero Trust).
    /// </summary>
    /// <example>
    /// <code>
    /// var result = await cofre.GenerateSecretAsync("api-parceiro-token",
    ///     new SecretGenerationOptions { Kind = SecretGenerationKind.Token },
    ///     new SecretWriteOptions { ExpiresOn = DateTimeOffset.UtcNow.AddDays(90) });
    /// </code>
    /// </example>
    public static Task<Result<SecretProperties>> GenerateSecretAsync(this ISecretStore store, string name,
        SecretGenerationOptions? generation = null, SecretWriteOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(store);

        var generated = Generate(generation ?? new SecretGenerationOptions());
        if (generated.IsFailure)
            return Task.FromResult(generated.ToFailure<SecretProperties>());

        return store.SetSecretAsync(name, generated.Value, options, cancellationToken);
    }

    /// <summary>
    /// Rotaciona o segredo: grava uma nova versão gerada aleatoriamente, mantendo o tipo de conteúdo e as tags da versão atual.
    /// </summary>
    /// <param name="store">Cofre.</param>
    /// <param name="name">Nome do segredo (precisa existir).</param>
    /// <param name="generation">Parâmetros de geração.</param>
    /// <param name="validity">Validade da nova versão (recomendado). <c>null</c> = sem expiração.</param>
    /// <param name="disablePreviousVersions">
    /// Desabilita as versões anteriores após gravar a nova. Use somente quando nenhum consumidor depende mais delas;
    /// caso contrário, deixe expirarem.
    /// </param>
    /// <param name="timeProvider">Relógio usado para calcular a expiração. Padrão: <see cref="TimeProvider.System"/>.</param>
    /// <param name="cancellationToken">Cancelamento.</param>
    /// <returns>
    /// Falha se nada foi gravado. Sucesso assim que a nova versão é gravada; se alguma versão anterior não pôde ser
    /// desabilitada, <see cref="SecretRotationResult.IsComplete"/> é <c>false</c> (veja <see cref="SecretRotationResult"/>).
    /// </returns>
    public static async Task<Result<SecretRotationResult>> RotateSecretAsync(this ISecretStore store, string name,
        SecretGenerationOptions? generation = null, TimeSpan? validity = null, bool disablePreviousVersions = false,
        TimeProvider? timeProvider = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(store);
        if (validity is { } v && v <= TimeSpan.Zero)
            return CofreErrors.InvalidInput(nameof(validity), "A validade deve ser maior que zero.");

        var versions = await store.ListSecretVersionsAsync(name, cancellationToken).ConfigureAwait(false);
        if (versions.IsFailure)
            return versions.ToFailure<SecretRotationResult>();

        var current = await CurrentVersionAsync(store, name, versions.Value, cancellationToken).ConfigureAwait(false);
        if (current.IsFailure)
            return current.ToFailure<SecretRotationResult>();
        if (current.Value.IsManaged)
            return CofreErrors.InvalidInput(nameof(name), "Segredos gerenciados pelo provedor (ex.: de certificados) não podem ser rotacionados diretamente.");

        var generated = Generate(generation ?? new SecretGenerationOptions());
        if (generated.IsFailure)
            return generated.ToFailure<SecretRotationResult>();

        var now = (timeProvider ?? TimeProvider.System).GetUtcNow();
        var written = await store.SetSecretAsync(name, generated.Value, new SecretWriteOptions
        {
            ContentType = current.Value.ContentType,
            Tags = current.Value.Tags,
            ExpiresOn = validity is null ? null : now.Add(validity.Value)
        }, cancellationToken).ConfigureAwait(false);

        if (written.IsFailure)
            return written.ToFailure<SecretRotationResult>();
        if (!disablePreviousVersions)
            return new SecretRotationResult { Current = written.Value };

        return await DisableOthersAsync(store, name, written.Value, versions.Value, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Desabilita todas as versões habilitadas do segredo, exceto <paramref name="currentVersion"/>. Idempotente: use para
    /// concluir uma rotação cujo <see cref="SecretRotationResult.IsComplete"/> veio <c>false</c>, sem criar nova versão.
    /// </summary>
    /// <param name="store">Cofre.</param>
    /// <param name="name">Nome do segredo.</param>
    /// <param name="currentVersion">Versão que continua habilitada (precisa existir).</param>
    /// <param name="cancellationToken">Cancelamento.</param>
    public static async Task<Result<SecretRotationResult>> DisablePreviousSecretVersionsAsync(this ISecretStore store, string name,
        string currentVersion, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(store);
        if (string.IsNullOrEmpty(currentVersion))
            return CofreErrors.InvalidInput(nameof(currentVersion), "A versão atual é obrigatória.");

        var versions = await store.ListSecretVersionsAsync(name, cancellationToken).ConfigureAwait(false);
        if (versions.IsFailure)
            return versions.ToFailure<SecretRotationResult>();

        var current = versions.Value.FirstOrDefault(p => string.Equals(p.Version, currentVersion, StringComparison.OrdinalIgnoreCase));
        if (current is null)
            return CofreErrors.NotFound();

        return await DisableOthersAsync(store, name, current, versions.Value, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<SecretRotationResult> DisableOthersAsync(ISecretStore store, string name, SecretProperties current,
        IReadOnlyList<SecretProperties> versions, CancellationToken cancellationToken)
    {
        var disabledVersions = new List<string>();
        var failedVersions = new List<string>();
        var errors = new List<Error>();

        // Tenta todas, mesmo após uma falha: deixa o mínimo possível de versões antigas habilitadas
        foreach (var old in versions.Where(p => p.Enabled && p.Version is not null
            && !string.Equals(p.Version, current.Version, StringComparison.OrdinalIgnoreCase)))
        {
            var disabled = await store.UpdateSecretPropertiesAsync(name, new SecretPropertiesUpdate { Enabled = false }, old.Version,
                cancellationToken).ConfigureAwait(false);
            if (disabled.IsSuccess)
            {
                disabledVersions.Add(old.Version!);
            }
            else
            {
                failedVersions.Add(old.Version!);
                errors.Add(disabled.Error!);
            }
        }

        return new SecretRotationResult { Current = current, DisabledVersions = disabledVersions, FailedVersions = failedVersions, Errors = errors };
    }

    /// <summary>
    /// Versão atual do segredo: a de maior <see cref="Common.VaultItemProperties.CreatedOn"/>. Os provedores costumam ter
    /// resolução de 1 segundo; em empate a listagem não diz qual é a atual, então o provedor é consultado (leitura sem versão,
    /// que retorna a atual; o valor é descartado). Se a atual estiver desabilitada, desempata por <c>UpdatedOn</c> e versão.
    /// </summary>
    internal static async Task<Result<SecretProperties>> CurrentVersionAsync(ISecretReader store, string name,
        IReadOnlyList<SecretProperties> versions, CancellationToken cancellationToken)
    {
        if (versions.Count == 0)
            return CofreErrors.NotFound();

        var newest = VaultVersionRules.Newest(versions, p => p.CreatedOn);
        if (newest.Count == 1)
            return newest[0];

        var read = await store.GetSecretAsync(name, cancellationToken: cancellationToken).ConfigureAwait(false);
        if (read.IsSuccess)
        {
            return versions.FirstOrDefault(p => string.Equals(p.Version, read.Value.Version, StringComparison.OrdinalIgnoreCase))
                ?? read.Value.Properties;
        }

        if (read.Error!.Code != CofreErrors.DisabledCode)
            return read.ToFailure<SecretProperties>();

        return VaultVersionRules.BreakTie(newest, p => p.UpdatedOn, p => p.Version);
    }

    internal static Result<string> Generate(SecretGenerationOptions options)
    {
        if (options.Length is < 16 or > 1024)
            return CofreErrors.InvalidInput(nameof(options.Length), "O tamanho deve estar entre 16 e 1024.");

        return options.Kind switch
        {
            SecretGenerationKind.Password => SecureRandomGenerator.GeneratePassword(options.Length, includeSpecial: options.IncludeSpecialCharacters),
            SecretGenerationKind.Token => SecureRandomGenerator.GenerateToken(options.Length),
            SecretGenerationKind.Hex => SecureRandomGenerator.GenerateHex(options.Length),
            _ => CofreErrors.InvalidInput(nameof(options.Kind), "Formato de geração inválido.")
        };
    }
}
