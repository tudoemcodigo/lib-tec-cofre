using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using TEC.Cofre.Abstractions;
using TEC.Cofre.Caching;
using TEC.Cofre.HealthChecks;
using TEC.Core.Common.Results;

namespace TEC.Cofre.DependencyInjection;

/// <summary>Registro do cofre no container de injeção de dependência.</summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registra o cofre com o provedor escolhido. Cada interface que o provedor implementa é registrada apontando para a mesma
    /// instância (singleton, thread-safe):
    /// <list type="bullet">
    /// <item><description>Segredos: <see cref="ISecretReader"/>, <see cref="ISecretStore"/>, <see cref="ISecretRecycleBin"/>, <see cref="ISecretBackup"/>.</description></item>
    /// <item><description>Chaves: <see cref="IKeyReader"/>, <see cref="IKeyStore"/>, <see cref="IKeyCryptography"/>, <see cref="IKeyRecycleBin"/>, <see cref="IKeyBackup"/>.</description></item>
    /// <item><description>Certificados: <see cref="ICertificateReader"/>, <see cref="ICertificateStore"/>, <see cref="ICertificateRecycleBin"/>, <see cref="ICertificateBackup"/>.</description></item>
    /// <item><description><see cref="IVaultHealthProbe"/>.</description></item>
    /// </list>
    /// Interfaces que o provedor não implementa não são registradas (ex.: um provedor sem backup não registra <see cref="ISecretBackup"/>).
    /// </summary>
    /// <remarks>
    /// <para>Com <see cref="CofreBuilder.EnableSecretCache"/>, <see cref="ISecretReader"/> é o cache e <see cref="ISecretStore"/>,
    /// <see cref="ISecretRecycleBin"/> e <see cref="ISecretBackup"/> são decorators que limpam o cache após cada escrita.
    /// A classe concreta do provedor também fica registrada e <b>não</b> passa pelo cache: escritas feitas por ela não limpam
    /// o cache (grave sempre pelas interfaces).</para>
    /// <para><see cref="IVaultHealthProbe"/> é registrado em qualquer combinação de stores e verifica <b>cada</b> instância de provedor,
    /// com a permissão que ela exige (ex.: só chaves → lista chaves; não exige permissão de segredos). Provedores que implementam
    /// <see cref="IVaultHealthProbe"/> usam a própria sonda; os demais, a listagem de metadados do leitor. Um <see cref="IVaultHealthProbe"/>
    /// registrado antes pela aplicação é mantido.</para>
    /// </remarks>
    /// <exception cref="InvalidOperationException">Chamado mais de uma vez, ou nenhum provedor configurado.</exception>
    /// <example>
    /// <code>
    /// builder.Services.AddTecCofre(cofre => cofre.UseAzureKeyVault(o =>
    /// {
    ///     o.VaultUri = new Uri("https://kv-minha-app.vault.azure.net/");
    ///     o.Authentication = builder.Environment.IsDevelopment()
    ///         ? AzureKeyVaultAuthentication.Developer
    ///         : AzureKeyVaultAuthentication.ManagedIdentity;
    /// }));
    /// </code>
    /// </example>
    public static IServiceCollection AddTecCofre(this IServiceCollection services, Action<CofreBuilder> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        if (services.Any(d => d.ServiceType == typeof(CofreBuilder)))
            throw new InvalidOperationException("AddTecCofre já foi chamado. Configure o cofre em uma única chamada.");

        var builder = new CofreBuilder(services);
        configure(builder);

        if (builder.Secrets is null && builder.Keys is null && builder.Certificates is null)
            throw new InvalidOperationException("Nenhum provedor de cofre configurado. Ex.: cofre.UseAzureKeyVault(...).");

        services.AddSingleton(builder);

        if (builder.Secrets is { } secrets)
        {
            if (builder.SecretCacheDuration is { } duration)
                AddCachedSecrets(services, secrets, duration);
            else
            {
                AddAs<ISecretReader>(services, secrets);
                AddAs<ISecretStore>(services, secrets);
                AddAs<ISecretRecycleBin>(services, secrets);
                AddAs<ISecretBackup>(services, secrets);
            }
        }

        if (builder.Keys is { } keys)
        {
            AddAs<IKeyReader>(services, keys);
            AddAs<IKeyStore>(services, keys);
            AddAs<IKeyCryptography>(services, keys);
            AddAs<IKeyRecycleBin>(services, keys);
            AddAs<IKeyBackup>(services, keys);
        }

        if (builder.Certificates is { } certificates)
        {
            AddAs<ICertificateReader>(services, certificates);
            AddAs<ICertificateStore>(services, certificates);
            AddAs<ICertificateRecycleBin>(services, certificates);
            AddAs<ICertificateBackup>(services, certificates);
        }

        services.TryAddSingleton<IVaultHealthProbe>(sp => new CofreHealthProbe(CreateHealthChecks(sp, builder)));

        return services;
    }

    private static bool Implements<TService>(CofreBuilder.Registration registration) =>
        typeof(TService).IsAssignableFrom(registration.ImplementationType);

    /// <summary>Registra <typeparamref name="TService"/> apontando para a instância do provedor, se ele implementar a interface.</summary>
    private static void AddAs<TService>(IServiceCollection services, CofreBuilder.Registration registration) where TService : class
    {
        if (Implements<TService>(registration))
            services.AddSingleton(sp => (TService)registration.Resolve(sp));
    }

    private static void AddCachedSecrets(IServiceCollection services, CofreBuilder.Registration secrets, TimeSpan duration)
    {
        services.AddSingleton(sp => new CachingSecretReader((ISecretReader)secrets.Resolve(sp), duration));
        services.AddSingleton<ISecretReader>(sp => sp.GetRequiredService<CachingSecretReader>());

        if (Implements<ISecretStore>(secrets))
        {
            services.AddSingleton<ISecretStore>(sp =>
                new CacheInvalidatingSecretStore((ISecretStore)secrets.Resolve(sp), sp.GetRequiredService<CachingSecretReader>()));
        }

        if (Implements<ISecretRecycleBin>(secrets))
        {
            services.AddSingleton<ISecretRecycleBin>(sp =>
                new CacheInvalidatingSecretRecycleBin((ISecretRecycleBin)secrets.Resolve(sp), sp.GetRequiredService<CachingSecretReader>()));
        }

        if (Implements<ISecretBackup>(secrets))
        {
            services.AddSingleton<ISecretBackup>(sp =>
                new CacheInvalidatingSecretBackup((ISecretBackup)secrets.Resolve(sp), sp.GetRequiredService<CachingSecretReader>()));
        }
    }

    /// <summary>Uma verificação por instância de provedor (a mesma classe pode atender mais de uma família).</summary>
    private static List<Func<CancellationToken, Task<Result>>> CreateHealthChecks(IServiceProvider sp, CofreBuilder builder)
    {
        var checks = new List<Func<CancellationToken, Task<Result>>>();
        var seen = new HashSet<object>(ReferenceEqualityComparer.Instance);

        void Add(CofreBuilder.Registration? registration, Func<object, Func<CancellationToken, Task<Result>>?> fallback)
        {
            if (registration is null)
                return;

            var store = registration.Resolve(sp);
            if (!seen.Add(store))
                return;

            var check = store is IVaultHealthProbe probe ? probe.CheckAccessAsync : fallback(store);
            if (check is not null)
                checks.Add(check);
        }

        Add(builder.Secrets, store => store is ISecretReader reader
            ? async ct => ToResult(await reader.ListSecretsAsync(ct).ConfigureAwait(false))
            : null);
        Add(builder.Keys, store => store is IKeyReader reader
            ? async ct => ToResult(await reader.ListKeysAsync(ct).ConfigureAwait(false))
            : null);   // só IKeyCryptography e sem sonda própria: não há operação barata e sem efeito para verificar
        Add(builder.Certificates, store => store is ICertificateReader reader
            ? async ct => ToResult(await reader.ListCertificatesAsync(ct).ConfigureAwait(false))
            : null);

        return checks;
    }

    private static Result ToResult(Result result) => result.IsSuccess ? Result.Success() : result.ToFailure();
}
