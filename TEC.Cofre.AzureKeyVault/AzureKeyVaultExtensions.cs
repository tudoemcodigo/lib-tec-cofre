using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using TEC.Cofre.Abstractions;
using TEC.Cofre.AzureKeyVault.Internal;
using TEC.Cofre.Configuration;
using TEC.Cofre.DependencyInjection;
using TEC.Cofre.Providers;

namespace TEC.Cofre.AzureKeyVault;

/// <summary>Registro do provedor Azure Key Vault.</summary>
public static class AzureKeyVaultExtensions
{
    /// <summary>
    /// Usa o Azure Key Vault como provedor de segredos, chaves e certificados (os escolhidos em
    /// <see cref="AzureKeyVaultOptions.Stores"/>; padrão: todos). As opções são validadas aqui
    /// (falha na inicialização, não na primeira requisição).
    /// </summary>
    /// <example>
    /// <code>
    /// builder.Services.AddTecCofre(cofre => cofre.UseAzureKeyVault(o =>
    /// {
    ///     o.VaultUri = new Uri(builder.Configuration["Cofre:VaultUri"]!);
    ///     o.Authentication = builder.Environment.IsDevelopment()
    ///         ? AzureKeyVaultAuthentication.Developer
    ///         : AzureKeyVaultAuthentication.ManagedIdentity;
    /// }));
    /// </code>
    /// </example>
    /// <exception cref="InvalidOperationException">Opções inválidas (ex.: endereço fora do domínio do Key Vault).</exception>
    public static CofreBuilder UseAzureKeyVault(this CofreBuilder builder, Action<AzureKeyVaultOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new AzureKeyVaultOptions();
        configure(options);

        options.HostEnvironment ??= VaultEnvironment.FindHostEnvironment(builder.Services);

        var clients = new AzureKeyVaultClients(options);   // valida as opções, inclusive Stores

        return builder.UseStores(options.Stores,
            sp => new AzureKeyVaultSecretStore(clients, sp.GetService<ILogger<AzureKeyVaultSecretStore>>()),
            sp => new AzureKeyVaultKeyStore(clients, sp.GetService<ILogger<AzureKeyVaultKeyStore>>()),
            sp => new AzureKeyVaultCertificateStore(clients, sp.GetService<ILogger<AzureKeyVaultCertificateStore>>()));
    }

    /// <summary>
    /// Adiciona os segredos do Azure Key Vault à configuração. Veja <see cref="CofreConfigurationBuilderExtensions.AddTecCofre"/>.
    /// </summary>
    /// <remarks>
    /// <paramref name="loggerFactory"/> é usado pelo store (auditoria) e pelo provedor de configuração (falhas de carga e
    /// recarga, tempo limite e estouro de <see cref="CofreConfigurationOptions.MaxSecrets"/>). Recomendado informar.
    /// </remarks>
    /// <example>
    /// <code>
    /// builder.Configuration.AddTecCofreAzureKeyVault(
    ///     o => o.VaultUri = new Uri("https://kv-minha-app.vault.azure.net/"),
    ///     c => c.Prefix = "MinhaApi--",
    ///     LoggerFactory.Create(l => l.AddConsole()));
    /// </code>
    /// </example>
    public static IConfigurationBuilder AddTecCofreAzureKeyVault(this IConfigurationBuilder builder, Action<AzureKeyVaultOptions> configure,
        Action<CofreConfigurationOptions>? configureConfiguration = null, ILoggerFactory? loggerFactory = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder.AddTecCofre(AzureKeyVaultStores.CreateSecretStore(configure, loggerFactory), configureConfiguration,
            loggerFactory: loggerFactory);
    }
}

/// <summary>Criação direta dos stores, sem injeção de dependência (ex.: ferramentas de linha de comando, configuração).</summary>
public static class AzureKeyVaultStores
{
    /// <summary>Cria o cofre de segredos (implementa <see cref="ISecretStore"/>, <see cref="ISecretRecycleBin"/>, <see cref="ISecretBackup"/> e <see cref="IVaultHealthProbe"/>).</summary>
    public static AzureKeyVaultSecretStore CreateSecretStore(Action<AzureKeyVaultOptions> configure, ILoggerFactory? loggerFactory = null) =>
        new(CreateClients(configure), loggerFactory?.CreateLogger<AzureKeyVaultSecretStore>());

    /// <summary>Cria o cofre de chaves (implementa <see cref="IKeyStore"/>, <see cref="IKeyCryptography"/>, <see cref="IKeyRecycleBin"/>, <see cref="IKeyBackup"/> e <see cref="IVaultHealthProbe"/>).</summary>
    public static AzureKeyVaultKeyStore CreateKeyStore(Action<AzureKeyVaultOptions> configure, ILoggerFactory? loggerFactory = null) =>
        new(CreateClients(configure), loggerFactory?.CreateLogger<AzureKeyVaultKeyStore>());

    /// <summary>Cria o cofre de certificados (implementa <see cref="ICertificateStore"/>, <see cref="ICertificateRecycleBin"/>, <see cref="ICertificateBackup"/> e <see cref="IVaultHealthProbe"/>).</summary>
    public static AzureKeyVaultCertificateStore CreateCertificateStore(Action<AzureKeyVaultOptions> configure, ILoggerFactory? loggerFactory = null) =>
        new(CreateClients(configure), loggerFactory?.CreateLogger<AzureKeyVaultCertificateStore>());

    private static AzureKeyVaultClients CreateClients(Action<AzureKeyVaultOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        var options = new AzureKeyVaultOptions();
        configure(options);
        return new AzureKeyVaultClients(options);
    }
}
