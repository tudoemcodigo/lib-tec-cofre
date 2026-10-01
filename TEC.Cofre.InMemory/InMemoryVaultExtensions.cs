using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using TEC.Cofre.DependencyInjection;
using TEC.Cofre.Providers;

namespace TEC.Cofre.InMemory;

/// <summary>Registro do provedor em memória.</summary>
public static class InMemoryVaultExtensions
{
    /// <summary>
    /// Usa o provedor em memória (segredos, chaves e certificados, conforme <see cref="InMemoryVaultOptions.Stores"/>).
    /// <b>Somente desenvolvimento local e testes</b>: fora do ambiente Development a inicialização falha, a menos que
    /// <see cref="InMemoryVaultOptions.AllowOutsideDevelopment"/> seja <c>true</c>. O conteúdo some quando o processo termina.
    /// </summary>
    /// <example>
    /// <code>
    /// builder.Services.AddTecCofre(cofre =>
    /// {
    ///     if (builder.Environment.IsDevelopment())
    ///         cofre.UseInMemory(o => o.InitialSecrets["db-senha"] = "senha-local");
    ///     else
    ///         cofre.UseAzureKeyVault(o => o.VaultUri = new Uri(builder.Configuration["Cofre:VaultUri"]!));
    /// });
    /// </code>
    /// </example>
    /// <exception cref="InvalidOperationException">Ambiente diferente de Development sem <see cref="InMemoryVaultOptions.AllowOutsideDevelopment"/>.</exception>
    public static CofreBuilder UseInMemory(this CofreBuilder builder, Action<InMemoryVaultOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(builder);

        var options = new InMemoryVaultOptions();
        configure?.Invoke(options);

        options.HostEnvironment ??= VaultEnvironment.FindHostEnvironment(builder.Services);

        InMemoryEnvironment.EnsureAllowed(options);
        CofreBuilder.EnsureValidStores(options.Stores, "InMemoryVaultOptions.Stores");

        return builder.UseStores(options.Stores,
            sp => new InMemorySecretStore(options, sp.GetService<ILogger<InMemorySecretStore>>()),
            sp => new InMemoryKeyStore(options, sp.GetService<ILogger<InMemoryKeyStore>>()),
            sp => new InMemoryCertificateStore(options, sp.GetService<ILogger<InMemoryCertificateStore>>()));
    }
}

/// <summary>Trava de ambiente: o provedor em memória só roda em Development (ou com liberação explícita).</summary>
internal static class InMemoryEnvironment
{
    internal static void EnsureAllowed(InMemoryVaultOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.AllowOutsideDevelopment || VaultEnvironment.IsDevelopment(options.HostEnvironment))
            return;

        throw new InvalidOperationException(
            "O provedor de cofre em memória (TEC.Cofre.InMemory) só é permitido no ambiente Development (IHostEnvironment ou " +
            "ASPNETCORE_ENVIRONMENT/DOTNET_ENVIRONMENT). Em produção use um cofre real; em testes automatizados, " +
            "InMemoryVaultOptions.AllowOutsideDevelopment = true.");
    }
}
