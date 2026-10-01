using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace TEC.Cofre.Providers;

/// <summary>
/// Trava de ambiente comum aos provedores (uso pelos provedores): recursos só de desenvolvimento (credencial de desenvolvedor,
/// provedor em memória) falham fechados fora do ambiente Development.
/// </summary>
public static class VaultEnvironment
{
    /// <summary>
    /// Ambiente de desenvolvimento? O <see cref="IHostEnvironment"/>, quando disponível, é a fonte de verdade (o ambiente pode vir
    /// de appsettings, linha de comando ou <c>WebApplicationOptions</c>, não só de variável); sem ele, as variáveis
    /// <c>ASPNETCORE_ENVIRONMENT</c>/<c>DOTNET_ENVIRONMENT</c>.
    /// </summary>
    public static bool IsDevelopment(IHostEnvironment? environment = null) =>
        environment is not null
            ? string.Equals(environment.EnvironmentName, Environments.Development, StringComparison.OrdinalIgnoreCase)
            : string.Equals(Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT"), Environments.Development, StringComparison.OrdinalIgnoreCase)
              || string.Equals(Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT"), Environments.Development, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// O <see cref="IHostEnvironment"/> registrado como instância no container (o <c>WebApplicationBuilder</c>/<c>HostApplicationBuilder</c>
    /// registra antes do <c>Program.cs</c>), ou <c>null</c>.
    /// </summary>
    public static IHostEnvironment? FindHostEnvironment(IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        return services.LastOrDefault(d => d.ServiceType == typeof(IHostEnvironment) && !d.IsKeyedService)?.ImplementationInstance as IHostEnvironment;
    }
}
