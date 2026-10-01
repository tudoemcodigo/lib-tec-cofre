using Microsoft.Extensions.Hosting;
using TEC.Cofre.DependencyInjection;

namespace TEC.Cofre.InMemory;

/// <summary>Configuração do provedor em memória (somente desenvolvimento local e testes automatizados).</summary>
public sealed class InMemoryVaultOptions
{
    /// <summary>
    /// Permite usar o provedor fora do ambiente Development. Padrão: <c>false</c> (falha fechada: um servidor nunca passa a
    /// guardar segredos em memória por engano de configuração). Use <c>true</c> em testes automatizados, cujo processo
    /// normalmente não tem ambiente definido.
    /// </summary>
    public bool AllowOutsideDevelopment { get; set; }

    /// <summary>
    /// Ambiente da aplicação, usado na trava de Development. <c>null</c> (padrão): <c>UseInMemory</c> usa o
    /// <see cref="IHostEnvironment"/> registrado no container e, sem ele, as variáveis <c>ASPNETCORE_ENVIRONMENT</c>/<c>DOTNET_ENVIRONMENT</c>.
    /// </summary>
    public IHostEnvironment? HostEnvironment { get; set; }

    /// <summary>Relógio (datas de criação, validade, exclusão). Padrão: <see cref="System.TimeProvider.System"/>.</summary>
    public TimeProvider? TimeProvider { get; set; }

    /// <summary>Stores registrados por <c>UseInMemory</c>. Padrão: <see cref="CofreStores.All"/>.</summary>
    public CofreStores Stores { get; set; } = CofreStores.All;

    /// <summary>
    /// Segredos iniciais (nome → valor), gravados na criação do store de segredos. Útil para subir a aplicação localmente
    /// sem cofre real. Não coloque segredos reais aqui: use valores de desenvolvimento.
    /// </summary>
    public IDictionary<string, string> InitialSecrets { get; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
}
