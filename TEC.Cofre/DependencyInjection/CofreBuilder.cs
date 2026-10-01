using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using TEC.Cofre.Abstractions;
using TEC.Cofre.Caching;

namespace TEC.Cofre.DependencyInjection;

/// <summary>Configuração do <c>AddTecCofre</c>: escolha do provedor e opções gerais.</summary>
/// <remarks>
/// Um cofre por aplicação: cada família (segredos, chaves, certificados) aceita um único provedor. A classe informada é
/// registrada como singleton e <b>cada interface que ela implementa</b> (leitura, gestão, criptografia, lixeira, backup)
/// aponta para a mesma instância. Uma classe que implementa mais de uma família também é uma única instância.
/// </remarks>
public sealed class CofreBuilder
{
    internal CofreBuilder(IServiceCollection services) => Services = services;

    /// <summary>Container, para os provedores registrarem as suas dependências.</summary>
    public IServiceCollection Services { get; }

    /// <summary>Implementação escolhida para uma família e como obtê-la do container.</summary>
    internal sealed record Registration(Type ImplementationType, Func<IServiceProvider, object> Resolve);

    internal Registration? Secrets { get; private set; }

    internal Registration? Keys { get; private set; }

    internal Registration? Certificates { get; private set; }

    internal TimeSpan? SecretCacheDuration { get; private set; }

    /// <summary>
    /// Define o provedor de segredos (uso pelos provedores). Registra <typeparamref name="T"/> como singleton e, conforme o que ele
    /// implementa, <see cref="ISecretReader"/>, <see cref="ISecretStore"/>, <see cref="ISecretRecycleBin"/> e <see cref="ISecretBackup"/>.
    /// </summary>
    public CofreBuilder UseSecretStore<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] T>()
        where T : class, ISecretReader
    {
        Secrets = Set(Secrets, typeof(T), "segredos");
        return AddType<T>();
    }

    /// <summary>Como <see cref="UseSecretStore{T}()"/>, criando a instância com <paramref name="factory"/> (ex.: construtor interno).</summary>
    /// <remarks><typeparamref name="T"/> deve ser a classe concreta: as interfaces registradas são as que ela implementa.</remarks>
    public CofreBuilder UseSecretStore<T>(Func<IServiceProvider, T> factory) where T : class, ISecretReader
    {
        ArgumentNullException.ThrowIfNull(factory);
        Secrets = Set(Secrets, typeof(T), "segredos");
        return AddFactory(factory);
    }

    /// <summary>
    /// Define o provedor de chaves (uso pelos provedores). <typeparamref name="T"/> precisa implementar <see cref="IKeyReader"/>
    /// e/ou <see cref="IKeyCryptography"/>; são registradas também <see cref="IKeyStore"/>, <see cref="IKeyRecycleBin"/> e
    /// <see cref="IKeyBackup"/>, se implementadas.
    /// </summary>
    /// <exception cref="ArgumentException"><typeparamref name="T"/> não implementa nenhuma interface de chaves.</exception>
    public CofreBuilder UseKeyStore<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] T>() where T : class
    {
        Keys = Set(Keys, EnsureKeyProvider(typeof(T)), "chaves");
        return AddType<T>();
    }

    /// <summary>Como <see cref="UseKeyStore{T}()"/>, criando a instância com <paramref name="factory"/>.</summary>
    public CofreBuilder UseKeyStore<T>(Func<IServiceProvider, T> factory) where T : class
    {
        ArgumentNullException.ThrowIfNull(factory);
        Keys = Set(Keys, EnsureKeyProvider(typeof(T)), "chaves");
        return AddFactory(factory);
    }

    /// <summary>
    /// Define o provedor de certificados (uso pelos provedores). Registra <see cref="ICertificateReader"/> e, se implementadas,
    /// <see cref="ICertificateStore"/>, <see cref="ICertificateRecycleBin"/> e <see cref="ICertificateBackup"/>.
    /// </summary>
    public CofreBuilder UseCertificateStore<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] T>()
        where T : class, ICertificateReader
    {
        Certificates = Set(Certificates, typeof(T), "certificados");
        return AddType<T>();
    }

    /// <summary>Como <see cref="UseCertificateStore{T}()"/>, criando a instância com <paramref name="factory"/>.</summary>
    public CofreBuilder UseCertificateStore<T>(Func<IServiceProvider, T> factory) where T : class, ICertificateReader
    {
        ArgumentNullException.ThrowIfNull(factory);
        Certificates = Set(Certificates, typeof(T), "certificados");
        return AddFactory(factory);
    }

    /// <summary>
    /// Ativa o cache em memória das leituras de segredos (desligado por padrão). Reduz latência e o risco de throttling do cofre,
    /// ao custo de manter valores em memória e de ver rotações feitas por outras instâncias só após <paramref name="duration"/>.
    /// </summary>
    /// <remarks>
    /// <para><b>Escritas devem passar pelas interfaces</b> (<see cref="ISecretStore"/>, <see cref="ISecretRecycleBin"/>,
    /// <see cref="ISecretBackup"/>): com o cache ativo elas são decorators que limpam o cache após cada escrita. A classe
    /// concreta do provedor (ex.: <c>AzureKeyVaultSecretStore</c>) continua registrada no container (contrato do
    /// <c>UseSecretStore</c>) e grava direto no cofre, <b>sem</b> limpar o cache: quem a injeta para escrever deixa as leituras
    /// com o valor antigo até <paramref name="duration"/>. Injete a classe concreta só para leitura sem cache.</para>
    /// </remarks>
    /// <param name="duration">Duração (maior que zero, máximo 1 hora). Recomendado: até 5 minutos.</param>
    public CofreBuilder EnableSecretCache(TimeSpan duration)
    {
        CachingSecretReader.ValidateDuration(duration);
        SecretCacheDuration = duration;
        return this;
    }

    /// <summary>
    /// Registra, de uma vez, os stores escolhidos em <paramref name="stores"/> (uso pelos provedores que oferecem as três
    /// famílias e uma opção <c>Stores</c>): cada fábrica só é registrada se a família estiver selecionada.
    /// </summary>
    /// <param name="stores">Stores selecionados (ao menos um; veja <see cref="EnsureValidStores"/>).</param>
    /// <param name="secrets">Fábrica do store de segredos.</param>
    /// <param name="keys">Fábrica do store de chaves.</param>
    /// <param name="certificates">Fábrica do store de certificados.</param>
    /// <exception cref="InvalidOperationException"><paramref name="stores"/> vazio ou com valor desconhecido.</exception>
    public CofreBuilder UseStores<TSecrets, TKeys, TCertificates>(CofreStores stores, Func<IServiceProvider, TSecrets> secrets,
        Func<IServiceProvider, TKeys> keys, Func<IServiceProvider, TCertificates> certificates)
        where TSecrets : class, ISecretReader
        where TKeys : class
        where TCertificates : class, ICertificateReader
    {
        ArgumentNullException.ThrowIfNull(secrets);
        ArgumentNullException.ThrowIfNull(keys);
        ArgumentNullException.ThrowIfNull(certificates);
        EnsureValidStores(stores, nameof(stores));

        if (stores.HasFlag(CofreStores.Secrets))
            UseSecretStore(secrets);
        if (stores.HasFlag(CofreStores.Keys))
            UseKeyStore(keys);
        if (stores.HasFlag(CofreStores.Certificates))
            UseCertificateStore(certificates);

        return this;
    }

    /// <summary>Confere a opção <c>Stores</c> de um provedor: ao menos um store e nenhum valor desconhecido.</summary>
    /// <param name="stores">Valor da opção.</param>
    /// <param name="optionName">Nome da opção para a mensagem (ex.: "AzureKeyVaultOptions.Stores").</param>
    /// <exception cref="InvalidOperationException">Opção inválida.</exception>
    public static void EnsureValidStores(CofreStores stores, string optionName)
    {
        if (stores == CofreStores.None || (stores & ~CofreStores.All) != 0)
            throw new InvalidOperationException($"{optionName} deve conter ao menos um store válido.");
    }

    private CofreBuilder AddType<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] T>() where T : class
    {
        Services.TryAddSingleton<T>();
        return this;
    }

    private CofreBuilder AddFactory<T>(Func<IServiceProvider, T> factory) where T : class
    {
        Services.TryAddSingleton(factory);
        return this;
    }

    private static Type EnsureKeyProvider(Type type) =>
        typeof(IKeyReader).IsAssignableFrom(type) || typeof(IKeyCryptography).IsAssignableFrom(type)
            ? type
            : throw new ArgumentException($"{type.Name} não implementa IKeyReader nem IKeyCryptography.", "T");

    private static Registration Set(Registration? current, Type type, string family)
    {
        if (current is not null && current.ImplementationType != type)
        {
            throw new InvalidOperationException(
                $"Já existe um provedor configurado para {family} ({current.ImplementationType.Name}). Configure apenas um provedor (um cofre por aplicação).");
        }

        return new Registration(type, sp => sp.GetRequiredService(type));
    }
}
