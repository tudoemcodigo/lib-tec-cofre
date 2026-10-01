using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using TEC.Cofre.Abstractions;
using TEC.Cofre.Certificates;
using TEC.Cofre.Common;
using TEC.Cofre.InMemory.Internal;
using TEC.Cofre.Keys;
using TEC.Cofre.Providers;
using TEC.Core.Common.Results;

namespace TEC.Cofre.InMemory;

/// <summary>
/// Certificados em memória (desenvolvimento e testes): criação de certificados autoassinados (RSA/EC, com SAN), importação de
/// PFX/PEM com as mesmas verificações locais dos provedores reais, download só quando exportável, versões, lixeira e backup.
/// </summary>
/// <remarks>
/// Diferenças de um cofre real: só emite autoassinados (<see cref="CreateCertificateOptions.Issuer"/> informado →
/// <see cref="CofreErrors.NotSupportedCode"/>), sem HSM, sem renovação automática (<see cref="CreateCertificateOptions.AutoRenewDaysBeforeExpiry"/>
/// é ignorado) e sem chave/segredo associados ao certificado (use <see cref="InMemoryKeyStore"/> para chaves).
/// </remarks>
public sealed class InMemoryCertificateStore : InMemoryStoreBase, ICertificateStore, ICertificateRecycleBin, ICertificateBackup, IVaultHealthProbe
{
    /// <summary>Versão: metadados, parte pública (DER) e o PKCS#12 sem senha com a chave privada (só em memória).</summary>
    private sealed record Version(CertificateProperties Properties, byte[] Cer, byte[] Pkcs12, bool Exportable);

    private readonly VersionedItems<Version> _items = new();

    /// <summary>Cria o store.</summary>
    /// <param name="options">Opções. <c>null</c> = padrão (só permitido em Development).</param>
    /// <param name="logger">Logger (auditoria).</param>
    /// <exception cref="InvalidOperationException">Fora de Development sem <see cref="InMemoryVaultOptions.AllowOutsideDevelopment"/>.</exception>
    public InMemoryCertificateStore(InMemoryVaultOptions? options = null, ILogger<InMemoryCertificateStore>? logger = null)
        : base(options, logger)
    {
    }

    /// <inheritdoc />
    public Task<Result<VaultCertificate>> CreateCertificateAsync(string name, CreateCertificateOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        var inputError = VaultInputRules.First(Rules.Name(name), VaultCertificateRules.Create(options), Rules.Tags(options.Tags));

        return Run<VaultCertificate>("certificate.create", name, inputError, isWrite: true, () =>
        {
            if (options.Issuer is not null || options.HardwareProtected)
                return CofreErrors.NotSupported();

            var now = Time.GetUtcNow();
            using var certificate = CreateSelfSigned(options, now);
            return Store(name, certificate, options.Exportable, options.Enabled, options.Tags, now);
        }, cancellationToken);
    }

    /// <inheritdoc />
    public Task<Result<VaultCertificate>> ImportCertificateAsync(string name, byte[] certificate, ImportCertificateOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        options ??= new ImportCertificateOptions();
        var inputError = Rules.ImportCertificate(name, certificate, options, out var format, out _);

        return Run<VaultCertificate>("certificate.import", name, inputError, isWrite: true, () =>
        {
            // Já conferido por InspectImport: formato, senha, chave privada e tamanho da chave
            using var loaded = format == CertificateContentFormat.Pem
                ? VaultCertificateRules.LoadPem(certificate, options.Password)
                : VaultCertificateLoader.LoadPkcs12(certificate, options.Password, VaultCertificateLoader.SafeKeyStorageFlags | X509KeyStorageFlags.Exportable);
            return Store(name, loaded, options.Exportable, options.Enabled, options.Tags, Time.GetUtcNow());
        }, cancellationToken);
    }

    /// <inheritdoc />
    public Task<Result<VaultCertificate>> GetCertificateAsync(string name, string? version = null, CancellationToken cancellationToken = default) =>
        Run<VaultCertificate>("certificate.get", name, Rules.Item(name, version), isWrite: false, () =>
        {
            lock (_items.Sync)
                return _items.Find(name, version, v => v.Properties.Version!) is { } item ? ToModel(item) : CofreErrors.NotFound();
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<X509Certificate2>> DownloadCertificateAsync(string name, string? version = null, CancellationToken cancellationToken = default) =>
        // Auditado como escrita: é a operação que tira uma chave privada do cofre
        Run<X509Certificate2>("certificate.download", name, Rules.Item(name, version), isWrite: true, () =>
        {
            Version? item;
            lock (_items.Sync)
                item = _items.Find(name, version, v => v.Properties.Version!);

            if (item is null)
                return CofreErrors.NotFound();
            if (!item.Properties.Enabled)
                return CofreErrors.Disabled();
            if (!item.Exportable)
                return CofreErrors.NotExportable();
            return VaultCertificateLoader.LoadPkcs12(item.Pkcs12, password: null);
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<IReadOnlyList<CertificateProperties>>> ListCertificatesAsync(CancellationToken cancellationToken = default) =>
        Run<IReadOnlyList<CertificateProperties>>("certificate.list", null, null, isWrite: false, () =>
        {
            lock (_items.Sync)
                return _items.Current().Select(v => v.Properties).ToList();
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<IReadOnlyList<CertificateProperties>>> ListCertificateVersionsAsync(string name, CancellationToken cancellationToken = default) =>
        Run<IReadOnlyList<CertificateProperties>>("certificate.versions", name, Rules.Name(name), isWrite: false, () =>
        {
            lock (_items.Sync)
            {
                var versions = _items.Versions(name);
                return versions is null ? CofreErrors.NotFound() : versions.Select(v => v.Properties).ToList();
            }
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<CertificateProperties>> UpdateCertificatePropertiesAsync(string name, CertificatePropertiesUpdate update,
        string? version = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(update);
        return Run<CertificateProperties>("certificate.update", name, VaultInputRules.First(Rules.Name(name), Rules.Version(version), Rules.Tags(update.Tags)),
            isWrite: true, () =>
            {
                lock (_items.Sync)
                {
                    var current = _items.Find(name, version, v => v.Properties.Version!);
                    if (current is null)
                        return CofreErrors.NotFound();

                    var properties = current.Properties with
                    {
                        Enabled = update.Enabled ?? current.Properties.Enabled,
                        Tags = update.Tags is null ? current.Properties.Tags : CopyTags(update.Tags),
                        UpdatedOn = Time.GetUtcNow()
                    };
                    _items.Replace(name, current, current with { Properties = properties });
                    return properties;
                }
            }, cancellationToken);
    }

    /// <inheritdoc />
    public Task<Result<DeletedVaultItem>> DeleteCertificateAsync(string name, CancellationToken cancellationToken = default) =>
        Run<DeletedVaultItem>("certificate.delete", name, Rules.Name(name), isWrite: true, () =>
        {
            var now = Time.GetUtcNow();
            lock (_items.Sync)
            {
                return _items.Delete(name, now)
                    ? new DeletedVaultItem(name, now, now + RetentionPeriod)
                    : Result<DeletedVaultItem>.Failure(CofreErrors.NotFound());
            }
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<IReadOnlyList<DeletedVaultItem>>> ListDeletedCertificatesAsync(CancellationToken cancellationToken = default) =>
        Run<IReadOnlyList<DeletedVaultItem>>("certificate.list-deleted", null, null, isWrite: false, () =>
        {
            lock (_items.Sync)
                return _items.ListDeleted().Select(d => new DeletedVaultItem(d.Name, d.DeletedOn, d.DeletedOn + RetentionPeriod)).ToList();
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<VaultCertificate>> RecoverDeletedCertificateAsync(string name, CancellationToken cancellationToken = default) =>
        Run<VaultCertificate>("certificate.recover", name, Rules.Name(name), isWrite: true, () =>
        {
            lock (_items.Sync)
                return _items.Recover(name) is { } versions ? ToModel(versions[^1]) : CofreErrors.NotFound();
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result> PurgeDeletedCertificateAsync(string name, CancellationToken cancellationToken = default) =>
        RunVoid("certificate.purge", name, Rules.Name(name), isWrite: true, () =>
        {
            lock (_items.Sync)
                return _items.Purge(name) ? Result.Success() : Result.Failure(CofreErrors.NotFound());
        }, cancellationToken);

    /// <inheritdoc />
    /// <remarks>Em memória o backup é um identificador opaco, válido só nesta instância (não contém o certificado).</remarks>
    public Task<Result<byte[]>> BackupCertificateAsync(string name, CancellationToken cancellationToken = default) =>
        Run<byte[]>("certificate.backup", name, Rules.Name(name), isWrite: true, () =>
        {
            lock (_items.Sync)
                return _items.Backup(name) is { } token ? token : Result<byte[]>.Failure(CofreErrors.NotFound());
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<VaultCertificate>> RestoreCertificateBackupAsync(byte[] backup, CancellationToken cancellationToken = default) =>
        Run<VaultCertificate>("certificate.restore", null, Rules.Backup(backup), isWrite: true, () =>
        {
            lock (_items.Sync)
            {
                var versions = _items.Restore(backup, out _, out bool conflict);
                if (conflict)
                    return CofreErrors.Conflict();
                return versions is null ? CofreErrors.Rejected() : ToModel(versions[^1]);
            }
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result> CheckAccessAsync(CancellationToken cancellationToken = default) =>
        RunVoid("certificate.health", null, null, isWrite: false, Result.Success, cancellationToken);

    /// <summary>
    /// Guarda o certificado como nova versão. O PKCS#12 exportado (com a chave privada) passa a ser o dado guardado; se não
    /// for guardado (nome na lixeira ou exceção), é zerado.
    /// </summary>
    private Result<VaultCertificate> Store(string name, X509Certificate2 certificate, bool exportable, bool enabled,
        IReadOnlyDictionary<string, string>? tags, DateTimeOffset now)
    {
        byte[] pkcs12 = certificate.Export(X509ContentType.Pkcs12);
        bool stored = false;
        try
        {
            lock (_items.Sync)
            {
                if (_items.IsDeleted(name))
                    return CofreErrors.Conflict();

                var version = NewVersion(name, certificate, pkcs12, exportable, enabled, tags, now);
                _items.Add(name, version);
                stored = true;
                return ToModel(version);
            }
        }
        finally
        {
            if (!stored)
                CryptographicOperations.ZeroMemory(pkcs12);
        }
    }

    private static X509Certificate2 CreateSelfSigned(CreateCertificateOptions options, DateTimeOffset now)
    {
        var subject = new X500DistinguishedName(options.Subject);
        CertificateRequest request;
        AsymmetricAlgorithm key;
        if (options.KeyType == VaultKeyType.Rsa)
        {
            var rsa = RSA.Create(options.KeySize);
            key = rsa;
            request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, critical: true));
        }
        else
        {
            var ecdsa = ECDsa.Create(VaultKeyRules.ToECCurve(options.Curve));
            key = ecdsa;
            request = new CertificateRequest(subject, ecdsa, VaultKeyRules.CurveHash(options.Curve));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        }

        using (key)
        {
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, critical: true));
            if (options.DnsNames is { Count: > 0 } dnsNames)
            {
                var san = new SubjectAlternativeNameBuilder();
                foreach (var dns in dnsNames)
                    san.AddDnsName(dns);
                request.CertificateExtensions.Add(san.Build());
            }

            return request.CreateSelfSigned(now.AddMinutes(-5), now.AddMonths(options.ValidityInMonths));
        }
    }

    private static Version NewVersion(string name, X509Certificate2 certificate, byte[] pkcs12, bool exportable, bool enabled,
        IReadOnlyDictionary<string, string>? tags, DateTimeOffset now)
    {
        string version = NewVersion();
        var properties = new CertificateProperties
        {
            Name = name,
            Version = version,
            Id = $"memoria://certificates/{name}/{version}",
            Enabled = enabled,
            CreatedOn = now,
            UpdatedOn = now,
            NotBefore = new DateTimeOffset(certificate.NotBefore.ToUniversalTime(), TimeSpan.Zero),
            ExpiresOn = new DateTimeOffset(certificate.NotAfter.ToUniversalTime(), TimeSpan.Zero),
            Thumbprint = certificate.Thumbprint,
            Tags = CopyTags(tags)
        };
        return new Version(properties, certificate.RawData, pkcs12, exportable);
    }

    private static VaultCertificate ToModel(Version version) => new() { Properties = version.Properties, Cer = [.. version.Cer] };
}
