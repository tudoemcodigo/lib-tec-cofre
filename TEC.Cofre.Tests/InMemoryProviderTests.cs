using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using TEC.Cofre.Abstractions;
using TEC.Cofre.Certificates;
using TEC.Cofre.Common;
using TEC.Cofre.DependencyInjection;
using TEC.Cofre.InMemory;
using TEC.Cofre.Keys;
using TEC.Cofre.Secrets;
using TEC.Cofre.Tests.Fakes;

namespace TEC.Cofre.Tests;

/// <summary>Provedor em memória (TEC.Cofre.InMemory): trava de ambiente e contrato de segredos, chaves e certificados.</summary>
public class InMemoryProviderTests
{
    private const string SecretValue = "VALOR-EM-MEMORIA-5c1e";

    // ---------- Trava de ambiente ----------

    [Test]
    public async Task Fora_de_Development_a_criacao_falha_fechada()
    {
        var production = new InMemoryVaultOptions { HostEnvironment = new HostEnvironmentStub("Production") };

        await Assert.That(() => new InMemorySecretStore(production)).Throws<InvalidOperationException>();
        await Assert.That(() => new InMemoryKeyStore(production)).Throws<InvalidOperationException>();
        await Assert.That(() => new InMemoryCertificateStore(production)).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task Development_ou_liberacao_explicita_permitem_o_uso()
    {
        await Assert.That(() => new InMemorySecretStore(new InMemoryVaultOptions { HostEnvironment = new HostEnvironmentStub("Development") }))
            .ThrowsNothing();
        await Assert.That(() => new InMemorySecretStore(new InMemoryVaultOptions
        {
            HostEnvironment = new HostEnvironmentStub("Production"),
            AllowOutsideDevelopment = true
        })).ThrowsNothing();
    }

    [Test]
    public async Task UseInMemory_usa_o_IHostEnvironment_registrado_no_container()
    {
        var production = new ServiceCollection();
        production.AddSingleton<IHostEnvironment>(new HostEnvironmentStub("Production"));
        var development = new ServiceCollection();
        development.AddSingleton<IHostEnvironment>(new HostEnvironmentStub("Development"));

        await Assert.That(() => production.AddTecCofre(c => c.UseInMemory())).Throws<InvalidOperationException>();
        await Assert.That(() => development.AddTecCofre(c => c.UseInMemory())).ThrowsNothing();
    }

    [Test]
    public async Task UseInMemory_registra_so_os_stores_escolhidos()
    {
        var services = new ServiceCollection();
        services.AddTecCofre(c => c.UseInMemory(o => { o.AllowOutsideDevelopment = true; o.Stores = CofreStores.Keys; }));
        using var provider = services.BuildServiceProvider();

        await Assert.That(provider.GetService<ISecretReader>()).IsNull();
        await Assert.That(provider.GetService<ICertificateReader>()).IsNull();
        await Assert.That(provider.GetRequiredService<IKeyCryptography>()).IsTypeOf<InMemoryKeyStore>();
        await Assert.That((await provider.GetRequiredService<IVaultHealthProbe>().CheckAccessAsync()).IsSuccess).IsTrue();
    }

    // ---------- Segredos ----------

    [Test]
    public async Task Segredos_iniciais_sao_carregados()
    {
        var options = Memory.Options();
        options.InitialSecrets["db-senha"] = "senha-local";

        var store = new InMemorySecretStore(options);

        await Assert.That((await store.GetSecretAsync("DB-SENHA")).Value.Value).IsEqualTo("senha-local");
    }

    [Test]
    public async Task Segredo_inicial_com_nome_invalido_e_recusado()
    {
        var options = Memory.Options();
        options.InitialSecrets["nome com espaço"] = "x";

        await Assert.That(() => new InMemorySecretStore(options)).Throws<ArgumentException>();
    }

    [Test]
    public async Task Segredo_ciclo_completo_com_lixeira_e_backup()
    {
        var store = Memory.Secrets();
        var v1 = await store.SetSecretAsync("api", "v1");
        await store.SetSecretAsync("api", "v2");

        await Assert.That((await store.GetSecretAsync("api")).Value.Value).IsEqualTo("v2");
        await Assert.That((await store.GetSecretAsync("api", v1.Value.Version)).Value.Value).IsEqualTo("v1");
        await Assert.That((await store.ExistsAsync("api")).Value).IsTrue();

        var backup = await store.BackupSecretAsync("api");
        await Assert.That(Encoding.UTF8.GetString(backup.Value)).DoesNotContain("v2");   // backup opaco

        var deleted = await store.DeleteSecretAsync("api");
        await Assert.That(deleted.Value.ScheduledPurgeDate).IsNotNull();
        await Assert.That((await store.GetSecretAsync("api")).Error!.Code).IsEqualTo(CofreErrors.NotFoundCode);
        await Assert.That((await store.ExistsAsync("api")).Value).IsFalse();
        await Assert.That((await store.SetSecretAsync("api", "x")).Error!.Code).IsEqualTo(CofreErrors.ConflictCode);
        await Assert.That((await store.ListDeletedSecretsAsync()).Value.Select(d => d.Name)).Contains("api");

        await store.RecoverDeletedSecretAsync("api");
        await Assert.That((await store.GetSecretAsync("api")).Value.Value).IsEqualTo("v2");

        await store.DeleteSecretAsync("api");
        await Assert.That((await store.PurgeDeletedSecretAsync("api")).IsSuccess).IsTrue();
        var restored = await store.RestoreSecretBackupAsync(backup.Value);
        await Assert.That(restored.Value.Name).IsEqualTo("api");
        await Assert.That((await store.ListSecretVersionsAsync("api")).Value.Count).IsEqualTo(2);
        await Assert.That((await store.RestoreSecretBackupAsync(backup.Value)).Error!.Code).IsEqualTo(CofreErrors.ConflictCode);
        await Assert.That((await store.RestoreSecretBackupAsync(new byte[32])).Error!.Code).IsEqualTo(CofreErrors.RejectedCode);
    }

    [Test]
    public async Task Segredo_valida_entrada_e_nao_registra_o_valor_em_log()
    {
        var logs = new CapturingLoggerProvider();
        using var factory = LoggerFactory.Create(b => b.AddProvider(logs).SetMinimumLevel(LogLevel.Trace));
        var store = new InMemorySecretStore(Memory.Options(), factory.CreateLogger<InMemorySecretStore>());

        var invalid = await store.GetSecretAsync("../outro");
        var expired = await store.SetSecretAsync("x", "v", new SecretWriteOptions { ExpiresOn = DateTimeOffset.UtcNow.AddMinutes(-1) });
        await store.SetSecretAsync("db", SecretValue);
        await store.GetSecretAsync("db");

        await Assert.That(invalid.Error!.Code).IsEqualTo(CofreErrors.InvalidInputCode);
        await Assert.That(expired.Error!.Field).IsEqualTo("expiresOn");
        await Assert.That(logs.AllText).DoesNotContain(SecretValue);
        await Assert.That(logs.Entries.Any(e => e.Level == LogLevel.Information && e.Text.Contains("secret.set") && e.Text.Contains("InMemory"))).IsTrue();
    }

    // ---------- Chaves ----------

    [Test]
    public async Task Chave_RSA_cifra_protege_e_assina_e_a_versao_antiga_continua_valida_apos_rotacao()
    {
        var keys = Memory.Keys();
        var created = await keys.CreateKeyAsync("rsa", new CreateKeyOptions { KeySize = 2048 });
        string v1 = created.Value.Version!;
        byte[] plaintext = "dado sensível"u8.ToArray();

        var encrypted = await keys.EncryptAsync("rsa", plaintext);
        var wrapped = await keys.WrapKeyAsync("rsa", RandomNumberGenerator.GetBytes(32));
        var signed = await keys.SignDataAsync("rsa", plaintext, VaultSignatureAlgorithm.PS256);
        var rotated = await keys.RotateKeyAsync("rsa");

        await Assert.That(created.Value.KeySize).IsEqualTo(2048);
        await Assert.That(created.Value.HardwareProtected).IsFalse();
        await Assert.That(encrypted.Value.KeyVersion).IsEqualTo(v1);
        await Assert.That((await keys.DecryptAsync("rsa", v1, encrypted.Value.Ciphertext)).Value).IsEquivalentTo(plaintext);
        await Assert.That((await keys.UnwrapKeyAsync("rsa", v1, wrapped.Value.Ciphertext)).Value.Length).IsEqualTo(32);
        await Assert.That((await keys.VerifyDataAsync("rsa", v1, plaintext, signed.Value.Signature, VaultSignatureAlgorithm.PS256)).Value).IsTrue();
        await Assert.That((await keys.VerifyDataAsync("rsa", v1, "outro"u8.ToArray(), signed.Value.Signature, VaultSignatureAlgorithm.PS256)).Value).IsFalse();
        await Assert.That(rotated.Value.Version).IsNotEqualTo(v1);
        await Assert.That((await keys.EncryptAsync("rsa", plaintext)).Value.KeyVersion).IsEqualTo(rotated.Value.Version!);
        await Assert.That((await keys.ListKeyVersionsAsync("rsa")).Value.Count).IsEqualTo(2);

        using var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(created.Value.PublicKeySpki, out _);
        await Assert.That(rsa.VerifyData(plaintext, signed.Value.Signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss)).IsTrue();
    }

    [Test]
    [Arguments(VaultKeyCurve.P256, VaultSignatureAlgorithm.ES256)]
    [Arguments(VaultKeyCurve.P384, VaultSignatureAlgorithm.ES384)]
    [Arguments(VaultKeyCurve.P521, VaultSignatureAlgorithm.ES512)]
    public async Task Chave_EC_assina_no_formato_IEEE_P1363_e_nao_cifra(VaultKeyCurve curve, VaultSignatureAlgorithm algorithm)
    {
        var keys = Memory.Keys();
        var created = await keys.CreateKeyAsync("ec", new CreateKeyOptions { KeyType = VaultKeyType.Ec, Curve = curve });
        byte[] data = "mensagem"u8.ToArray();

        var signed = await keys.SignDataAsync("ec", data, algorithm);

        using var ecdsa = ECDsa.Create();
        ecdsa.ImportSubjectPublicKeyInfo(created.Value.PublicKeySpki, out _);
        await Assert.That(created.Value.Operations).IsEqualTo(VaultKeyOperations.Sign | VaultKeyOperations.Verify);
        await Assert.That(ecdsa.VerifyData(data, signed.Value.Signature, HashForCurve(curve))).IsTrue();
        await Assert.That((await keys.EncryptAsync("ec", data)).Error!.Code).IsEqualTo(CofreErrors.RejectedCode);
        await Assert.That((await keys.SignDataAsync("ec", data, VaultSignatureAlgorithm.PS256)).Error!.Code).IsEqualTo(CofreErrors.RejectedCode);
    }

    [Test]
    public async Task Chave_respeita_operacoes_permitidas_estado_e_HSM()
    {
        var keys = Memory.Keys();
        await keys.CreateKeyAsync("assinatura", new CreateKeyOptions { KeySize = 2048, Operations = VaultKeyOperations.Sign | VaultKeyOperations.Verify });

        var encrypt = await keys.EncryptAsync("assinatura", "x"u8.ToArray());
        await keys.UpdateKeyPropertiesAsync("assinatura", new KeyPropertiesUpdate { Enabled = false });
        var disabled = await keys.SignDataAsync("assinatura", "x"u8.ToArray(), VaultSignatureAlgorithm.RS256);
        var hsm = await keys.CreateKeyAsync("hsm", new CreateKeyOptions { HardwareProtected = true });
        var weak = await keys.CreateKeyAsync("fraca", new CreateKeyOptions { KeySize = 1024 });

        await Assert.That(encrypt.Error!.Code).IsEqualTo(CofreErrors.RejectedCode);
        await Assert.That(disabled.Error!.Code).IsEqualTo(CofreErrors.DisabledCode);
        await Assert.That(hsm.Error!.Code).IsEqualTo(CofreErrors.NotSupportedCode);
        await Assert.That(weak.Error!.Field).IsEqualTo("keySize");
    }

    [Test]
    public async Task Chave_com_lixeira_e_backup()
    {
        var keys = Memory.Keys();
        await keys.CreateKeyAsync("k", new CreateKeyOptions { KeySize = 2048 });
        var backup = await keys.BackupKeyAsync("k");

        await keys.DeleteKeyAsync("k");
        await Assert.That((await keys.GetKeyAsync("k")).Error!.Code).IsEqualTo(CofreErrors.NotFoundCode);
        await Assert.That((await keys.RecoverDeletedKeyAsync("k")).Value.Name).IsEqualTo("k");
        await keys.DeleteKeyAsync("k");
        await keys.PurgeDeletedKeyAsync("k");
        await Assert.That((await keys.RestoreKeyBackupAsync(backup.Value)).Value.Name).IsEqualTo("k");
    }

    [Test]
    public async Task Chave_publica_retornada_e_uma_copia()
    {
        var keys = Memory.Keys();
        var created = await keys.CreateKeyAsync("k", new CreateKeyOptions { KeySize = 2048 });
        created.Value.PublicKeySpki![0] ^= 0xFF;

        var again = await keys.GetKeyAsync("k");

        await Assert.That(again.Value.PublicKeySpki![0]).IsNotEqualTo(created.Value.PublicKeySpki[0]);
    }

    // ---------- Certificados ----------

    [Test]
    public async Task Certificado_autoassinado_exportavel_e_baixado_com_a_chave()
    {
        var certificates = Memory.Certificates();

        var created = await certificates.CreateCertificateAsync("api", new CreateCertificateOptions
        {
            Subject = "CN=api.local",
            DnsNames = ["api.local"],
            KeySize = 2048,
            Exportable = true
        });
        var downloaded = await certificates.DownloadCertificateAsync("api");

        using var withKey = downloaded.Value;
        using var publicOnly = created.Value.ToX509Certificate();
        await Assert.That(withKey.HasPrivateKey).IsTrue();
        await Assert.That(publicOnly.HasPrivateKey).IsFalse();
        await Assert.That(publicOnly.Subject).IsEqualTo("CN=api.local");
        await Assert.That(created.Value.Properties.Thumbprint).IsEqualTo(withKey.Thumbprint);
        await Assert.That(created.Value.Properties.ExpiresOn).IsNotNull();
    }

    [Test]
    public async Task Certificado_nao_exportavel_nao_libera_a_chave_e_emissor_externo_nao_e_suportado()
    {
        var certificates = Memory.Certificates();
        await certificates.CreateCertificateAsync("ec", new CreateCertificateOptions { Subject = "CN=ec", KeyType = VaultKeyType.Ec });

        var download = await certificates.DownloadCertificateAsync("ec");
        var issuer = await certificates.CreateCertificateAsync("ca", new CreateCertificateOptions { Subject = "CN=ca", Issuer = "DigiCert" });

        await Assert.That(download.Error!.Code).IsEqualTo(CofreErrors.NotExportableCode);
        await Assert.That(issuer.Error!.Code).IsEqualTo(CofreErrors.NotSupportedCode);
    }

    [Test]
    public async Task Certificado_importado_de_PFX_e_PEM()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=importado", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var local = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(30));
        byte[] pfx = local.Export(X509ContentType.Pkcs12, "senha");
        byte[] pem = Encoding.ASCII.GetBytes(local.ExportCertificatePem() + "\n" + rsa.ExportPkcs8PrivateKeyPem());
        var certificates = Memory.Certificates();

        var fromPfx = await certificates.ImportCertificateAsync("pfx", pfx, new ImportCertificateOptions { Password = "senha", Exportable = true });
        var fromPem = await certificates.ImportCertificateAsync("pem", pem, new ImportCertificateOptions { Exportable = true });
        var wrongPassword = await certificates.ImportCertificateAsync("errado", pfx, new ImportCertificateOptions { Password = "errada" });

        await Assert.That(fromPfx.Value.Properties.Thumbprint).IsEqualTo(local.Thumbprint);
        await Assert.That(fromPem.Value.Properties.Thumbprint).IsEqualTo(local.Thumbprint);
        await Assert.That(wrongPassword.Error!.Field).IsEqualTo("certificate");
        using var downloaded = (await certificates.DownloadCertificateAsync("pem")).Value;
        await Assert.That(downloaded.HasPrivateKey).IsTrue();
    }

    [Test]
    public async Task Certificado_com_lixeira_e_backup()
    {
        var certificates = Memory.Certificates();
        await certificates.CreateCertificateAsync("c", new CreateCertificateOptions { Subject = "CN=c", KeySize = 2048 });
        var backup = await certificates.BackupCertificateAsync("c");

        await certificates.DeleteCertificateAsync("c");
        await Assert.That((await certificates.ListDeletedCertificatesAsync()).Value.Single().Name).IsEqualTo("c");
        await Assert.That((await certificates.RecoverDeletedCertificateAsync("c")).Value.Name).IsEqualTo("c");
        await Assert.That((await certificates.UpdateCertificatePropertiesAsync("c", new CertificatePropertiesUpdate { Enabled = false })).Value.Enabled).IsFalse();
        await certificates.DeleteCertificateAsync("c");
        await certificates.PurgeDeletedCertificateAsync("c");
        await Assert.That((await certificates.RestoreCertificateBackupAsync(backup.Value)).Value.Name).IsEqualTo("c");
    }

    private static HashAlgorithmName HashForCurve(VaultKeyCurve curve) => curve switch
    {
        VaultKeyCurve.P384 => HashAlgorithmName.SHA384,
        VaultKeyCurve.P521 => HashAlgorithmName.SHA512,
        _ => HashAlgorithmName.SHA256
    };

    private sealed class HostEnvironmentStub(string name) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = name;
        public string ApplicationName { get; set; } = "testes";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = null!;
    }
}
