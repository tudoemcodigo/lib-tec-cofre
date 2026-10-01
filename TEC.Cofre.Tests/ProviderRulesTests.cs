using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using TEC.Cofre.Abstractions;
using TEC.Cofre.AzureKeyVault;
using TEC.Cofre.DependencyInjection;
using TEC.Cofre.InMemory;
using TEC.Cofre.Keys;
using TEC.Cofre.Providers;
using TEC.Cofre.Secrets;
using TEC.Cofre.Tests.Fakes;

namespace TEC.Cofre.Tests;

/// <summary>Regras compartilhadas pelos provedores (uma única implementação para Azure Key Vault e memória).</summary>
public class ProviderRulesTests
{
    [Test]
    public async Task Provedores_usam_as_mesmas_regras_com_limites_proprios()
    {
        var azure = AzureKeyVaultStoreBase.Rules;
        var memory = InMemoryStoreBase.Rules;

        await Assert.That(azure.MaxTags).IsEqualTo(15);
        await Assert.That(memory.MaxTags).IsEqualTo(50);
        await Assert.That(azure.MaxSecretValueBytes).IsEqualTo(25 * 1024);
        await Assert.That(memory.MaxSecretValueBytes).IsEqualTo(InMemorySecretStore.MaxSecretValueBytes);
        await Assert.That(azure.Name("nome_com_underscore")!.Field).IsEqualTo("name");   // só o provedor em memória aceita "_"
        await Assert.That(memory.Name("nome_com_underscore")).IsNull();
        await Assert.That(azure.VersionPattern).IsSameReferenceAs(memory.VersionPattern);
    }

    [Test]
    public async Task Regras_de_operacao_devolvem_o_primeiro_erro_na_ordem_dos_campos()
    {
        var rules = AzureKeyVaultStoreBase.Rules;
        var now = DateTimeOffset.UtcNow;

        await Assert.That(rules.SetSecret("ok", "v", new SecretWriteOptions(), now)).IsNull();
        await Assert.That(rules.SetSecret("a b", "", new SecretWriteOptions(), now)!.Field).IsEqualTo("name");
        await Assert.That(rules.SetSecret("ok", "", new SecretWriteOptions(), now)!.Field).IsEqualTo("value");
        await Assert.That(rules.SetSecret("ok", "v", new SecretWriteOptions { ContentType = new string('x', 256) }, now)!.Field).IsEqualTo("contentType");
        await Assert.That(rules.UpdateSecret("ok", null, new SecretPropertiesUpdate { ExpiresOn = now.AddDays(-1) }, now)).IsNull();
        await Assert.That(rules.CreateKey("ok", new CreateKeyOptions { KeySize = 1024 }, now)!.Field).IsEqualTo("keySize");
        await Assert.That(rules.UpdateKey("ok", "xyz", new KeyPropertiesUpdate(), now)!.Field).IsEqualTo("version");
        await Assert.That(rules.Encrypt("ok", null, VaultEncryptionAlgorithm.RsaOaep256, new byte[VaultKeyRules.MaxEncryptBytes + 1], "plaintext")!.Field).IsEqualTo("plaintext");
        await Assert.That(rules.Decrypt("ok", null, VaultEncryptionAlgorithm.RsaOaep256, new byte[16], "ciphertext")!.Field).IsEqualTo("version");
        await Assert.That(rules.Decrypt("ok", FakeKeyVault.Version, VaultEncryptionAlgorithm.RsaOaep256, new byte[VaultKeyRules.MaxCiphertextBytes + 1], "wrappedKey")!.Field).IsEqualTo("wrappedKey");
        await Assert.That(rules.Sign("ok", null, (VaultSignatureAlgorithm)999, new byte[1])!.Field).IsEqualTo("algorithm");
        await Assert.That(rules.Verify("ok", FakeKeyVault.Version, VaultSignatureAlgorithm.PS256, new byte[1], [])!.Field).IsEqualTo("signature");
        await Assert.That(rules.ImportCertificate("a b", [1, 2, 3], new(), out _, out _)!.Field).IsEqualTo("name");
        await Assert.That(rules.ImportCertificate("ok", [1, 2, 3], new(), out _, out _)!.Field).IsEqualTo("certificate");
    }

    [Test]
    public async Task Algoritmos_de_assinatura_mapeiam_hash_padding_e_curva()
    {
        await Assert.That(VaultKeyRules.RsaSignature(VaultSignatureAlgorithm.RS384)!.Value.Hash).IsEqualTo(HashAlgorithmName.SHA384);
        await Assert.That(VaultKeyRules.RsaSignature(VaultSignatureAlgorithm.PS512)!.Value.Padding).IsEqualTo(RSASignaturePadding.Pss);
        await Assert.That(VaultKeyRules.RsaSignature(VaultSignatureAlgorithm.ES256)).IsNull();
        await Assert.That(VaultKeyRules.EcSignature(VaultSignatureAlgorithm.ES512)!.Value.Curve).IsEqualTo(VaultKeyCurve.P521);
        await Assert.That(VaultKeyRules.EcSignature(VaultSignatureAlgorithm.ES512)!.Value.Hash).IsEqualTo(HashAlgorithmName.SHA512);
        await Assert.That(VaultKeyRules.EcSignature(VaultSignatureAlgorithm.RS256)).IsNull();
        await Assert.That(VaultKeyRules.CurveHash(VaultKeyCurve.P384)).IsEqualTo(HashAlgorithmName.SHA384);
        await Assert.That(VaultKeyRules.ToECCurve(VaultKeyCurve.P256).Oid.Value).IsEqualTo(ECCurve.NamedCurves.nistP256.Oid.Value);
    }

    [Test]
    public async Task Versao_atual_e_a_de_maior_criacao_e_o_empate_e_desfeito_por_atualizacao_e_versao()
    {
        var t = DateTimeOffset.UnixEpoch;
        var versions = new[]
        {
            new SecretProperties { Name = "x", Version = "a", CreatedOn = t, UpdatedOn = t.AddHours(5) },
            new SecretProperties { Name = "x", Version = "b", CreatedOn = t.AddSeconds(1), UpdatedOn = t.AddSeconds(1) },
            new SecretProperties { Name = "x", Version = "c", CreatedOn = t.AddSeconds(1), UpdatedOn = t.AddSeconds(2) },
            new SecretProperties { Name = "x", Version = "d", CreatedOn = t.AddSeconds(1), UpdatedOn = t.AddSeconds(2) }
        };

        var newest = VaultVersionRules.Newest(versions, p => p.CreatedOn);

        await Assert.That(newest.Select(p => p.Version!)).IsEquivalentTo(new[] { "b", "c", "d" });
        await Assert.That(VaultVersionRules.BreakTie(newest, p => p.UpdatedOn, p => p.Version).Version).IsEqualTo("d");
        await Assert.That(VaultVersionRules.Newest(Array.Empty<SecretProperties>(), p => p.CreatedOn)).IsEmpty();
    }

    [Test]
    public async Task UseStores_registra_so_as_familias_escolhidas_e_recusa_valor_invalido()
    {
        var services = new ServiceCollection();
        services.AddTecCofre(c => c.UseStores(CofreStores.Secrets | CofreStores.Certificates,
            _ => Memory.Secrets(), _ => Memory.Keys(), _ => Memory.Certificates()));
        using var provider = services.BuildServiceProvider();

        await Assert.That(provider.GetService<ISecretStore>()).IsNotNull();
        await Assert.That(provider.GetService<ICertificateStore>()).IsNotNull();
        await Assert.That(provider.GetService<IKeyStore>()).IsNull();
        await Assert.That(() => CofreBuilder.EnsureValidStores(CofreStores.None, "Opcoes.Stores")).Throws<InvalidOperationException>();
        await Assert.That(() => CofreBuilder.EnsureValidStores((CofreStores)8, "Opcoes.Stores")).Throws<InvalidOperationException>();
        await Assert.That(() => CofreBuilder.EnsureValidStores(CofreStores.Keys, "Opcoes.Stores")).ThrowsNothing();
        await Assert.That(() => new ServiceCollection().AddTecCofre(c => c.UseInMemory(o => { o.AllowOutsideDevelopment = true; o.Stores = CofreStores.None; })))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task Ambiente_de_desenvolvimento_vem_do_IHostEnvironment_registrado()
    {
        var services = new ServiceCollection();
        await Assert.That(VaultEnvironment.FindHostEnvironment(services)).IsNull();

        var environment = new EnvironmentStub("Development");
        services.AddSingleton<Microsoft.Extensions.Hosting.IHostEnvironment>(environment);

        await Assert.That(VaultEnvironment.FindHostEnvironment(services)).IsSameReferenceAs(environment);
        await Assert.That(VaultEnvironment.IsDevelopment(environment)).IsTrue();
        await Assert.That(VaultEnvironment.IsDevelopment(new EnvironmentStub("Production"))).IsFalse();
    }

    private sealed class EnvironmentStub(string name) : Microsoft.Extensions.Hosting.IHostEnvironment
    {
        public string EnvironmentName { get; set; } = name;
        public string ApplicationName { get; set; } = "testes";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider { get; set; } = null!;
    }
}
