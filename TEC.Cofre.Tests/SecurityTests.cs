using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Azure;
using Azure.Core.Pipeline;
using Azure.Identity;
using Microsoft.Extensions.Logging;
using TEC.Cofre.AzureKeyVault;
using TEC.Cofre.AzureKeyVault.Internal;
using TEC.Cofre.Certificates;
using TEC.Cofre.Common;
using TEC.Cofre.Configuration;
using TEC.Cofre.InMemory;
using TEC.Cofre.Keys;
using TEC.Cofre.Providers;
using TEC.Cofre.Secrets;
using TEC.Cofre.Tests.Fakes;
using TEC.Core.Common.Results;
using SecretClient = Azure.Security.KeyVault.Secrets.SecretClient;
using SecretClientOptions = Azure.Security.KeyVault.Secrets.SecretClientOptions;

namespace TEC.Cofre.Tests;

/// <summary>Regressões de segurança (Zero Trust): nenhuma delas acessa a rede.</summary>
public class SecurityTests
{
    private const string SecretValue = "VALOR-ULTRA-SECRETO-8f3a91";

    // ---------- Endereço do cofre: o token de acesso só pode ir para o Key Vault ----------

    [Test]
    [Arguments("http://kv-teste.vault.azure.net/")]                      // sem TLS
    [Arguments("https://kv-teste.vault.azure.net.evil.com/")]            // sufixo falso
    [Arguments("https://evil.com/")]                                     // outro domínio
    [Arguments("https://a.kv-teste.vault.azure.net/")]                   // subdomínio extra
    [Arguments("https://kv-teste.vault.azure.net:8443/")]                // porta
    [Arguments("https://user:pwd@kv-teste.vault.azure.net/")]            // credencial na URL
    [Arguments("https://kv-teste.vault.azure.net/secrets/")]             // caminho
    [Arguments("https://kv-teste.vault.azure.net/?x=1")]                 // query
    [Arguments("https://kv.vault.azure.net/")]                           // nome curto demais (mín. 3)
    public async Task VaultUri_fora_do_padrao_do_Key_Vault_e_rejeitado(string uri)
    {
        var options = new AzureKeyVaultOptions { VaultUri = new Uri(uri), Credential = new FakeCredential() };

        await Assert.That(() => AzureKeyVaultClients.Validate(options)).Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments("https://kv-tec-base.vault.azure.net/")]
    [Arguments("https://KV-TEC-BASE.vault.azure.net")]
    [Arguments("https://kv-teste.vault.azure.cn/")]
    [Arguments("https://kv-teste.vault.usgovcloudapi.net/")]
    public async Task VaultUri_valido_e_aceito(string uri)
    {
        var options = new AzureKeyVaultOptions { VaultUri = new Uri(uri), Credential = new FakeCredential() };

        await Assert.That(() => AzureKeyVaultClients.Validate(options)).ThrowsNothing();
    }

    [Test]
    public async Task VaultUri_ausente_falha_na_inicializacao() =>
        await Assert.That(() => AzureKeyVaultClients.Validate(new AzureKeyVaultOptions())).Throws<InvalidOperationException>();

    [Test]
    [Arguments("nao-e-guid", null)]
    [Arguments(null, "nao-e-guid")]
    public async Task TenantId_e_ClientId_devem_ser_GUID(string? tenant, string? clientId)
    {
        var options = new AzureKeyVaultOptions
        {
            VaultUri = new Uri(FakeKeyVault.VaultUri),
            TenantId = tenant,
            ManagedIdentityClientId = clientId
        };

        await Assert.That(() => AzureKeyVaultClients.Validate(options)).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task Credencial_de_desenvolvedor_fora_de_Development_falha_fechada()
    {
        Skip.When(VaultEnvironment.IsDevelopment(), "Processo de teste rodando com ambiente Development.");
        var options = new AzureKeyVaultOptions { VaultUri = new Uri(FakeKeyVault.VaultUri), Authentication = AzureKeyVaultAuthentication.Developer };

        await Assert.That(() => AzureKeyVaultClients.Validate(options)).Throws<InvalidOperationException>();

        options.AllowDeveloperCredentialsOutsideDevelopment = true;
        await Assert.That(() => AzureKeyVaultClients.Validate(options)).ThrowsNothing();
    }

    [Test]
    public async Task Token_nao_e_enviado_quando_o_desafio_aponta_para_outro_dominio()
    {
        // Um servidor que responde ao desafio pedindo token para outro recurso não recebe token nenhum.
        // Host exclusivo: o SDK guarda o desafio em cache estático por host, e outro teste com o mesmo host faria o token
        // sair direto, sem passar pelo desafio (dependência de ordem de execução).
        var credential = new FakeCredential();
        var vault = new FakeKeyVault((_, _) => (HttpStatusCode.OK, FakeKeyVault.SecretJson("x", "y")), challengeResource: "https://evil.com");
        string host = $"https://kv-desafio-{Guid.NewGuid():N}"[..^24] + ".vault.azure.net/";
        var store = new AzureKeyVaultSecretStore(vault.CreateClients(credential, host));

        var result = await store.GetSecretAsync("x");

        await Assert.That(result.IsFailure).IsTrue();
        await Assert.That(credential.Calls).IsEqualTo(0);
        await Assert.That(vault.Requests.All(r => !r.Authorized)).IsTrue();
    }

    [Test]
    public async Task Token_e_pedido_somente_para_o_escopo_do_Key_Vault()
    {
        var credential = new FakeCredential();
        var vault = new FakeKeyVault((_, _) => (HttpStatusCode.OK, FakeKeyVault.SecretJson("x", "y")));
        var store = new AzureKeyVaultSecretStore(vault.CreateClients(credential));

        await store.GetSecretAsync("x");

        await Assert.That(credential.Scopes).IsEquivalentTo(new[] { "https://vault.azure.net/.default" });
        await Assert.That(vault.Requests.All(r => r.Uri.Host == "kv-teste.vault.azure.net")).IsTrue();
    }

    // ---------- Validação de entrada antes de qualquer chamada ----------

    [Test]
    [Arguments("")]
    [Arguments("../outro")]
    [Arguments("a/b")]
    [Arguments("a?b")]
    [Arguments("a b")]
    [Arguments("nome_com_underscore")]
    [Arguments("ção")]
    [Arguments("nome\n")]           // quebra de linha final: "$" aceitaria, "\z" não
    [Arguments("nome\r\n")]
    public async Task Nome_invalido_e_recusado_sem_chamar_o_cofre(string name)
    {
        var credential = new FakeCredential();
        var vault = new FakeKeyVault((_, _) => (HttpStatusCode.OK, "{}"));
        var store = new AzureKeyVaultSecretStore(vault.CreateClients(credential));

        var result = await store.GetSecretAsync(name);

        await Assert.That(result.Error!.Code).IsEqualTo(CofreErrors.InvalidInputCode);
        await Assert.That(vault.Requests).IsEmpty();
        await Assert.That(credential.Calls).IsEqualTo(0);
    }

    [Test]
    public async Task Nome_com_mais_de_127_caracteres_e_recusado()
    {
        var store = new AzureKeyVaultSecretStore(new FakeKeyVault((_, _) => (HttpStatusCode.OK, "{}")).CreateClients());

        var result = await store.GetSecretAsync(new string('a', 128));

        await Assert.That(result.Error!.Code).IsEqualTo(CofreErrors.InvalidInputCode);
    }

    [Test]
    public async Task Versao_invalida_e_recusada()
    {
        var store = new AzureKeyVaultSecretStore(new FakeKeyVault((_, _) => (HttpStatusCode.OK, "{}")).CreateClients());

        var result = await store.GetSecretAsync("nome", "../../keys/outra");

        await Assert.That(result.Error!.Field).IsEqualTo("version");
    }

    [Test]
    [Arguments("0123456789abcdef0123456789abcdef\n")]
    [Arguments("0123456789abcdef0123456789abcde\n")]
    public async Task Versao_com_quebra_de_linha_final_e_recusada_sem_chamar_o_cofre(string version)
    {
        var vault = new FakeKeyVault((_, _) => (HttpStatusCode.OK, "{}"));
        var secrets = new AzureKeyVaultSecretStore(vault.CreateClients());
        var keys = new AzureKeyVaultKeyStore(vault.CreateClients());

        var optional = await secrets.GetSecretAsync("nome", version);
        var required = await keys.DecryptAsync("nome", version, new byte[16]);

        await Assert.That(optional.Error!.Field).IsEqualTo("version");
        await Assert.That(required.Error!.Field).IsEqualTo("version");
        await Assert.That(vault.Requests).IsEmpty();
    }

    [Test]
    public async Task Quebra_de_linha_final_e_recusada_em_todos_os_padroes()
    {
        var memory = Memory.Secrets();

        var name = await memory.GetSecretAsync("nome\n");
        var version = await memory.GetSecretAsync("nome", FakeKeyVault.Version + "\n");
        var dns = VaultCertificateRules.Create(new CreateCertificateOptions { Subject = "CN=api", DnsNames = ["api.exemplo.com\n"] });
        var issuer = AzureKeyVaultCertificateStore.ValidateCreate(new CreateCertificateOptions { Subject = "CN=api", Issuer = "MinhaCA\n" });

        await Assert.That(name.Error!.Field).IsEqualTo("name");
        await Assert.That(version.Error!.Field).IsEqualTo("version");
        await Assert.That(dns!.Field).IsEqualTo("dnsNames");
        await Assert.That(issuer!.Field).IsEqualTo("issuer");
        await Assert.That(VaultInputRules.HexVersionPattern().IsMatch(FakeKeyVault.Version)).IsTrue();
        await Assert.That(VaultInputRules.HexVersionPattern().IsMatch(FakeKeyVault.Version + "\n")).IsFalse();
    }

    [Test]
    public async Task Valor_acima_de_25KB_e_recusado_e_a_mensagem_nao_repete_o_valor()
    {
        var vault = new FakeKeyVault((_, _) => (HttpStatusCode.OK, "{}"));
        var store = new AzureKeyVaultSecretStore(vault.CreateClients());
        string value = SecretValue + new string('x', 26 * 1024);

        var result = await store.SetSecretAsync("nome", value);

        await Assert.That(result.Error!.Field).IsEqualTo("value");
        await Assert.That(result.Error.Message).DoesNotContain(SecretValue);
        await Assert.That(vault.Requests).IsEmpty();
    }

    [Test]
    public async Task Expiracao_no_passado_e_recusada()
    {
        var store = new AzureKeyVaultSecretStore(new FakeKeyVault((_, _) => (HttpStatusCode.OK, "{}")).CreateClients());

        var result = await store.SetSecretAsync("nome", "v", new SecretWriteOptions { ExpiresOn = DateTimeOffset.UtcNow.AddMinutes(-1) });

        await Assert.That(result.Error!.Field).IsEqualTo("expiresOn");
    }

    [Test]
    public async Task Tags_acima_do_limite_ou_com_caracteres_de_controle_sao_recusadas()
    {
        var store = new AzureKeyVaultSecretStore(new FakeKeyVault((_, _) => (HttpStatusCode.OK, "{}")).CreateClients());
        var many = Enumerable.Range(0, 16).ToDictionary(i => $"t{i}", i => "v");
        var control = new Dictionary<string, string> { ["ok"] = "linha\nnova" };

        var r1 = await store.SetSecretAsync("nome", "v", new SecretWriteOptions { Tags = many });
        var r2 = await store.SetSecretAsync("nome", "v", new SecretWriteOptions { Tags = control });

        await Assert.That(r1.Error!.Field).IsEqualTo("tags");
        await Assert.That(r2.Error!.Field).IsEqualTo("tags");
    }

    [Test]
    public async Task Chave_RSA_menor_que_2048_e_recusada() =>
        await Assert.That(VaultKeyRules.Shape(VaultKeyType.Rsa, 1024, VaultKeyCurve.P256, null)!.Field).IsEqualTo("keySize");

    [Test]
    public async Task Chave_EC_nao_aceita_operacoes_de_criptografia() =>
        await Assert.That(VaultKeyRules.Shape(VaultKeyType.Ec, 0, VaultKeyCurve.P256, VaultKeyOperations.Encrypt)!.Field)
            .IsEqualTo("operations");

    [Test]
    public async Task Algoritmos_fracos_nao_existem_na_API()
    {
        // RSA1_5 (padding oracle) e RSA-OAEP com SHA-1 não são representáveis
        await Assert.That(Enum.GetNames<VaultEncryptionAlgorithm>()).IsEquivalentTo(new[] { nameof(VaultEncryptionAlgorithm.RsaOaep256) });
    }

    [Test]
    [Arguments("")]
    [Arguments("CN=ok\n")]
    public async Task Subject_de_certificado_invalido_e_recusado(string subject) =>
        await Assert.That(AzureKeyVaultCertificateStore.ValidateCreate(new CreateCertificateOptions { Subject = subject })!.Field).IsEqualTo("subject");

    [Test]
    public async Task Nome_DNS_malicioso_e_recusado()
    {
        var options = new CreateCertificateOptions { Subject = "CN=api", DnsNames = ["api.exemplo.com", "evil.com/../x"] };

        await Assert.That(AzureKeyVaultCertificateStore.ValidateCreate(options)!.Field).IsEqualTo("dnsNames");
    }

    [Test]
    public async Task Importacao_exige_chave_privada_e_senha_correta()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=teste", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1));
        byte[] pfx = cert.Export(X509ContentType.Pkcs12, "senha-correta");
        byte[] publicOnly = cert.Export(X509ContentType.Cert);

        var wrongPassword = VaultCertificateRules.InspectImport(pfx, "errada", CertificateContentFormat.Pkcs12, out _);
        var noKey = VaultCertificateRules.InspectImport(publicOnly, null, CertificateContentFormat.Pkcs12, out _);
        var ok = VaultCertificateRules.InspectImport(pfx, "senha-correta", CertificateContentFormat.Pkcs12, out var subject);

        await Assert.That(wrongPassword!.Field).IsEqualTo("certificate");
        await Assert.That(noKey!.Field).IsEqualTo("certificate");
        await Assert.That(ok).IsNull();
        await Assert.That(subject).IsEqualTo("CN=teste");
    }

    [Test]
    public async Task Importacao_recusa_RSA_1024()
    {
        using var rsa = RSA.Create(1024);
        var request = new CertificateRequest("CN=fraco", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1));

        var error = VaultCertificateRules.InspectImport(cert.Export(X509ContentType.Pkcs12, "s"), "s", CertificateContentFormat.Pkcs12, out _);

        await Assert.That(error!.Message).Contains("2048");
    }

    // ---------- O valor nunca vaza ----------

    [Test]
    public async Task VaultSecret_ToString_mascara_o_valor()
    {
        var secret = new VaultSecret(new SecretProperties { Name = "db" }, SecretValue);

        await Assert.That(secret.ToString()).DoesNotContain(SecretValue);
        await Assert.That($"{secret}").Contains("***");
    }

    [Test]
    public async Task ImportCertificateOptions_ToString_mascara_a_senha()
    {
        var options = new ImportCertificateOptions { Password = SecretValue, Exportable = true };
        var copy = options with { Enabled = false };

        await Assert.That(options.ToString()).DoesNotContain(SecretValue);
        await Assert.That($"{copy}").DoesNotContain(SecretValue);
        await Assert.That(options.ToString()).Contains("Password = ***");
        await Assert.That(new ImportCertificateOptions().ToString()).Contains("Password = null");
    }

    [Test]
    public async Task Nome_recusado_na_validacao_nao_vai_cru_para_o_log()
    {
        var logs = new CapturingLoggerProvider();
        using var factory = LoggerFactory.Create(b => b.AddProvider(logs).SetMinimumLevel(LogLevel.Trace));
        var store = new AzureKeyVaultSecretStore(new FakeKeyVault((_, _) => (HttpStatusCode.OK, "{}")).CreateClients(),
            factory.CreateLogger<AzureKeyVaultSecretStore>());
        string name = "nome invalido " + SecretValue;

        var result = await store.GetSecretAsync(name);

        await Assert.That(result.Error!.Code).IsEqualTo(CofreErrors.InvalidInputCode);
        await Assert.That(logs.AllText).DoesNotContain(SecretValue);
        await Assert.That(logs.AllText).Contains($"{name.Length} caracteres");
        await Assert.That(logs.AllText).Contains("hmac:");
        await Assert.That(logs.AllText).DoesNotContain("sha256:");
    }

    [Test]
    public async Task Leitura_de_segredo_gerenciado_e_auditada_em_Information_sem_o_valor()
    {
        var logs = new CapturingLoggerProvider();
        using var factory = LoggerFactory.Create(b => b.AddProvider(logs).SetMinimumLevel(LogLevel.Trace));
        string json = FakeKeyVault.SecretJson("cert-api", SecretValue).Replace("\"tags\"", "\"managed\":true,\"tags\"", StringComparison.Ordinal);
        var store = new AzureKeyVaultSecretStore(new FakeKeyVault((_, _) => (HttpStatusCode.OK, json)).CreateClients(),
            factory.CreateLogger<AzureKeyVaultSecretStore>());

        var result = await store.GetSecretAsync("cert-api");

        await Assert.That(result.Value.Properties.ManagedBy).IsEqualTo("certificate");   // permitido...
        await Assert.That(logs.Entries.Any(e => e.Level == LogLevel.Information && e.Text.Contains("cert-api")
            && e.Text.Contains(AzureKeyVaultSecretStore.ManagedSecretAuditReason))).IsTrue();   // ...mas auditado
        await Assert.That(logs.AllText).DoesNotContain(SecretValue);
    }

    [Test]
    public async Task Leitura_de_segredo_comum_nao_gera_auditoria_em_Information()
    {
        var logs = new CapturingLoggerProvider();
        using var factory = LoggerFactory.Create(b => b.AddProvider(logs).SetMinimumLevel(LogLevel.Trace));
        var store = new AzureKeyVaultSecretStore(new FakeKeyVault((_, _) => (HttpStatusCode.OK, FakeKeyVault.SecretJson("db", SecretValue))).CreateClients(),
            factory.CreateLogger<AzureKeyVaultSecretStore>());

        await store.GetSecretAsync("db");

        await Assert.That(logs.Entries.Any(e => e.Level >= LogLevel.Information)).IsFalse();
    }

    [Test]
    public async Task Forbidden_de_firewall_vira_acesso_negado_com_log_Error()
    {
        var logs = new CapturingLoggerProvider();
        using var factory = LoggerFactory.Create(b => b.AddProvider(logs).SetMinimumLevel(LogLevel.Trace));
        var vault = new FakeKeyVault((_, _) => (HttpStatusCode.Forbidden, FakeKeyVault.ErrorJson("Forbidden",
            "Public network access is disabled and request is not from a trusted service nor via an approved private link.", "ForbiddenByConnection")));
        var store = new AzureKeyVaultSecretStore(vault.CreateClients(), factory.CreateLogger<AzureKeyVaultSecretStore>());

        var result = await store.GetSecretAsync("db");

        await Assert.That(result.Error!.Code).IsEqualTo(CofreErrors.AccessDeniedCode);
        await Assert.That(logs.Entries.Any(e => e.Level == LogLevel.Error && e.Text.Contains("ForbiddenByConnection"))).IsTrue();
    }

    [Test]
    [Arguments("SecretDisabled")]
    [Arguments("KeyDisabled")]
    [Arguments("CertificateDisabled")]
    public async Task Codigo_estruturado_de_item_desabilitado_vira_Disabled(string innerCode)
    {
        var vault = new FakeKeyVault((_, _) => (HttpStatusCode.Forbidden, FakeKeyVault.ErrorJson("Forbidden", "qualquer texto", innerCode)));
        var store = new AzureKeyVaultSecretStore(vault.CreateClients());

        var result = await store.GetSecretAsync("db");

        await Assert.That(result.Error!.Code).IsEqualTo(CofreErrors.DisabledCode);
    }

    [Test]
    public async Task Codigo_interno_fora_do_formato_nao_vai_para_o_log()
    {
        var logs = new CapturingLoggerProvider();
        using var factory = LoggerFactory.Create(b => b.AddProvider(logs).SetMinimumLevel(LogLevel.Trace));
        var vault = new FakeKeyVault((_, _) => (HttpStatusCode.Forbidden, FakeKeyVault.ErrorJson("Forbidden", "x", "<script>alert(1)</script>")));
        var store = new AzureKeyVaultSecretStore(vault.CreateClients(), factory.CreateLogger<AzureKeyVaultSecretStore>());

        var result = await store.GetSecretAsync("db");

        await Assert.That(result.Error!.Code).IsEqualTo(CofreErrors.AccessDeniedCode);
        await Assert.That(logs.AllText).DoesNotContain("<script>");
    }

    [Test]
    [Arguments("<script>alert(1)</script>")]
    [Arguments("codigo com espaco")]
    public async Task Codigo_de_erro_fora_do_formato_nao_vai_para_o_log(string code)
    {
        // error.code vem do corpo da resposta, como o innererror.code: passa pela mesma conferência (SafeCode)
        var logs = new CapturingLoggerProvider();
        using var factory = LoggerFactory.Create(b => b.AddProvider(logs).SetMinimumLevel(LogLevel.Trace));
        var vault = new FakeKeyVault((_, _) => (HttpStatusCode.BadRequest, FakeKeyVault.ErrorJson(code, "x")));
        var store = new AzureKeyVaultSecretStore(vault.CreateClients(), factory.CreateLogger<AzureKeyVaultSecretStore>());

        var result = await store.GetSecretAsync("db");

        await Assert.That(result.Error!.Code).IsEqualTo(CofreErrors.RejectedCode);
        await Assert.That(logs.AllText).DoesNotContain(code);
        await Assert.That(logs.AllText).Contains(AzureKeyVaultStoreBase.InvalidCodeMarker);
    }

    [Test]
    public async Task SafeCode_aceita_so_identificador_ASCII_curto()
    {
        await Assert.That(AzureKeyVaultStoreBase.SafeCode("SecretNotFound")).IsEqualTo("SecretNotFound");
        await Assert.That(AzureKeyVaultStoreBase.SafeCode("Forbidden_By-Rbac.1")).IsEqualTo("Forbidden_By-Rbac.1");
        await Assert.That(AzureKeyVaultStoreBase.SafeCode(null)).IsNull();
        await Assert.That(AzureKeyVaultStoreBase.SafeCode("")).IsNull();
        await Assert.That(AzureKeyVaultStoreBase.SafeCode("linha\nnova")).IsEqualTo(AzureKeyVaultStoreBase.InvalidCodeMarker);
        await Assert.That(AzureKeyVaultStoreBase.SafeCode("códigoAcentuado")).IsEqualTo(AzureKeyVaultStoreBase.InvalidCodeMarker);
        await Assert.That(AzureKeyVaultStoreBase.SafeCode(new string('a', 65))).IsEqualTo(AzureKeyVaultStoreBase.InvalidCodeMarker);
    }

    [Test]
    public async Task Nome_recusado_e_descrito_com_HMAC_de_chave_do_processo_e_nao_com_hash_puro()
    {
        // Um SHA-256 puro permitiria confirmar, fora do processo, um palpite sobre o texto recusado (ex.: um valor colado no nome)
        string name = "nome invalido " + SecretValue;
        string sha256 = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(name)), 0, 6);

        string first = VaultProviderBase.DescribeUntrusted(name);
        string second = VaultProviderBase.DescribeUntrusted(name);
        string other = VaultProviderBase.DescribeUntrusted(name + "x");

        await Assert.That(first).IsEqualTo(second);          // mesmo texto, mesmo identificador (correlação dentro do processo)
        await Assert.That(other).IsNotEqualTo(first);
        await Assert.That(first).Contains("hmac:");
        await Assert.That(first).DoesNotContain(sha256);
        await Assert.That(first).DoesNotContain(SecretValue);
    }

    [Test]
    public async Task Registros_internos_com_valor_de_segredo_mascaram_o_ToString()
    {
        var version = new InMemorySecretStore.Version(new SecretProperties { Name = "db", Version = FakeKeyVault.Version }, SecretValue);
        var snapshot = new CofreConfigurationProvider.Snapshot(FakeKeyVault.Version, DateTimeOffset.UtcNow, "Db:Senha", SecretValue);

        await Assert.That(version.ToString()).DoesNotContain(SecretValue);
        await Assert.That($"{version with { Value = SecretValue + "2" }}").DoesNotContain(SecretValue);
        await Assert.That(version.ToString()).Contains("Value = ***");
        await Assert.That(snapshot.ToString()).DoesNotContain(SecretValue);
        await Assert.That($"{snapshot}").Contains("Value = ***");
    }

    [Test]
    public async Task Clientes_do_SDK_nao_geram_spans_com_o_endereco_e_o_nome_do_item()
    {
        // Os spans do SDK levam url.full/az.namespace (endereço do cofre + nome e versão do item) ao backend de rastreamento
        var started = new ConcurrentQueue<Activity>();
        using var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name.StartsWith("Azure.", StringComparison.Ordinal),
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStarted = started.Enqueue
        };
        ActivitySource.AddActivityListener(listener);

        // Controle: um cliente do SDK com as opções padrão gera spans (prova que o listener os enxerga)
        var control = new FakeKeyVault((_, _) => (HttpStatusCode.OK, FakeKeyVault.SecretJson("item-controle", "v")));
        var sdk = new SecretClient(new Uri(FakeKeyVault.VaultUri), new FakeCredential(),
            new SecretClientOptions { Transport = new HttpClientTransport(new HttpClient(control)) });
        await sdk.GetSecretAsync("item-controle");
        await Assert.That(started.Any(a => Describe(a).Contains("item-controle", StringComparison.Ordinal))).IsTrue();

        var vault = new FakeKeyVault((_, _) => (HttpStatusCode.OK, FakeKeyVault.SecretJson("item-sem-span", "v")));
        var store = new AzureKeyVaultSecretStore(vault.CreateClients());
        var result = await store.GetSecretAsync("item-sem-span");

        await Assert.That(result.IsSuccess).IsTrue();
        await Assert.That(started.Any(a => Describe(a).Contains("item-sem-span", StringComparison.Ordinal))).IsFalse();

        static string Describe(Activity activity) =>
            activity.DisplayName + " " + string.Join(' ', activity.TagObjects.Select(t => $"{t.Key}={t.Value}"));
    }

    [Test]
    public async Task Logs_de_escrita_e_de_falha_nao_contem_o_valor()
    {
        var logs = new CapturingLoggerProvider();
        using var factory = LoggerFactory.Create(b => b.AddProvider(logs).SetMinimumLevel(LogLevel.Trace));
        var vault = new FakeKeyVault((request, body) => request.Method == HttpMethod.Put
            ? (HttpStatusCode.OK, FakeKeyVault.SecretJson("db", SecretValue))
            : (HttpStatusCode.Forbidden, FakeKeyVault.ErrorJson("Forbidden", "Caller is not authorized.", "ForbiddenByRbac")));
        var store = new AzureKeyVaultSecretStore(vault.CreateClients(), factory.CreateLogger<AzureKeyVaultSecretStore>());

        var set = await store.SetSecretAsync("db", SecretValue);
        var get = await store.GetSecretAsync("db");

        await Assert.That(set.IsSuccess).IsTrue();
        await Assert.That(get.Error!.Code).IsEqualTo(CofreErrors.AccessDeniedCode);
        await Assert.That(logs.Entries).IsNotEmpty();
        await Assert.That(logs.AllText).DoesNotContain(SecretValue);
        await Assert.That(logs.Entries.Any(e => e.Level == LogLevel.Information && e.Text.Contains("secret.set"))).IsTrue();
    }

    // ---------- Conversão de erros: nada de infraestrutura chega ao cliente ----------

    [Test]
    [Arguments(400, "BadParameter", "detalhe-interno-do-servidor", CofreErrors.RejectedCode, ErrorType.Validation)]
    [Arguments(401, "Unauthorized", "detalhe-interno-do-servidor", CofreErrors.AuthenticationFailedCode, ErrorType.ExternalService)]
    // Sem código estruturado de item desabilitado, 403 é acesso negado: o texto da mensagem não decide mais nada
    [Arguments(403, "Forbidden", "Operation get is not allowed on a disabled secret.", CofreErrors.AccessDeniedCode, ErrorType.ExternalService)]
    [Arguments(403, "Forbidden", "Public network access is disabled and request is not from a trusted service.", CofreErrors.AccessDeniedCode, ErrorType.ExternalService)]
    [Arguments(403, "SecretDisabled", "x", CofreErrors.DisabledCode, ErrorType.BusinessRule)]
    [Arguments(403, "Forbidden", "Caller is not authorized. ForbiddenByRbac", CofreErrors.AccessDeniedCode, ErrorType.ExternalService)]
    [Arguments(404, "SecretNotFound", "detalhe-interno-do-servidor", CofreErrors.NotFoundCode, ErrorType.NotFound)]
    [Arguments(409, "Conflict", "detalhe-interno-do-servidor", CofreErrors.ConflictCode, ErrorType.Conflict)]
    [Arguments(429, "Throttled", "detalhe-interno-do-servidor", CofreErrors.ThrottledCode, ErrorType.ExternalService)]
    [Arguments(503, "ServiceUnavailable", "detalhe-interno-do-servidor", CofreErrors.UnavailableCode, ErrorType.ExternalService)]
    [Arguments(0, null, "DNS", CofreErrors.UnavailableCode, ErrorType.ExternalService)]
    public async Task RequestFailedException_e_convertida(int status, string? code, string message, string expectedCode, ErrorType expectedType)
    {
        var mapped = AzureKeyVaultStoreBase.Map(new RequestFailedException(status, message, code, null));

        await Assert.That(mapped!.Value.Error.Code).IsEqualTo(expectedCode);
        await Assert.That(mapped.Value.Error.Type).IsEqualTo(expectedType);
        await Assert.That(mapped.Value.Error.Message).DoesNotContain(message);
    }

    [Test]
    public async Task Falha_de_autenticacao_e_convertida_sem_detalhes()
    {
        var mapped = AzureKeyVaultStoreBase.Map(new AuthenticationFailedException("AADSTS700016: tenant 1234 ..."));

        await Assert.That(mapped!.Value.Error.Code).IsEqualTo(CofreErrors.AuthenticationFailedCode);
        await Assert.That(mapped.Value.Detail).DoesNotContain("AADSTS");
    }

    [Test]
    public async Task Excecao_desconhecida_nao_e_convertida_pelo_mapa() =>
        await Assert.That(AzureKeyVaultStoreBase.Map(new InvalidCastException())).IsNull();

    [Test]
    public async Task Erros_de_infraestrutura_nao_sao_expostos_ao_cliente()
    {
        Error[] hidden = [CofreErrors.AccessDenied(), CofreErrors.AuthenticationFailed(), CofreErrors.Throttled(), CofreErrors.Unavailable(), CofreErrors.ProviderFailure()];

        foreach (var error in hidden)
            await Assert.That(error.Type.IsExposedToClient()).IsFalse();
    }
}
