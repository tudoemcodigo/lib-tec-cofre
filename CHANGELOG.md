# Changelog

Formato baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/). Enquanto a versão for `0.0.x`, quebras de API são aceitas e ficam listadas em **Quebras**.

## [Não publicado]

### Quebras

#### Fase 3: revisão de segurança

- Nomes, versões, nomes DNS e emissores com **quebra de linha no final** (`"nome\n"`) passam a ser recusados (`COFRE_ENTRADA_INVALIDA`): os padrões terminavam em `$`, que aceita `\n` final; agora terminam em `\z`.
- Cofre fora do ar (falha de transporte) com `MaxRetries > 0` retornava `COFRE_FALHA`; agora retorna `COFRE_INDISPONIVEL` (o Azure.Core lança `AggregateException` quando todas as tentativas falham por exceção). `IOException`/`HttpRequestException`/`SocketException` sem retentativa também viram `COFRE_INDISPONIVEL`.
- Log de entrada recusada (evento 2006): o identificador do nome mudou de `sha256:<prefixo>` para `hmac:<prefixo>` (HMAC-SHA256 com chave aleatória do processo; não é mais comparável entre processos nem reproduzível fora dele).
- Log de falha do Azure Key Vault: `error.code` fora do formato de identificador é substituído por `codigo-invalido` (antes ia como veio); `innererror.code` inválido, antes omitido, também aparece como `codigo-invalido`.
- `AzureKeyVaultOptions.CryptographyClientLifetime` (padrão 10 minutos): os clientes de criptografia reaproveitados passam a ser recriados após esse tempo (uma busca da chave pública a mais por chave + versão a cada período).
- Os spans do SDK do Azure (`Azure.*`) não são mais gerados pelos clientes do provedor (`IsDistributedTracingEnabled = false`); a `Activity` do TEC.Cofre continua igual.
- `CofreConfigurationOptions`: `MaxSecrets` e `MaxConcurrentReads` inválidos continuam lançando `ArgumentOutOfRangeException` com o mesmo nome de parâmetro, mas a mensagem passou a ser a do `Guard` do TEC.Core.
- Dependência: o formato do AES-GCM do TEC.Core mudou (o byte de versão passou a ser autenticado): `EnvelopeEncryptedData.Ciphertext` gerado com o TEC.Core anterior **não** é decifrado; decifre com a versão anterior e cifre de novo.
- CI: os testes de integração com o Key Vault saíram do job `build` para o job `integration` (só na `main`); o job `publish` depende dos dois.

#### Fase 2: interfaces menores, .NET 8, AOT

- **Interfaces divididas** por responsabilidade (pensando em provedores sem backup/lixeira, como HashiCorp Vault KV v2 e AWS Secrets Manager):
  - Segredos: `ISecretReader` (`GetSecretAsync`, `ExistsAsync`, `ListSecretsAsync`, `ListSecretVersionsAsync`, `ProviderName`); `ISecretStore : ISecretReader` (`SetSecretAsync`, `UpdateSecretPropertiesAsync`, `DeleteSecretAsync`); opcionais `ISecretRecycleBin` (`ListDeleted…`, `RecoverDeleted…`, `PurgeDeleted…`) e `ISecretBackup` (`Backup…`, `Restore…Backup`).
  - Chaves: `IKeyReader` (`GetKeyAsync`, `ListKeysAsync`, `ListKeyVersionsAsync`); `IKeyStore : IKeyReader` (`CreateKeyAsync`, `UpdateKeyPropertiesAsync`, `RotateKeyAsync`, `DeleteKeyAsync`); `IKeyCryptography` (`Encrypt/Decrypt`, `WrapKey/UnwrapKey`, `SignData/VerifyData`); opcionais `IKeyRecycleBin` e `IKeyBackup`.
  - Certificados: `ICertificateReader` (`GetCertificateAsync`, `DownloadCertificateAsync`, `ListCertificatesAsync`, `ListCertificateVersionsAsync`); `ICertificateStore : ICertificateReader` (`Create…`, `Import…`, `Update…Properties`, `Delete…`); opcionais `ICertificateRecycleBin` e `ICertificateBackup`.
  - Quem chamava lixeira/backup/criptografia por `ISecretStore`/`IKeyStore`/`ICertificateStore` passa a injetar a interface correspondente (todas apontam para a mesma instância no DI).
- `KeyStoreExtensions` → `KeyCryptographyExtensions`; `EncryptEnvelopeAsync`/`DecryptEnvelopeAsync` estendem `IKeyCryptography`.
- `CofreConfigurationBuilderExtensions.AddTecCofre` recebe `ISecretReader` (fonte compatível para quem passava `ISecretStore`).
- `CofreBuilder.UseSecretStore<T>()` exige `T : ISecretReader`; `UseKeyStore<T>()` exige `IKeyReader` e/ou `IKeyCryptography` (verificado na chamada); `UseCertificateStore<T>()` exige `ICertificateReader`. Novas sobrecargas com fábrica (`UseSecretStore(sp => ...)`).
- `AddTecCofre` registra **só** as interfaces que o provedor implementa, todas para a mesma instância; o tipo concreto também fica registrado como singleton. O Azure não registra mais `AzureKeyVaultClients` no container.
- Cache: `CachingSecretStore` (decorator de `ISecretStore`) foi substituído por `CachingSecretReader` (decorator de `ISecretReader`) + decorators de escrita que limpam o cache (`ISecretStore`, `ISecretRecycleBin`, `ISecretBackup`).
- Detalhes do Azure removidos da abstração:
  - `VaultItemProperties.Managed` (`bool`) → `ManagedBy` (`string?`, ex.: `"certificate"`) + `IsManaged`.
  - `VaultItemProperties.Id`: `Uri?` → `string?` (URI, ARN, caminho...).
  - `DeletedVaultItem`: sem `RecoveryId` (agora `Name`, `DeletedOn`, `ScheduledPurgeDate`).
  - `VaultKeyType`: só `Rsa = 0` e `Ec = 1` (`RsaHsm`/`EcHsm` removidos; valores renumerados) → `HardwareProtected` em `CreateKeyOptions`, `CreateCertificateOptions` e `VaultKey`.
  - `CreateCertificateOptions.IssuerName` (padrão `"Self"`) → `Issuer` (`null` = autoassinado).
- `TEC.Cofre.AzureKeyVault`: `AzureKeyVaultSecretStore`, `AzureKeyVaultKeyStore`, `AzureKeyVaultCertificateStore` e a base `AzureKeyVaultStoreBase` passam a ser públicos (construtores internos), e `AzureKeyVaultStores.Create*` os devolvem (antes `ISecretStore`/`IKeyStore`/`ICertificateStore`).
- `EnvelopeEncryptedData.Ciphertext` segue o formato versionado do AES-GCM do TEC.Core (`[versão][nonce][tag][dados]`): envelopes gerados com o TEC.Core anterior **não** são decifrados; decifre com a versão anterior e cifre de novo.
- Dependência: TEC.Core 0.0.1 (`net8.0` + `net10.0`, AOT; ver o CHANGELOG do TEC.Core).
- **Health check com tags `ready` e `vault` por padrão** (`AddHealthChecks().AddTecCofre()`): entra no readiness do TEC.Observability (`/health/ready`) sem configuração. Antes, sem `tags`, o check não tinha tag e ficava fora dos endpoints filtrados por tag. Informar `tags` substitui as duas (passe `[]` para manter o comportamento anterior).

#### Fase 1

- `SecretStoreExtensions.RotateSecretAsync` agora retorna `Result<SecretRotationResult>` (antes `Result<SecretProperties>`) e ganhou o parâmetro `timeProvider` antes de `cancellationToken`. A nova versão está em `SecretRotationResult.Current`. Falha ao desabilitar versões anteriores **não** é mais erro: é sucesso com `IsComplete = false`, `FailedVersions` e `Errors`.
- `CofreConfigurationBuilderExtensions.AddTecCofre` ganhou o parâmetro opcional `loggerFactory` (quebra binária; fonte compatível).
- 403 do Azure Key Vault só vira `COFRE_ITEM_DESABILITADO` com código estruturado (`SecretDisabled`, `KeyDisabled`, `CertificateDisabled`); qualquer outro 403 — inclusive o de firewall "Public network access is disabled" — vira `COFRE_ACESSO_NEGADO` (log `Error`).
- `AddTecCofre` sempre registra `IVaultHealthProbe` (com `TryAdd`) e a sonda verifica **todos** os stores registrados. Com o Azure Key Vault e `Stores = All` (padrão), a identidade precisa poder listar segredos, chaves **e** certificados para o health check ficar saudável; registre só o que usa com `AzureKeyVaultOptions.Stores`.
- Nomes de operação do health check no log: `health` → `secret.health`, `key.health`, `certificate.health`.
- `AzureKeyVaultAuthentication.Developer`: quando há `IHostEnvironment` (no container ou em `AzureKeyVaultOptions.HostEnvironment`), ele decide o ambiente, e não mais as variáveis `ASPNETCORE_ENVIRONMENT`/`DOTNET_ENVIRONMENT`.
- Build: `NU1901`–`NU1904` (vulnerabilidade conhecida em pacote) passam a ser erro em todos os projetos.

### Adicionado

- **.NET 8**: todos os pacotes (e os testes) com `net8.0` e `net10.0`, mesmo comportamento. `X509CertificateLoader` (.NET 9+) → `VaultCertificateLoader`, que no .NET 8 confere o tipo do conteúdo e usa o construtor de `X509Certificate2` com os mesmos flags; `System.Threading.Lock` → `lock` em `object` no .NET 8.
- **Native AOT/trimming**: `IsAotCompatible=true` com IL2xxx/IL3xxx como erro em todos os pacotes; verificado com publicação trimmed (net8.0/net10.0) e AOT (ILC) sem avisos em `TEC.Cofre` e `TEC.Cofre.InMemory`. O `Azure.Core` gera dois avisos próprios (documentados no README).
- **Pacote `TEC.Cofre.InMemory`**: provedor em memória (segredos, chaves RSA/EC com criptografia e assinatura reais, certificados autoassinados/importados, lixeira e backup opaco) para desenvolvimento local e testes, com `UseInMemory(...)`, `InitialSecrets` e trava fora de Development (`AllowOutsideDevelopment`). Substitui os fakes internos dos testes.
- **Métricas**: Meter `TEC.Cofre` (`CofreDiagnostics.MeterName`) com `cofre.operation.duration` (histograma em segundos; `cofre.provider`, `cofre.operation`, `error.type`) e `cofre.cache.requests` (`hit`/`miss`/`coalesced`), sem nome de item.
- **Alinhamento com o TEC.Observability** (exporta as fontes `TEC.*` sem configuração): a `Activity` de cada operação ganhou `error.type`, com o mesmo valor da métrica (código de `CofreErrors`, ou `canceled`); constantes `CofreHealthChecksBuilderExtensions.ReadyTag` e `VaultTag`.
- Regras comuns para provedores: `VaultKeyRules` (RSA ≥ 2048, curvas, operações, algoritmos), `VaultCertificateRules` (criação, detecção/normalização de PEM, inspeção da importação) e `VaultCertificateLoader`.
- `VaultItemProperties.IsManaged`; `VaultKey.HardwareProtected`.
- `EnablePackageValidation` (sem baseline) no `dotnet pack`.
- CI: `setup-dotnet` com `global-json-file` + runtime `8.0.x`; `.trx` com nome padrão (um por alvo); CodeQL com o SDK do `global.json`.
- `SecretRotationResult` e `SecretStoreExtensions.DisablePreviousSecretVersionsAsync` (conclui uma rotação parcial sem criar nova versão; idempotente).
- `CofreStores` e `AzureKeyVaultOptions.Stores`: escolhe quais stores o `UseAzureKeyVault` registra.
- `AzureKeyVaultOptions.HostEnvironment`; `UseAzureKeyVault` usa o `IHostEnvironment` registrado no container.
- `CofreConfigurationOptions.LoadTimeout` (padrão 30 s) e `MaxConcurrentReads` (padrão 4); recarga incremental (só relê segredos com versão/`UpdatedOn` alterados; releitura completa a cada 12 recargas).
- `IVaultHealthProbe` nos stores de chaves e certificados do Azure (uma página de metadados).
- `VaultProviderBase.AuditSensitiveRead` para provedores auditarem leituras sensíveis.
- Importação de certificado PEM: RSA e EC, PKCS#8 (com ou sem senha), PKCS#1, SEC1, saída do OpenSSL com `Bag Attributes` e BOM UTF-8.
- Build com o TEC.Core local: com o repositório na pasta vizinha (`..\TEC.Core`), referência de projeto (`UseLocalTecCore`, lock file em `packages.local.lock.json`, ignorado pelo git); sem ele, o pacote `TEC.Core` do feed `tec-interno`. Forçar o pacote: `-p:UseLocalTecCore=false`. O `.nupkg` sempre depende do pacote `TEC.Core`.
- Workflow CodeQL; metadados NuGet (autor, empresa, URLs, ícone); `global.json` com SDK fixado; `.editorconfig`; `.gitattributes`.
- `AzureKeyVaultOptions.CryptographyClientLifetime` (1 minuto a 24 horas; padrão 10 minutos), com `MinCryptographyClientLifetime`/`MaxCryptographyClientLifetime`.
- Regras compartilhadas pelos provedores (antes duplicadas entre `TEC.Cofre.AzureKeyVault` e `TEC.Cofre.InMemory`): `VaultProviderRules` (limites do provedor + validação de cada operação: `SetSecret`, `UpdateSecret`, `CreateKey`, `UpdateKey`, `Encrypt`, `Decrypt`, `Sign`, `Verify`, `ImportCertificate`), `VaultInputRules.HexVersionPattern`/`RequiredVersion`/`MaxContentTypeLength`, `VaultKeyRules.MaxEncryptBytes`/`MaxCiphertextBytes`/`MaxSignDataBytes`/`ToECCurve`/`CurveHash`/`RsaSignature`/`EcSignature`, `VaultVersionRules` (versão atual = maior `CreatedOn`, com desempate), `VaultEnvironment` (trava de Development e busca do `IHostEnvironment`), `VaultProviderBase.CopyTags`, `CofreBuilder.UseStores` e `CofreBuilder.EnsureValidStores`.
- Uso do que o TEC.Core já oferece: `Result.ToFailure()`/`ToFailure<T>()` para propagar erros, `Guard` nas validações de argumento, `AesGcmCryptography.GenerateKey()` para a chave de dados do envelope e `HashHelper.ComputeHmac` no identificador de nome recusado.

### Corrigido

- `ImportCertificateOptions.ToString()` imprimia a senha; agora mascara (`Password = ***`), também no depurador.
- Importação PEM não carregava a chave privada (`CreateFromPem` só com o certificado) e PEM com texto antes do primeiro bloco era tratado como PFX.
- Cache de segredos: leitura iniciada antes de uma escrita podia regravar o valor antigo depois da limpeza (contador de geração); leituras simultâneas da mesma chave agora compartilham uma única chamada (o cancelamento de um chamador não afeta os demais; falhas não são guardadas).
- Leitura de segredo gerenciado (conteúdo de certificado com chave privada) por `ISecretStore` passa a ser auditada em `Information`, como prometido na documentação.
- Provedor de `IConfiguration`: falhas de carga/recarga, tempo limite e estouro de `MaxSecrets` são registrados em log (a mensagem "Verifique o log" passou a ser verdadeira) e a exceção traz o código do erro.
- Versão "atual" de segredo com `CreatedOn` empatado (mesmo segundo): consulta ao cofre em vez de escolha arbitrária (`UpdateSecretPropertiesAsync` sem versão e `RotateSecretAsync`).
- `RotateSecretAsync` usava `DateTimeOffset.UtcNow` direto; agora usa `TimeProvider`.
- Nome recusado na validação ia cru para o log; agora só tamanho + um identificador curto (HMAC com chave do processo; veja a revisão de segurança abaixo).
- `CryptographyClient` era criado a cada operação; agora é reaproveitado por nome + versão (até 256; sem versão continua sendo criado por chamada para seguir rotações).
- Health check: aplicação só com chaves ficava `Unhealthy` (a sonda listava segredos) e, com só `UseKeyStore`, nenhuma sonda era registrada.
- Testes de integração: limpeza de sobras `tec-teste-*` com mais de 1 hora no início (desligável com `TEC_COFRE_LIMPEZA=0`).
- Publicação: o `release.yml` publicava antes de criar a tag e `--skip-duplicate` escondia reexecuções; agora testa → cria a tag → publica (sem `--skip-duplicate`) → cria o Release. Actions fixadas por SHA e alinhadas entre `ci.yml` e `release.yml`.
- Documentação: link do TEC.Core (quebrava no NuGet), OIDC só na `main` (#24), `DefaultKeySet` no macOS (#13), formatos PEM.
- **Segurança (revisão):**
  - Padrões de nome, versão, nome DNS, emissor e nome do cofre terminavam em `$`, que aceita uma quebra de linha final; agora `\z`.
  - Cofre fora do ar virava `COFRE_FALHA` (a `AggregateException` da política de retry do Azure.Core não era convertida); agora `COFRE_INDISPONIVEL`, com e sem retentativas.
  - `CryptographyClient` ficava em cache até o processo reiniciar: o SDK cifra/faz wrap/verifica localmente com a chave pública lida na primeira operação, então uma chave desabilitada no cofre continuava em uso. Agora cada cliente vive no máximo `CryptographyClientLifetime`.
  - Spans do SDK do Azure levavam o endereço do cofre e o nome/versão do item aos traces; foram desligados nos clientes do provedor. A documentação do controle #29 dizia mais do que o componente garante (a instrumentação de `HttpClient` de terceiros grava `url.full`).
  - `IConfigurationRoot.Reload()` com `Optional = true` e o cofre fora do ar trocava a configuração por vazio (apagava os segredos carregados); agora mantém os valores anteriores, como a recarga periódica.
  - Cache de segredos: leitura em andamento ficava presa para sempre se o cache fosse descartado (o resultado da tarefa compartilhada só era definido depois de gravar no cache, que lançava `ObjectDisposedException`), e uma escrita depois do descarte tinha o resultado mascarado pela exceção da limpeza. A varredura de expirados passa a acompanhar durações menores que 1 minuto.
  - Registros internos com valor de segredo (`InMemorySecretStore.Version`, `CofreConfigurationProvider.Snapshot`) imprimiam o valor no `ToString` gerado pelo `record`; agora mascaram, também no depurador.
  - Nome recusado na validação ia ao log com prefixo de SHA-256 sem chave (permitia confirmar, fora do processo, um palpite sobre um valor colado no lugar do nome); agora HMAC-SHA256 com chave aleatória do processo.
  - `error.code` do Key Vault ia ao log sem conferência de formato (só o `innererror.code` era conferido); agora os dois passam pelo mesmo `SafeCode`.
  - Cópias da chave privada na importação PEM (texto decodificado, PEM normalizado, PKCS#12 não guardado) não eram zeradas; agora são (`CryptographicOperations.ZeroMemory`), e o PEM é carregado sem criar `string`.
  - Documentado: com `EnableSecretCache`, a classe concreta do provedor continua resolvível e grava sem limpar o cache (escritas devem passar por `ISecretStore`/`ISecretRecycleBin`/`ISecretBackup`).
- **Pipeline:** versão conferida com SemVer em todos os caminhos (a prévia, vinda de `git describe --match`, não era; a tag é conferida antes da conta do patch); nenhum `${{ ... }}` dentro de `run:` (versão e token do `nuget push` por `env:`); `id-token: write` só no novo job `integration` (antes valia também em `pull_request`); Release manual só publica se o commit estiver na `main`; `persist-credentials: false` em todos os checkouts.

## [0.0.1]

- Versão inicial.
