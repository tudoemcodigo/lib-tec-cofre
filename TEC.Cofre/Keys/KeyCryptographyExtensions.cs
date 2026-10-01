using System.Security.Cryptography;
using TEC.Cofre.Abstractions;
using TEC.Cofre.Common;
using TEC.Core.Common.Results;
using TEC.Core.Cryptography.Symmetric;

namespace TEC.Cofre.Keys;

/// <summary>Criptografia envelope com qualquer provedor de chaves.</summary>
/// <remarks>
/// <para>Uma chave de dados AES-256 aleatória (DEK) cifra o conteúdo localmente com AES-GCM (autenticado, via TEC.Core);
/// a DEK é protegida (wrap) pela chave do cofre (KEK) e descartada da memória. Não há limite de tamanho e o cofre recebe
/// apenas 32 bytes por operação.</para>
/// <para>Use <c>associatedData</c> para amarrar o conteúdo ao contexto (ex.: id do registro): a descriptografia
/// com outro contexto falha, impedindo que um campo cifrado seja copiado para outro registro.</para>
/// </remarks>
public static class KeyCryptographyExtensions
{
    private const int DataKeySize = 32;
    private static readonly AesGcmCryptography Aes = new();

    /// <summary>Cifra <paramref name="plaintext"/> com criptografia envelope.</summary>
    public static async Task<Result<EnvelopeEncryptedData>> EncryptEnvelopeAsync(this IKeyCryptography store, string keyName, byte[] plaintext,
        byte[]? associatedData = null, string? keyVersion = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(plaintext);

        var dataKey = Aes.GenerateKey();   // AES-256 (32 bytes), gerador criptográfico do TEC.Core
        try
        {
            var wrapped = await store.WrapKeyAsync(keyName, dataKey, VaultEncryptionAlgorithm.RsaOaep256, keyVersion, cancellationToken)
                .ConfigureAwait(false);
            if (wrapped.IsFailure)
                return wrapped.ToFailure<EnvelopeEncryptedData>();

            var ciphertext = Aes.Encrypt(plaintext, dataKey, associatedData);
            return new EnvelopeEncryptedData(wrapped.Value.KeyName, wrapped.Value.KeyVersion, wrapped.Value.Ciphertext, ciphertext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dataKey);
        }
    }

    /// <summary>Decifra dados produzidos por <see cref="EncryptEnvelopeAsync"/>. Dados adulterados ou contexto diferente retornam erro de validação.</summary>
    public static async Task<Result<byte[]>> DecryptEnvelopeAsync(this IKeyCryptography store, EnvelopeEncryptedData data,
        byte[]? associatedData = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(data);
        if (data.Ciphertext is null || data.WrappedKey is null)
            return CofreErrors.InvalidInput("data", "Dados cifrados incompletos.");

        var unwrapped = await store.UnwrapKeyAsync(data.KeyName, data.KeyVersion, data.WrappedKey, VaultEncryptionAlgorithm.RsaOaep256,
            cancellationToken).ConfigureAwait(false);
        if (unwrapped.IsFailure)
            return unwrapped;

        var dataKey = unwrapped.Value;
        try
        {
            if (dataKey.Length != DataKeySize)
                return InvalidCiphertext();
            return Aes.Decrypt(data.Ciphertext, dataKey, associatedData);
        }
        catch (CryptographicException)
        {
            return InvalidCiphertext();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dataKey);
        }
    }

    private static Error InvalidCiphertext() => CofreErrors.InvalidInput("ciphertext", "Dados cifrados inválidos, adulterados ou de outro contexto.");
}
