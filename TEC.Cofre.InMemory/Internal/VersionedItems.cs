using System.Security.Cryptography;

namespace TEC.Cofre.InMemory.Internal;

/// <summary>
/// Itens versionados em memória com exclusão lógica (lixeira) e backup opaco. Nomes sem diferenciar maiúsculas (como no
/// Azure Key Vault). Não é thread-safe: o chamador usa <see cref="Sync"/>.
/// </summary>
/// <typeparam name="T">Versão imutável do item (a última da lista é a atual).</typeparam>
internal sealed class VersionedItems<T> where T : class
{
    private readonly Dictionary<string, List<T>> _active = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, Deleted> _deleted = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, Snapshot> _backups = new(StringComparer.Ordinal);

    private sealed record Deleted(string Name, List<T> Versions, DateTimeOffset DeletedOn);

    private sealed record Snapshot(string Name, List<T> Versions);

#if NET9_0_OR_GREATER
    public Lock Sync { get; } = new();
#else
    public object Sync { get; } = new();
#endif

    public bool IsDeleted(string name) => _deleted.ContainsKey(name);

    public bool Exists(string name) => _active.ContainsKey(name);

    public IReadOnlyList<T>? Versions(string name) => _active.TryGetValue(name, out var versions) ? versions : null;

    /// <summary>Versão informada ou, sem versão, a atual.</summary>
    public T? Find(string name, string? version, Func<T, string> versionOf)
    {
        if (!_active.TryGetValue(name, out var versions))
            return null;
        return version is null
            ? versions[^1]
            : versions.Find(v => string.Equals(versionOf(v), version, StringComparison.OrdinalIgnoreCase));
    }

    public IEnumerable<T> Current() => _active.Values.Select(v => v[^1]);

    public void Add(string name, T version)
    {
        if (!_active.TryGetValue(name, out var versions))
            _active[name] = versions = [];
        versions.Add(version);
    }

    public void Replace(string name, T current, T updated)
    {
        var versions = _active[name];
        versions[versions.IndexOf(current)] = updated;
    }

    public bool Delete(string name, DateTimeOffset now)
    {
        if (!_active.Remove(name, out var versions))
            return false;
        _deleted[name] = new Deleted(name, versions, now);
        return true;
    }

    public IEnumerable<(string Name, DateTimeOffset DeletedOn)> ListDeleted() => _deleted.Values.Select(d => (d.Name, d.DeletedOn));

    public IReadOnlyList<T>? Recover(string name)
    {
        if (!_deleted.Remove(name, out var deleted))
            return null;
        _active[deleted.Name] = deleted.Versions;
        return deleted.Versions;
    }

    public bool Purge(string name) => _deleted.Remove(name);

    /// <summary>Backup opaco: um identificador aleatório que só esta instância reconhece (não contém nenhum dado do item).</summary>
    public byte[]? Backup(string name)
    {
        if (!_active.TryGetValue(name, out var versions))
            return null;

        byte[] token = RandomNumberGenerator.GetBytes(32);
        _backups[Convert.ToHexString(token)] = new Snapshot(name, [.. versions]);
        return token;
    }

    /// <summary>Restaura um backup. <c>null</c> = backup desconhecido ou nome ocupado (<paramref name="conflict"/> = <c>true</c>).</summary>
    public IReadOnlyList<T>? Restore(byte[] token, out string? name, out bool conflict)
    {
        name = null;
        conflict = false;
        if (!_backups.TryGetValue(Convert.ToHexString(token), out var snapshot))
            return null;

        name = snapshot.Name;
        if (_active.ContainsKey(snapshot.Name) || _deleted.ContainsKey(snapshot.Name))
        {
            conflict = true;
            return null;
        }

        _active[snapshot.Name] = [.. snapshot.Versions];
        return _active[snapshot.Name];
    }
}
