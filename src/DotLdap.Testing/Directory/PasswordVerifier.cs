using System.Security.Cryptography;
using DotLdap.Testing.Protocol;

namespace DotLdap.Testing;

/// <summary>
/// Checks a bind password against userPassword values. A value is either the password itself or an RFC 2307
/// hash with a scheme prefix: {MD5}, {SMD5} and {SHA}, {SSHA} with their 256, 384 and 512 variants.
/// Hashes in schemes that are not implemented ({CRYPT}, {PBKDF2...}, {ARGON2...} and the like) match nothing.
/// Anything else, including text in braces that does not name a hash scheme, is a clear-text password, as in
/// OpenLDAP.
/// </summary>
internal static class PasswordVerifier
{
    public static bool Verify(IEnumerable<byte[]> storedValues, string password) =>
        storedValues.Any(stored => VerifyOne(Utf8.String(stored), Utf8.Bytes(password)));

    /// <summary>
    /// The userPassword value for a password that is known to be clear text (Password Modify, unicodePwd).
    /// Normally the text itself, so tests can read it back. A password that happens to look like one of the
    /// hash schemes would be misread on the next bind, so that one is stored as a salted hash.
    /// </summary>
    public static string Store(string password)
    {
        if (ParseScheme(password) is null) return password;
        var salt = RandomNumberGenerator.GetBytes(8);
        var digest = SHA256.HashData([.. Utf8.Bytes(password), .. salt]);
        return "{SSHA256}" + Convert.ToBase64String([.. digest, .. salt]);
    }

    private static bool VerifyOne(string stored, byte[] password)
    {
        if (ParseScheme(stored) is not var (hash, salted, encoded))
            return CryptographicOperations.FixedTimeEquals(Utf8.Bytes(stored), password);
        if (hash is null) return false; // a real hash scheme this library cannot check: nothing binds with it

        byte[] data;
        try
        {
            data = Convert.FromBase64String(encoded);
        }
        catch (FormatException)
        {
            return false;
        }
        var digestLength = hash([]).Length;
        if (data.Length < digestLength) return false;
        var salt = salted ? data[digestLength..] : [];
        return CryptographicOperations.FixedTimeEquals(hash([.. password, .. salt]), data.AsSpan(0, digestLength));
    }

    private static readonly string[] HashFamilies = ["SHA", "MD4", "MD5", "CRYPT", "PBKDF", "ARGON", "PKCS"];

    /// <summary>Null for clear text. A null hash function marks a hash scheme that is not implemented.</summary>
    private static (Func<byte[], byte[]>? Hash, bool Salted, string Encoded)? ParseScheme(string value)
    {
        var close = value.IndexOf('}');
        if (!value.StartsWith('{') || close < 0) return null;
        var encoded = value[(close + 1)..];
        var scheme = value[1..close].ToUpperInvariant();
        return scheme switch
        {
            "MD5" => (MD5.HashData, false, encoded),
            "SMD5" => (MD5.HashData, true, encoded),
            "SHA" => (SHA1.HashData, false, encoded),
            "SSHA" => (SHA1.HashData, true, encoded),
            "SHA256" => (SHA256.HashData, false, encoded),
            "SSHA256" => (SHA256.HashData, true, encoded),
            "SHA384" => (SHA384.HashData, false, encoded),
            "SSHA384" => (SHA384.HashData, true, encoded),
            "SHA512" => (SHA512.HashData, false, encoded),
            "SSHA512" => (SHA512.HashData, true, encoded),
            "SASL" or "K5KEY" or "LANMAN" or "UNIX" => (null, false, encoded),
            // {SSHA-256}, {PBKDF2-SHA512}, {ARGON2}, {PKCS5S2}...: the name says it is a hash, just not one of ours
            _ when HashFamilies.Any(scheme.Contains) => (null, false, encoded),
            _ => null,
        };
    }
}
