using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace DetectSecretsSharp.Core
{
    /// <summary>
    /// Represents the result of a verification check on a potential secret.
    /// </summary>
    public enum VerifiedResult
    {
        /// <summary>Secret is confirmed to be a false positive.</summary>
        VerifiedFalse = -1,

        /// <summary>Secret has not been verified yet.</summary>
        Unverified = 0,

        /// <summary>Secret is confirmed to be a true positive.</summary>
        VerifiedTrue = 1
    }

    /// <summary>
    /// Represents a string found matching plugin rules that has the potential to be a secret.
    /// </summary>
    public class PotentialSecret : IEquatable<PotentialSecret>
    {
        private const string DefaultHashAlgorithm = "SHA1";

        /// <summary>Human-readable secret type defined by the plugin.</summary>
        public string Type { get; set; }

        /// <summary>Name of file where the secret was found.</summary>
        public string Filename { get; set; }

        /// <summary>Line number of the secret within the file.</summary>
        public int LineNumber { get; set; }

        /// <summary>SHA1 hash of the secret value.</summary>
        public string SecretHash { get; private set; }

        /// <summary>
        /// The actual secret value. Stored in memory but never serialized to baseline.
        /// </summary>
        [System.Text.Json.Serialization.JsonIgnore]
        public string SecretValue { get; private set; }

        /// <summary>
        /// Whether the secret is a true positive (true), false positive (false), or undetermined (null).
        /// </summary>
        public bool? IsSecret { get; set; }

        /// <summary>Whether the secret has been externally verified.</summary>
        public bool IsVerified { get; set; }

        /// <summary>
        /// Creates a new PotentialSecret.
        /// </summary>
        /// <param name="type">Human-readable secret type, e.g. "AWS Key"</param>
        /// <param name="filename">Path to the file containing the secret</param>
        /// <param name="secret">The actual secret value</param>
        /// <param name="lineNumber">Line number where the secret was found</param>
        /// <param name="isSecret">Whether this is a true/false positive</param>
        /// <param name="isVerified">Whether the secret has been externally verified</param>
        public PotentialSecret(
            string type,
            string filename,
            string secret,
            int lineNumber = 0,
            bool? isSecret = null,
            bool isVerified = false)
        {
            Type = type ?? throw new ArgumentNullException(nameof(type));
            Filename = filename ?? throw new ArgumentNullException(nameof(filename));
            LineNumber = lineNumber;
            IsSecret = isSecret;
            IsVerified = isVerified;

            SetSecret(secret);
        }

        /// <summary>
        /// Private parameterless constructor for deserialization.
        /// </summary>
        private PotentialSecret()
        {
            Type = string.Empty;
            Filename = string.Empty;
            SecretHash = string.Empty;
        }

        /// <summary>
        /// Sets the secret value and computes its hash.
        /// </summary>
        public void SetSecret(string secret)
        {
            if (secret == null)
                throw new ArgumentNullException(nameof(secret));

            SecretHash = HashSecret(secret);
            SecretValue = secret;
        }

        /// <summary>
        /// Computes the SHA1 hash of a secret string.
        /// </summary>
        public static string HashSecret(string secret)
        {
            byte[] bytes = SHA1.Create().ComputeHash(Encoding.UTF8.GetBytes(secret));
            return BytesToHexString(bytes);
        }

        private static string BytesToHexString(byte[] bytes)
        {
            char[] hex = new char[bytes.Length * 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                int val = bytes[i];
                hex[i * 2] = GetHexChar(val >> 4);
                hex[i * 2 + 1] = GetHexChar(val & 0x0F);
            }
            return new string(hex).ToLowerInvariant();
        }

        private static char GetHexChar(int value)
        {
            if (value < 10)
                return (char)('0' + value);
            return (char)('A' + value - 10);
        }

        /// <summary>
        /// Creates a PotentialSecret from a deserialized baseline entry.
        /// The secret value will be null (only hash is restored).
        /// </summary>
        public static PotentialSecret LoadFromBaseline(
            string type,
            string filename,
            string hashedSecret,
            int lineNumber = 0,
            bool? isSecret = null,
            bool isVerified = false)
        {
            return new PotentialSecret
            {
                Type = type,
                Filename = filename,
                SecretHash = hashedSecret,
                SecretValue = null,
                LineNumber = lineNumber,
                IsSecret = isSecret,
                IsVerified = isVerified
            };
        }

        /// <summary>
        /// Exports secret metadata to a dictionary suitable for baseline JSON serialization.
        /// </summary>
        public Dictionary<string, object> ToBaselineDictionary()
        {
            var dict = new Dictionary<string, object>
            {
                ["type"] = Type,
                ["filename"] = Filename,
                ["hashed_secret"] = SecretHash,
                ["is_verified"] = IsVerified
            };

            if (LineNumber > 0)
                dict["line_number"] = LineNumber;

            if (IsSecret.HasValue)
                dict["is_secret"] = IsSecret.Value;

            return dict;
        }

        /// <summary>
        /// Returns the fields used for equality comparison.
        /// </summary>
        protected virtual IEnumerable<string> GetFieldsToCompare()
        {
            yield return "Filename";
            yield return "SecretHash";
            yield return "Type";
        }

        // ---- Equality ----

        public bool Equals(PotentialSecret other)
        {
            if (other == null) return false;

            foreach (var field in GetFieldsToCompare())
            {
                var thisValue = GetType().GetProperty(field)?.GetValue(this);
                var otherValue = other.GetType().GetProperty(field)?.GetValue(other);

                if (!object.Equals(thisValue, otherValue))
                    return false;
            }

            return true;
        }

        public override bool Equals(object obj)
        {
            return Equals(obj as PotentialSecret);
        }

        public override int GetHashCode()
        {
            int hash = 17;
            foreach (var field in GetFieldsToCompare())
            {
                var value = GetType().GetProperty(field)?.GetValue(this);
                hash = hash * 31 + (value != null ? value.GetHashCode() : 0);
            }
            return hash;
        }

        public static bool operator ==(PotentialSecret left, PotentialSecret right)
        {
            if (object.ReferenceEquals(left, null))
                return object.ReferenceEquals(right, null);
            return left.Equals(right);
        }

        public static bool operator !=(PotentialSecret left, PotentialSecret right)
        {
            return !(left == right);
        }

        public override string ToString()
        {
            return string.Format(
                "Secret Type: {0}\nLocation:    {1}:{2}\n",
                Type,
                Filename,
                LineNumber);
        }
    }
}
