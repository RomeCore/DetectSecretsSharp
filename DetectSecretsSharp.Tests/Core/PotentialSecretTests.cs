using DetectSecretsSharp.Core;
using Xunit;

namespace DetectSecretsSharp.Tests.Core
{
    public class PotentialSecretTests
    {
        [Fact]
        public void Constructor_SetsProperties()
        {
            var secret = new PotentialSecret(
                type: "AWS Key",
                filename: "config.env",
                secret: "AKIA1234567890ABCDEF",
                lineNumber: 42,
                isSecret: true,
                isVerified: true);

            Assert.Equal("AWS Key", secret.Type);
            Assert.Equal("config.env", secret.Filename);
            Assert.Equal(42, secret.LineNumber);
            Assert.True(secret.IsSecret);
            Assert.True(secret.IsVerified);
            Assert.NotNull(secret.SecretValue);
            Assert.NotNull(secret.SecretHash);
        }

        [Fact]
        public void Constructor_DefaultValues()
        {
            var secret = new PotentialSecret(
                type: "Generic",
                filename: "file.txt",
                secret: "password123");

            Assert.Equal(0, secret.LineNumber);
            Assert.Null(secret.IsSecret);
            Assert.False(secret.IsVerified);
        }

        [Fact]
        public void HashSecret_ComputesSha1Hash()
        {
            string hash = PotentialSecret.HashSecret("hello");
            // SHA1 of "hello" = aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
            Assert.Equal("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", hash);
        }

        [Fact]
        public void HashSecret_EmptyString()
        {
            string hash = PotentialSecret.HashSecret("");
            // SHA1 of "" = da39a3ee5e6b4b0d3255bfef95601890afd80709
            Assert.Equal("da39a3ee5e6b4b0d3255bfef95601890afd80709", hash);
        }

        [Fact]
        public void HashSecret_IsConsistent()
        {
            string hash1 = PotentialSecret.HashSecret("my-secret-key-123");
            string hash2 = PotentialSecret.HashSecret("my-secret-key-123");
            Assert.Equal(hash1, hash2);
        }

        [Fact]
        public void SetSecret_UpdatesHashAndValue()
        {
            var secret = new PotentialSecret("Test", "file.txt", "old-secret");
            string oldHash = secret.SecretHash;

            secret.SetSecret("new-secret");

            Assert.NotEqual(oldHash, secret.SecretHash);
            Assert.Equal("new-secret", secret.SecretValue);
        }

        [Fact]
        public void LoadFromBaseline_RestoresWithoutSecretValue()
        {
            var secret = PotentialSecret.LoadFromBaseline(
                type: "AWS Key",
                filename: "config.env",
                hashedSecret: "abc123",
                lineNumber: 10,
                isSecret: false,
                isVerified: true);

            Assert.Equal("AWS Key", secret.Type);
            Assert.Equal("config.env", secret.Filename);
            Assert.Equal("abc123", secret.SecretHash);
            Assert.Equal(10, secret.LineNumber);
            Assert.False(secret.IsSecret);
            Assert.True(secret.IsVerified);
            Assert.Null(secret.SecretValue);
        }

        [Fact]
        public void ToBaselineDictionary_ContainsAllFields()
        {
            var secret = new PotentialSecret(
                type: "GitHub Token",
                filename: ".env",
                secret: "ghp_abc123",
                lineNumber: 5,
                isSecret: true);

            var dict = secret.ToBaselineDictionary();

            Assert.Equal("GitHub Token", dict["type"]);
            Assert.Equal(".env", dict["filename"]);
            Assert.Equal(secret.SecretHash, dict["hashed_secret"]);
            Assert.Equal(5, dict["line_number"]);
            Assert.True((bool)dict["is_secret"]);
            Assert.False((bool)dict["is_verified"]);
        }

        [Fact]
        public void ToBaselineDictionary_OmitsOptionalFieldsWhenDefault()
        {
            var secret = new PotentialSecret("Test", "file.txt", "secret");

            var dict = secret.ToBaselineDictionary();

            Assert.False(dict.ContainsKey("line_number"));
            Assert.False(dict.ContainsKey("is_secret"));
        }

        [Fact]
        public void Equals_SameFields_ReturnsTrue()
        {
            var secret1 = new PotentialSecret("AWS Key", "config.env", "AKIA1234567890ABCDEF");
            var secret2 = new PotentialSecret("AWS Key", "config.env", "AKIA1234567890ABCDEF");

            Assert.Equal(secret1, secret2);
        }

        [Fact]
        public void Equals_DifferentType_ReturnsFalse()
        {
            var secret1 = new PotentialSecret("AWS Key", "config.env", "AKIA1234567890ABCDEF");
            var secret2 = new PotentialSecret("GitHub Token", "config.env", "AKIA1234567890ABCDEF");

            Assert.NotEqual(secret1, secret2);
        }

        [Fact]
        public void Equals_DifferentFilename_ReturnsFalse()
        {
            var secret1 = new PotentialSecret("AWS Key", "config.env", "AKIA1234567890ABCDEF");
            var secret2 = new PotentialSecret("AWS Key", "other.env", "AKIA1234567890ABCDEF");

            Assert.NotEqual(secret1, secret2);
        }

        [Fact]
        public void Equals_DifferentSecret_ReturnsFalse()
        {
            var secret1 = new PotentialSecret("AWS Key", "config.env", "AKIA1234567890ABCDEF");
            var secret2 = new PotentialSecret("AWS Key", "config.env", "AKIA9999999999999999");

            Assert.NotEqual(secret1, secret2);
        }

        [Fact]
        public void Equals_IgnoreLineNumber()
        {
            var secret1 = new PotentialSecret("AWS Key", "config.env", "AKIA1234567890ABCDEF", lineNumber: 1);
            var secret2 = new PotentialSecret("AWS Key", "config.env", "AKIA1234567890ABCDEF", lineNumber: 999);

            Assert.Equal(secret1, secret2);
        }

        [Fact]
        public void GetHashCode_ConsistentWithEquals()
        {
            var secret1 = new PotentialSecret("AWS Key", "config.env", "AKIA1234567890ABCDEF");
            var secret2 = new PotentialSecret("AWS Key", "config.env", "AKIA1234567890ABCDEF");

            Assert.Equal(secret1.GetHashCode(), secret2.GetHashCode());
        }

        [Fact]
        public void OperatorEquals_Works()
        {
            var secret1 = new PotentialSecret("Test", "f.txt", "s");
            var secret2 = new PotentialSecret("Test", "f.txt", "s");

            Assert.True(secret1 == secret2);
            Assert.False(secret1 != secret2);
        }

        [Fact]
        public void OperatorEquals_NullHandling()
        {
            var secret = new PotentialSecret("Test", "f.txt", "s");

            Assert.False(secret == null);
            Assert.True(secret != null);
            Assert.True(null == null);
        }

        [Fact]
        public void ToString_FormatsCorrectly()
        {
            var secret = new PotentialSecret("OpenAI Key", "config.env", "sk-...", lineNumber: 7);

            string result = secret.ToString();

            Assert.Contains("OpenAI Key", result);
            Assert.Contains("config.env", result);
            Assert.Contains("7", result);
        }
    }
}
