using System.Linq;
using DetectSecretsSharp.Core;
using DetectSecretsSharp.Plugins;
using Xunit;

namespace DetectSecretsSharp.Tests.Plugins
{
    public class HighEntropyStringsDetectorTests
    {
        [Fact]
        public void Base64_SecretType_IsSet()
        {
            var detector = new Base64HighEntropyStringDetector();
            Assert.Equal("Base64 High Entropy String", detector.SecretType);
        }

        [Fact]
        public void Base64_AnalyzeString_FindsQuotedString()
        {
            var detector = new Base64HighEntropyStringDetector(limit: 1.0);
            var results = detector.AnalyzeString("\"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\"").ToList();
            Assert.Single(results);
        }

        [Fact]
        public void Base64_AnalyzeString_IgnoresUnquoted()
        {
            var detector = new Base64HighEntropyStringDetector(limit: 1.0);
            var results = detector.AnalyzeString("abc123").ToList();
            Assert.Empty(results);
        }

        [Fact]
        public void Base64_AnalyzeLine_FiltersByEntropy()
        {
            // Use high limit to ensure detection
            var detector = new Base64HighEntropyStringDetector(limit: 1.0);
            var results = detector.AnalyzeLine("config.txt", "\"ABCDEFGHIJKLMNOPQRSTUVWXYZ\"", 1);
            Assert.Single(results);
        }

        [Fact]
        public void Base64_AnalyzeLine_LowEntropy_FilteredOut()
        {
            // Use high limit to filter out low-entropy strings
            var detector = new Base64HighEntropyStringDetector(limit: 5.0);
            // Low entropy: repeated chars
            var results = detector.AnalyzeLine("config.txt", "\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"", 1);
            Assert.Empty(results);
        }

        [Fact]
        public void Hex_SecretType_IsSet()
        {
            var detector = new HexHighEntropyStringDetector();
            Assert.Equal("Hex High Entropy String", detector.SecretType);
        }

        [Fact]
        public void Hex_AnalyzeString_FindsQuotedString()
        {
            var detector = new HexHighEntropyStringDetector(limit: 1.0);
            var results = detector.AnalyzeString("\"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6\"").ToList();
            Assert.Single(results);
        }

        [Fact]
        public void Hex_AnalyzeLine_FiltersByEntropy()
        {
            var detector = new HexHighEntropyStringDetector(limit: 1.0);
            var results = detector.AnalyzeLine("config.txt", "\"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6\"", 1);
            Assert.Single(results);
        }

        [Fact]
        public void Hex_AnalyzeLine_AllDigits_ReducedEntropy()
        {
            var detector = new HexHighEntropyStringDetector(limit: 3.0);
            // All digits should have reduced entropy
            var results = detector.AnalyzeLine("config.txt", "\"0123456789\"", 1);
            // Might be filtered out due to reduced entropy
            Assert.Empty(results);
        }

        [Fact]
        public void ShannonEntropy_CalculatesCorrectly()
        {
            var detector = new Base64HighEntropyStringDetector(limit: 3.0);
            // "aaaa" has low entropy
            double entropy = detector.CalculateShannonEntropy("aaaa");
            Assert.True(entropy < 1.0);

            // Random-looking string has higher entropy
            double highEntropy = detector.CalculateShannonEntropy("a1B2c3D4e5F6g7H8i9J0k1L2");
            Assert.True(highEntropy > 3.0);
        }

        [Fact]
        public void Constructor_InvalidLimit_Throws()
        {
            Assert.Throws<System.ArgumentException>(() => new Base64HighEntropyStringDetector(limit: 9.0));
            Assert.Throws<System.ArgumentException>(() => new Base64HighEntropyStringDetector(limit: -1.0));
        }

        [Fact]
        public void FormatScanResult_ShowsEntropy()
        {
            var detector = new Base64HighEntropyStringDetector(limit: 3.0);
            var secret = new PotentialSecret("Base64 High Entropy String", "f.txt", "abcdefghijklmnop");
            string result = detector.FormatScanResult(secret);
            Assert.Contains("True", result);
            Assert.Contains("(", result);
        }

        [Fact]
        public void UseNonQuotedRegex_AllowsUnquotedScan()
        {
            var detector = new Base64HighEntropyStringDetector(limit: 1.0);
            // Without disabler, unquoted string won't match
            var before = detector.AnalyzeString("abc123").ToList();
            Assert.Empty(before);

            // With disabler, it matches
            using (detector.UseNonQuotedRegex(isExactMatch: false))
            {
                var after = detector.AnalyzeString("abc123").ToList();
                Assert.Single(after);
            }

            // After disposal, reverts to original behavior
            var restored = detector.AnalyzeString("abc123").ToList();
            Assert.Empty(restored);
        }
    }
}
