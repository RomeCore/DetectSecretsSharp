using System.Collections.Generic;
using System.Linq;
using DetectSecretsSharp.Core;
using DetectSecretsSharp.Plugins;
using Xunit;

namespace DetectSecretsSharp.Tests.Core
{
    public class SecretsCollectionTests
    {
        private static PotentialSecret MakeSecret(string secret, string type = "Test", string filename = "f.txt", int line = 0, bool isVerified = false)
        {
            return new PotentialSecret(type, filename, secret, line, isVerified: isVerified);
        }

        [Fact]
        public void Constructor_Empty()
        {
            var coll = new SecretsCollection();
            Assert.Empty(coll.Files);
            Assert.False(coll.HasSecrets);
            Assert.Equal(0, coll.Count);
        }

        [Fact]
        public void Indexer_AddAndRetrieve()
        {
            var coll = new SecretsCollection();
            coll["file.txt"].Add(MakeSecret("secret123", filename: "file.txt"));

            Assert.Single(coll.Files);
            Assert.Single(coll["file.txt"]);
        }

        [Fact]
        public void Indexer_DefaultEmptySet()
        {
            var coll = new SecretsCollection();
            var secrets = coll["nonexistent.txt"];
            Assert.NotNull(secrets);
            Assert.Empty(secrets);
        }

        [Fact]
        public void Count_TotalSecrets()
        {
            var coll = new SecretsCollection();
            coll["a.txt"].Add(MakeSecret("s1", filename: "a.txt"));
            coll["a.txt"].Add(MakeSecret("s2", filename: "a.txt"));
            coll["b.txt"].Add(MakeSecret("s3", filename: "b.txt"));

            Assert.Equal(3, coll.Count);
        }

        [Fact]
        public void HasSecrets_True_WhenNotEmpty()
        {
            var coll = new SecretsCollection();
            coll["f.txt"].Add(MakeSecret("s"));
            Assert.True(coll.HasSecrets);
        }

        [Fact]
        public void Files_ReturnsUniqueFilenames()
        {
            var coll = new SecretsCollection();
            coll["a.txt"].Add(MakeSecret("s1", filename: "a.txt"));
            coll["a.txt"].Add(MakeSecret("s2", filename: "a.txt"));
            coll["b.txt"].Add(MakeSecret("s3", filename: "b.txt"));

            Assert.Equal(2, coll.Files.Count);
            Assert.Contains("a.txt", coll.Files);
            Assert.Contains("b.txt", coll.Files);
        }

        // ---- Merge ----

        [Fact]
        public void Merge_PreservesVerification()
        {
            var current = new SecretsCollection();
            current["f.txt"].Add(MakeSecret("secret", isVerified: false));

            var old = new SecretsCollection();
            old["f.txt"].Add(MakeSecret("secret", isVerified: true));

            current.Merge(old);

            Assert.True(current["f.txt"].First().IsVerified);
        }

        [Fact]
        public void Merge_DoesNotOverrideNewerValues()
        {
            var current = new SecretsCollection();
            current["f.txt"].Add(MakeSecret("secret", isVerified: true));

            var old = new SecretsCollection();
            old["f.txt"].Add(MakeSecret("secret", isVerified: false));

            current.Merge(old);

            Assert.True(current["f.txt"].First().IsVerified);
        }

        [Fact]
        public void Merge_NonExistentFile_DoesNothing()
        {
            var current = new SecretsCollection();
            current["a.txt"].Add(MakeSecret("s1", filename: "a.txt"));

            var old = new SecretsCollection();
            old["b.txt"].Add(MakeSecret("s2", filename: "b.txt"));

            current.Merge(old);
            Assert.Single(current.Files);
            Assert.Contains("a.txt", current.Files);
        }

        // ---- Trim ----

        [Fact]
        public void Trim_KeepsSecretsForRescannedFiles()
        {
            var coll = new SecretsCollection();
            coll["f.txt"].Add(MakeSecret("s", filename: "f.txt"));

            var scanned = new SecretsCollection();
            scanned["f.txt"].Add(MakeSecret("s", filename: "f.txt"));

            coll.Trim(scannedResults: scanned);
            Assert.Single(coll.Files);
        }

        [Fact]
        public void Trim_WithFilelist_RemovesScannedFilesWithoutSecrets()
        {
            var coll = new SecretsCollection();
            coll["old.txt"].Add(MakeSecret("s", filename: "old.txt"));

            var scanned = new SecretsCollection();
            coll.Trim(scannedResults: scanned, filelist: new List<string> { "old.txt" });
            Assert.Empty(coll.Files);
        }

        // ---- Subtraction ----

        [Fact]
        public void Subtraction_RemovesMatchingSecrets()
        {
            var left = new SecretsCollection();
            left["f.txt"].Add(MakeSecret("secret1", filename: "f.txt"));
            left["f.txt"].Add(MakeSecret("secret2", filename: "f.txt"));

            var right = new SecretsCollection();
            right["f.txt"].Add(MakeSecret("secret1", filename: "f.txt"));

            var result = left - right;

            Assert.Single(result["f.txt"]);
            Assert.Equal("secret2", result["f.txt"].First().SecretValue);
        }

        [Fact]
        public void Subtraction_LeftOnlyFiles_AreKept()
        {
            var left = new SecretsCollection();
            left["a.txt"].Add(MakeSecret("s1", filename: "a.txt"));

            var right = new SecretsCollection();
            right["b.txt"].Add(MakeSecret("s2", filename: "b.txt"));

            var result = left - right;
            Assert.Single(result.Files);
            Assert.Contains("a.txt", result.Files);
        }

        // ---- Equality ----

        [Fact]
        public void Equals_SameSecrets_ReturnsTrue()
        {
            var a = new SecretsCollection();
            a["f.txt"].Add(MakeSecret("s1", filename: "f.txt"));
            a["f.txt"].Add(MakeSecret("s2", filename: "f.txt"));

            var b = new SecretsCollection();
            b["f.txt"].Add(MakeSecret("s2", filename: "f.txt"));
            b["f.txt"].Add(MakeSecret("s1", filename: "f.txt"));

            Assert.Equal(a, b);
        }

        [Fact]
        public void Equals_DifferentFiles_ReturnsFalse()
        {
            var a = new SecretsCollection();
            a["a.txt"].Add(MakeSecret("s", filename: "a.txt"));

            var b = new SecretsCollection();
            b["b.txt"].Add(MakeSecret("s", filename: "b.txt"));

            Assert.NotEqual(a, b);
        }

        [Fact]
        public void ExactlyEquals_DifferentLineNumbers_ReturnsFalse()
        {
            var a = new SecretsCollection();
            a["f.txt"].Add(MakeSecret("s", filename: "f.txt", line: 1));

            var b = new SecretsCollection();
            b["f.txt"].Add(MakeSecret("s", filename: "f.txt", line: 2));

            Assert.False(a.ExactlyEquals(b));
        }

        // ---- Baseline ----

        [Fact]
        public void ToBaselineDictionary_ContainsResults()
        {
            var coll = new SecretsCollection();
            coll["f.txt"].Add(MakeSecret("mysecret", type: "TestType", filename: "f.txt", line: 5));

            var baseline = coll.ToBaselineDictionary();

            Assert.True(baseline.ContainsKey("results"));
        }

        [Fact]
        public void LoadFromBaseline_RestoresCollection()
        {
            var original = new SecretsCollection();
            original["f.txt"].Add(MakeSecret("mysecret", type: "TestType", filename: "f.txt", line: 5));

            var baseline = original.ToBaselineDictionary();
            var restored = SecretsCollection.LoadFromBaseline(baseline);

            Assert.Equal(original.Count, restored.Count);
            Assert.False(restored["f.txt"].First().IsVerified);
            Assert.Equal("TestType", restored["f.txt"].First().Type);
        }

        // ---- ScanLine ----

        [Fact]
        public void ScanLine_ReturnsSecrets()
        {
            var results = SecretsCollection.ScanLine(
                "GITHUB_TOKEN=ghp_abc123ABC456def789GHI012jkl345MNO678",
                ".env",
                new GitHubTokenDetector());

            Assert.NotEmpty(results);
            Assert.Contains(".env", results.Files);
        }

        [Fact]
        public void ScanLine_NoDetectors_Throws()
        {
            Assert.Throws<System.ArgumentException>(() =>
                SecretsCollection.ScanLine("some text", "f.txt"));
        }

        [Fact]
        public void ScanLineDefault_FindsSecrets()
        {
            var results = SecretsCollection.ScanLineDefault(
                "AKIA1234567890ABCDEF");
            Assert.NotEmpty(results);
        }

        // ---- IEnumerable ----

        [Fact]
        public void Enumeration_IteratesAllSecrets()
        {
            var coll = new SecretsCollection();
            coll["a.txt"].Add(MakeSecret("s1", filename: "a.txt"));
            coll["a.txt"].Add(MakeSecret("s2", filename: "a.txt"));
            coll["b.txt"].Add(MakeSecret("s3", filename: "b.txt"));

            var items = coll.ToList();
            Assert.Equal(3, items.Count);
        }

        [Fact]
        public void BoolOperator_True_WhenSecretsExist()
        {
            var coll = new SecretsCollection();
            coll["f.txt"].Add(MakeSecret("s"));
            Assert.True(coll.HasSecrets);
        }

        // ---- Indexer Edge Cases ----

        [Fact]
        public void Indexer_AfterTrim_StillWorks()
        {
            var coll = new SecretsCollection();
            coll["f.txt"].Add(MakeSecret("s", filename: "f.txt"));

            // Trim with empty scanned results and filelist containing the file
            coll.Trim(scannedResults: new SecretsCollection(), filelist: new List<string> { "f.txt" });
            Assert.Empty(coll.Files);
        }

        [Fact]
        public void SetIndexer_ReplacesValue()
        {
            var coll = new SecretsCollection();
            var secrets = new HashSet<PotentialSecret> { MakeSecret("new", filename: "f.txt") };
            coll["f.txt"] = secrets;

            Assert.Single(coll["f.txt"]);
            Assert.Equal("new", coll["f.txt"].First().SecretValue);
        }

        [Fact]
        public void SetIndexer_Null_Clears()
        {
            var coll = new SecretsCollection();
            coll["f.txt"] = null;

            Assert.Empty(coll["f.txt"]);
        }
    }
}
