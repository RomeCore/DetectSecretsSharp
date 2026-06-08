using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using DetectSecretsSharp.Core;
using DetectSecretsSharp.Plugins;
using Xunit;

namespace DetectSecretsSharp.Tests.Core
{
    public class ScannerTests
    {
        [Fact]
        public void Constructor_RequiresDetectors()
        {
            Assert.Throws<System.ArgumentException>(() => new Scanner(new List<DetectorBase>()));
        }

        [Fact]
        public void Constructor_ValidDetectors()
        {
            var scanner = new Scanner(new[] { new GitHubTokenDetector() });
            Assert.Single(scanner.Detectors);
        }

        [Fact]
        public void CreateDefault_HasAllDetectors()
        {
            var scanner = Scanner.CreateDefault();
            Assert.Equal(27, scanner.Detectors.Count);
        }

        // ---- ScanLine ----

        [Fact]
        public void ScanLine_FindsGitHubToken()
        {
            var scanner = new Scanner(new DetectorBase[] { new GitHubTokenDetector() });
            var results = scanner.ScanLine("ghp_abc123ABC456def789GHI012jkl345MNO678", filename: ".env");

            Assert.NotEmpty(results);
            Assert.Contains(".env", results.Files);
        }

        [Fact]
        public void ScanLine_NoMatch_ReturnsEmpty()
        {
            var scanner = new Scanner(new DetectorBase[] { new GitHubTokenDetector() });
            var results = scanner.ScanLine("hello world", filename: "f.txt");

            Assert.Empty(results.Files);
        }

        [Fact]
        public void ScanLine_MultipleDetectors()
        {
            var scanner = new Scanner(new DetectorBase[]
            {
                new GitHubTokenDetector(),
                new OpenAiDetector()
            });

            var results = scanner.ScanLine(
                "ghp_abc123ABC456def789GHI012jkl345MNO678 and " +
                "sk-abcdefghij1234567890T3BlbkFJabcdefghij1234567890");

            Assert.Equal(2, results.Count);
        }

        [Fact]
        public async Task ScanLineAsync_ReturnsResults()
        {
            var scanner = new Scanner(new DetectorBase[] { new GitHubTokenDetector() });
            var results = await scanner.ScanLineAsync(
                "ghp_abc123ABC456def789GHI012jkl345MNO678");

            Assert.NotEmpty(results);
        }

        // ---- ScanFile ----

        [Fact]
        public void ScanFile_NonExistent_ReturnsEmpty()
        {
            var scanner = new Scanner(new DetectorBase[] { new GitHubTokenDetector() });
            var results = scanner.ScanFile("nonexistent_file_xyz.txt");

            Assert.Empty(results.Files);
        }

        [Fact]
        public void ScanFile_FindsSecrets()
        {
            // Create temp file with a secret
            var tempFile = Path.GetTempFileName();
            try
            {
                File.WriteAllText(tempFile, "GITHUB_TOKEN=ghp_abc123ABC456def789GHI012jkl345MNO678\n");

                var scanner = new Scanner(new DetectorBase[] { new GitHubTokenDetector() });
                var results = scanner.ScanFile(tempFile);

                Assert.NotEmpty(results);
            }
            finally
            {
                File.Delete(tempFile);
            }
        }

        [Fact]
        public void ScanFile_NoSecrets_ReturnsEmpty()
        {
            var tempFile = Path.GetTempFileName();
            try
            {
                File.WriteAllText(tempFile, "hello world\nnothing secret here\n");

                var scanner = new Scanner(new DetectorBase[] { new GitHubTokenDetector() });
                var results = scanner.ScanFile(tempFile);

                Assert.Empty(results.Files);
            }
            finally
            {
                File.Delete(tempFile);
            }
        }

        // ---- ScanFiles ----

        [Fact]
        public void ScanFiles_MultipleFiles()
        {
            var tempFile1 = Path.GetTempFileName();
            var tempFile2 = Path.GetTempFileName();
            try
            {
                File.WriteAllText(tempFile1, "token=ghp_abc123ABC456def789GHI012jkl345MNO678");
                File.WriteAllText(tempFile2, "nothing here");

                var scanner = new Scanner(new DetectorBase[] { new GitHubTokenDetector() });
                var results = scanner.ScanFiles(new[] { tempFile1, tempFile2 });

                Assert.Equal(1, results.Count);
            }
            finally
            {
                File.Delete(tempFile1);
                File.Delete(tempFile2);
            }
        }

        // ---- ScanDiff ----

        [Fact]
        public void ScanDiff_AddedLine_ReturnsSecrets()
        {
            var diff = @"--- a/config.env
+++ b/config.env
@@ -0,0 +1 @@
+GITHUB_TOKEN=ghp_abc123ABC456def789GHI012jkl345MNO678";

            var scanner = new Scanner(new DetectorBase[] { new GitHubTokenDetector() });
            var results = scanner.ScanDiff(diff);

            Assert.NotEmpty(results);
        }

        [Fact]
        public void ScanDiff_NoAddedLines_ReturnsEmpty()
        {
            var diff = @"--- a/file.txt
+++ b/file.txt
@@ -1,1 +1,1 @@
-hello
+world";

            var scanner = new Scanner(new DetectorBase[] { new GitHubTokenDetector() });
            var results = scanner.ScanDiff(diff);

            Assert.Empty(results.Files);
        }

        // ---- GetFilesToScan ----

        [Fact]
        public void GetFilesToScan_WithFilePath()
        {
            var tempFile = Path.GetTempFileName();
            try
            {
                var files = Scanner.GetFilesToScan(new[] { tempFile }).ToList();
                Assert.Contains(tempFile, files);
            }
            finally
            {
                File.Delete(tempFile);
            }
        }

        [Fact]
        public void GetFilesToScan_WithDirectory()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "ScanTest_" + Path.GetRandomFileName());
            var tempFile = Path.Combine(tempDir, "test.txt");
            try
            {
                Directory.CreateDirectory(tempDir);
                File.WriteAllText(tempFile, "content");

                var files = Scanner.GetFilesToScan(new[] { tempDir }).ToList();
                Assert.Contains(tempFile, files);
            }
            finally
            {
                if (Directory.Exists(tempDir))
                    Directory.Delete(tempDir, true);
            }
        }

        // ---- Integration: Default ----

        [Fact]
        public void DefaultScanner_FindsMultipleSecretTypes()
        {
            var scanner = Scanner.CreateDefault();

            var results = scanner.ScanLine(
                "AWS_KEY=AKIA1234567890ABCDEF and " +
                "GITHUB_TOKEN=ghp_abc123ABC456def789GHI012jkl345MNO678 and " +
                "password = \"supersecret\"");

            // Should find AWS key, GitHub token, and keyword
            Assert.True(results.Count >= 2);
        }

        [Fact]
        public void ScanLine_SecretsHaveCorrectType()
        {
            var scanner = new Scanner(new DetectorBase[] { new GitHubTokenDetector() });
            var results = scanner.ScanLine("ghp_abc123ABC456def789GHI012jkl345MNO678");

            foreach (var kvp in results)
            {
                Assert.Equal("GitHub Token", kvp.Value.Type);
            }
        }
    }
}
