using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using DetectSecretsSharp.Plugins;
using DetectSecretsSharp.Util;

namespace DetectSecretsSharp.Core
{
    /// <summary>
    /// Scans files and diffs for potential secrets using registered detectors.
    /// </summary>
    public class Scanner
    {
        private readonly IReadOnlyList<DetectorBase> _detectors;

        public Scanner(IEnumerable<DetectorBase> detectors)
        {
            _detectors = detectors?.ToList() ?? throw new ArgumentNullException(nameof(detectors));
            if (_detectors.Count == 0)
                throw new ArgumentException("At least one detector is required.", nameof(detectors));
        }

        public IReadOnlyList<DetectorBase> Detectors => _detectors;

        /// <summary>
        /// Returns the list of files to scan from the given paths.
        /// If a path is a directory, it walks recursively. If a file, scans just that file.
        /// </summary>
        public static IEnumerable<string> GetFilesToScan(
            IEnumerable<string> paths,
            bool shouldScanAllFiles = false,
            string root = "")
        {
            foreach (var path in paths)
            {
                if (File.Exists(path))
                {
                    yield return path;
                }
                else if (Directory.Exists(path))
                {
                    foreach (var file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
                    {
                        yield return file;
                    }
                }
            }
        }

        /// <summary>
        /// Scans a single file and returns found secrets.
        /// </summary>
        public SecretsCollection ScanFile(string filename)
        {
            var results = new SecretsCollection();
            ScanFileInto(filename, results);
            return results;
        }

        /// <summary>
        /// Scans a single file and adds results to an existing collection.
        /// </summary>
        public void ScanFileInto(string filename, SecretsCollection results)
        {
            try
            {
                if (!File.Exists(filename))
                    return;

                var lines = File.ReadAllLines(filename);
                bool hasSecret = false;

                foreach (var lineInfo in ProcessLines(lines, filename))
                {
                    results[filename].Add(lineInfo.Secret);
                    hasSecret = true;
                }

                if (hasSecret)
                    return; // Eager scanning: stop after first secret found
            }
            catch (IOException)
            {
                // Skip files we can't read
            }
        }

        /// <summary>
        /// Scans multiple files (optionally in parallel).
        /// </summary>
        public SecretsCollection ScanFiles(IEnumerable<string> filenames)
        {
            var results = new SecretsCollection();
            foreach (var filename in filenames)
            {
                ScanFileInto(filename, results);
            }
            return results;
        }

        /// <summary>
        /// Async version of scanning multiple files.
        /// </summary>
        public async Task<SecretsCollection> ScanFilesAsync(IEnumerable<string> filenames)
        {
            var results = new SecretsCollection();
            var tasks = filenames.Select(filename => Task.Run(() =>
            {
                var fileResults = new SecretsCollection();
                ScanFileInto(filename, fileResults);
                lock (results)
                {
                    foreach (var file in fileResults.Files)
                    {
                        foreach (var secret in fileResults[file])
                        {
                            results[file].Add(secret);
                        }
                    }
                }
            }));

            await Task.WhenAll(tasks).ConfigureAwait(false);
            return results;
        }

        /// <summary>
        /// Scans a diff string (unified diff format) for added secrets.
        /// </summary>
        public SecretsCollection ScanDiff(string diff)
        {
            var results = new SecretsCollection();

            if (string.IsNullOrEmpty(diff))
                return results;

            // Simple diff parser for unified format
            var diffLines = diff.Split('\n');
            string currentFile = null;
            var addedLines = new List<(int lineNumber, string content)>();

            foreach (var line in diffLines)
            {
                if (line.StartsWith("+++ "))
                {
                    currentFile = line.Substring(4).Trim();
                    addedLines.Clear();
                }
                else if (line.StartsWith("@@"))
                {
                    // Parse hunk header: @@ -old +new @@
                    var match = System.Text.RegularExpressions.Regex.Match(line, @"@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@");
                    if (match.Success)
                    {
                        addedLines.Clear();
                    }
                }
                else if (line.StartsWith("+") && !line.StartsWith("+++"))
                {
                    var content = line.Substring(1);
                    // Find line number (approximate)
                    int lineNumber = addedLines.Count + 1;
                    addedLines.Add((lineNumber, content));
                }
            }

            // Process all collected added lines
            if (currentFile != null && addedLines.Count > 0)
            {
                var lineContents = addedLines.Select(l => l.content).ToArray();
                var lineNumbers = addedLines.Select(l => l.lineNumber).ToList();

                for (int i = 0; i < lineContents.Length; i++)
                {
                    var context = CodeSnippet.FromLines(lineContents, lineNumbers[i]);
                    foreach (var detector in _detectors)
                    {
                        var secrets = detector.AnalyzeLine(
                            currentFile,
                            lineContents[i],
                            lineNumbers[i],
                            context);

                        foreach (var secret in secrets)
                        {
                            results[currentFile].Add(secret);
                        }
                    }
                }
            }

            return results;
        }

        /// <summary>
        /// Scans a single line (for adhoc string scanning).
        /// </summary>
        public SecretsCollection ScanLine(string line, string filename = "adhoc-string-scan")
        {
            var results = new SecretsCollection();
            var context = CodeSnippet.FromSingleLine(line, 1);

            foreach (var detector in _detectors)
            {
                var secrets = detector.AnalyzeLine(filename, line, 0, context);
                foreach (var secret in secrets)
                {
                    results[filename].Add(secret);
                }
            }

            return results;
        }

        /// <summary>
        /// Async version of scanning a single line.
        /// </summary>
        public async Task<SecretsCollection> ScanLineAsync(string line, string filename = "adhoc-string-scan")
        {
            var results = new SecretsCollection();
            var context = CodeSnippet.FromSingleLine(line, 1);

            foreach (var detector in _detectors)
            {
                var secrets = await detector.AnalyzeLineAsync(filename, line, 0, context).ConfigureAwait(false);
                foreach (var secret in secrets)
                {
                    results[filename].Add(secret);
                }
            }

            return results;
        }

        /// <summary>
        /// Creates a Scanner with all default detectors registered.
        /// </summary>
        public static Scanner CreateDefault()
        {
            var detectors = new DetectorBase[]
            {
                new AwsKeyDetector(),
                new AzureStorageKeyDetector(),
                new ArtifactoryDetector(),
                new BasicAuthDetector(),
                new CloudantDetector(),
                new DiscordBotTokenDetector(),
                new GitHubTokenDetector(),
                new GitLabTokenDetector(),
                new IbmCloudIamDetector(),
                new IbmCosHmacDetector(),
                new IpPublicDetector(),
                new JwtTokenDetector(),
                new KeywordDetector(),
                new MailchimpDetector(),
                new NpmDetector(),
                new OpenAiDetector(),
                new PrivateKeyDetector(),
                new PypiTokenDetector(),
                new SendGridDetector(),
                new SlackDetector(),
                new SoftlayerDetector(),
                new SquareOAuthDetector(),
                new StripeDetector(),
                new TelegramBotTokenDetector(),
                new TwilioKeyDetector(),
                new Base64HighEntropyStringDetector(),
                new HexHighEntropyStringDetector(),
            };

            return new Scanner(detectors);
        }

        // ---- Internal line processing ----

        private IEnumerable<LineResult> ProcessLines(string[] allLines, string filename)
        {
            for (int i = 0; i < allLines.Length; i++)
            {
                string line = allLines[i].TrimEnd();
                int lineNumber = i + 1;
                var context = CodeSnippet.FromLines(allLines, lineNumber);

                foreach (var detector in _detectors)
                {
                    var secrets = detector.AnalyzeLine(
                        filename, line, lineNumber, context);

                    foreach (var secret in secrets)
                    {
                        yield return new LineResult(secret, detector);
                    }
                }
            }
        }

        /// <summary>
        /// Holds a secret along with the detector that found it.
        /// </summary>
        public class LineResult
        {
            public PotentialSecret Secret { get; }
            public DetectorBase Detector { get; }

            public LineResult(PotentialSecret secret, DetectorBase detector)
            {
                Secret = secret;
                Detector = detector;
            }
        }
    }
}
