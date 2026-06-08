using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using DetectSecretsSharp.Plugins;
using DetectSecretsSharp.Util;

namespace DetectSecretsSharp.Core
{
    /// <summary>
    /// Represents a collection of potential secrets found during scanning,
    /// organized by filename.
    /// </summary>
    public class SecretsCollection : IEnumerable<KeyValuePair<string, PotentialSecret>>
    {
        private readonly Dictionary<string, HashSet<PotentialSecret>> _data;

        /// <summary>
        /// The root directory for relative paths.
        /// </summary>
        public string Root { get; set; }

        /// <summary>
        /// Set of filenames that have secrets.
        /// </summary>
        public HashSet<string> Files => new HashSet<string>(_data.Keys);

        public SecretsCollection(string root = "")
        {
            _data = new Dictionary<string, HashSet<PotentialSecret>>();
            Root = root ?? "";
        }

        // ---- Scan helpers ----

        /// <summary>
        /// Scans a single line of text for secrets using the given detectors.
        /// </summary>
        public static SecretsCollection ScanLine(
            string line,
            string filename = "adhoc-string-scan",
            params DetectorBase[] detectors)
        {
            var scanner = new Scanner(detectors);
            return scanner.ScanLine(line, filename);
        }

        /// <summary>
        /// Async version of <see cref="ScanLine"/>.
        /// </summary>
        public static async Task<SecretsCollection> ScanLineAsync(
            string line,
            string filename = "adhoc-string-scan",
            params DetectorBase[] detectors)
        {
            var scanner = new Scanner(detectors);
            return await scanner.ScanLineAsync(line, filename).ConfigureAwait(false);
        }

        /// <summary>
        /// Scans a single line with the default set of detectors.
        /// </summary>
        public static SecretsCollection ScanLineDefault(string line, string filename = "adhoc-string-scan")
        {
            var scanner = Scanner.CreateDefault();
            return scanner.ScanLine(line, filename);
        }

        // ---- Baseline loading ----

        /// <summary>
        /// Creates a SecretsCollection from a baseline JSON dictionary.
        /// </summary>
        public static SecretsCollection LoadFromBaseline(Dictionary<string, object> baseline)
        {
            var output = new SecretsCollection();

            if (baseline.TryGetValue("results", out var resultsObj) && resultsObj is Dictionary<string, object> results)
            {
                foreach (var kvp in results)
                {
                    string filename = kvp.Key;

                    if (kvp.Value is List<object> items)
                    {
                        foreach (var item in items)
                        {
                            if (item is Dictionary<string, object> itemDict)
                            {
                                var fullDict = new Dictionary<string, object>(itemDict)
                                {
                                    ["filename"] = filename
                                };

                                var secret = PotentialSecret.LoadFromBaseline(
                                    type: GetString(fullDict, "type"),
                                    filename: filename,
                                    hashedSecret: GetString(fullDict, "hashed_secret"),
                                    lineNumber: GetInt(fullDict, "line_number"),
                                    isSecret: fullDict.TryGetValue("is_secret", out var isSec) ? (bool?)isSec : null,
                                    isVerified: GetBool(fullDict, "is_verified"));

                                output[filename].Add(secret);
                            }
                        }
                    }
                }
            }

            return output;
        }

        /// <summary>
        /// Converts the collection to a baseline-friendly dictionary.
        /// </summary>
        public Dictionary<string, object> ToBaselineDictionary()
        {
            var output = new Dictionary<string, List<object>>();

            foreach (var kvp in this)
            {
                if (!output.ContainsKey(kvp.Key))
                    output[kvp.Key] = new List<object>();

                output[kvp.Key].Add(kvp.Value.ToBaselineDictionary());
            }

            return new Dictionary<string, object>
            {
                ["results"] = output.ToDictionary(kvp => kvp.Key, kvp => (object)kvp.Value)
            };
        }

        // ---- Merge / Trim ----

        /// <summary>
        /// Merges old results into this collection, preserving verification status.
        /// </summary>
        public void Merge(SecretsCollection oldResults)
        {
            foreach (var filename in oldResults.Files)
            {
                if (!_data.ContainsKey(filename))
                    continue;

                var mapping = new Dictionary<PotentialSecret, PotentialSecret>();
                foreach (var secret in _data[filename])
                {
                    mapping[secret] = secret;
                }

                foreach (var oldSecret in oldResults[filename])
                {
                    if (!mapping.TryGetValue(oldSecret, out var currentSecret))
                        continue;

                    if (currentSecret.IsSecret == null)
                        currentSecret.IsSecret = oldSecret.IsSecret;

                    if (!currentSecret.IsVerified)
                        currentSecret.IsVerified = oldSecret.IsVerified;
                }
            }
        }

        /// <summary>
        /// Removes invalid entries. Behaves like set intersection and left-join.
        /// </summary>
        public void Trim(SecretsCollection scannedResults = null, List<string> filelist = null)
        {
        if (scannedResults == null)
        {
            scannedResults = new SecretsCollection();
            if (filelist == null)
            {
                filelist = Files
                    .Where(f => !File.Exists(Path.Combine(Root, f)))
                    .ToList();
            }
        }

            var fileset = filelist != null ? new HashSet<string>(filelist) : new HashSet<string>();
            var result = new Dictionary<string, HashSet<PotentialSecret>>();

            foreach (var filename in scannedResults.Files)
            {
                if (!_data.ContainsKey(filename))
                    continue;

                var existingSecretMap = new Dictionary<PotentialSecret, PotentialSecret>();
                foreach (var secret in _data[filename])
                {
                    existingSecretMap[secret] = secret;
                }

                foreach (var secret in scannedResults[filename])
                {
                    if (!existingSecretMap.TryGetValue(secret, out var existingSecret))
                        continue;

                    if (existingSecret.LineNumber > 0)
                        existingSecret.LineNumber = secret.LineNumber;

                    if (!result.ContainsKey(filename))
                        result[filename] = new HashSet<PotentialSecret>();

                    result[filename].Add(existingSecret);
                }
            }

            foreach (var filename in Files)
            {
                if (result.ContainsKey(filename))
                    continue;

                if (fileset.Contains(filename))
                    continue;

                result[filename] = _data[filename];
            }

            _data.Clear();
            foreach (var kvp in result)
            {
                _data[kvp.Key] = kvp.Value;
            }
        }

        // ---- Count / Bool ----

        /// <summary>
        /// Returns the total number of secrets.
        /// </summary>
        public int Count => _data.Values.Sum(s => s.Count);

        /// <summary>
        /// Checks if there are any secrets.
        /// </summary>
        public bool HasSecrets => Count > 0;

        // ---- Indexer ----

        public HashSet<PotentialSecret> this[string filename]
        {
            get
            {
                if (!_data.TryGetValue(filename, out var secrets))
                {
                    _data[filename] = new HashSet<PotentialSecret>();
                    return _data[filename];
                }
                return secrets;
            }
            set => _data[filename] = value ?? new HashSet<PotentialSecret>();
        }

        // ---- Equality ----

        public bool ExactlyEquals(SecretsCollection other)
        {
            return EqualsInternal(other, strict: true);
        }

        public override bool Equals(object obj)
        {
            if (obj is SecretsCollection other)
                return EqualsInternal(other, strict: false);
            return false;
        }

        private bool EqualsInternal(SecretsCollection other, bool strict)
        {
            if (!Files.SetEquals(other.Files))
                return false;

            foreach (var filename in Files)
            {
                var selfMapping = _data[filename]
                    .ToDictionary(s => (s.SecretHash, s.Type));

                var otherMapping = other._data[filename]
                    .ToDictionary(s => (s.SecretHash, s.Type));

                if (!new HashSet<PotentialSecret>(selfMapping.Values).SetEquals(otherMapping.Values))
                    return false;

                if (!strict)
                    continue;

                foreach (var kvp in selfMapping)
                {
                    if (!otherMapping.TryGetValue(kvp.Key, out var secretB))
                        return false;

                    var secretA = kvp.Value;

                    if (secretA.LineNumber == 0 || secretB.LineNumber == 0)
                    {
                        if (secretA.Type != secretB.Type ||
                            secretA.Filename != secretB.Filename ||
                            secretA.SecretHash != secretB.SecretHash ||
                            secretA.IsSecret != secretB.IsSecret ||
                            secretA.IsVerified != secretB.IsVerified)
                            return false;
                    }
                    else
                    {
                        if (!secretA.Equals(secretB) ||
                            secretA.LineNumber != secretB.LineNumber ||
                            secretA.IsSecret != secretB.IsSecret ||
                            secretA.IsVerified != secretB.IsVerified)
                            return false;
                    }
                }
            }

            return true;
        }

        public override int GetHashCode()
        {
            int hash = 17;
            foreach (var filename in Files.OrderBy(f => f))
            {
                hash = hash * 31 + filename.GetHashCode();
                foreach (var secret in _data[filename])
                {
                    hash = hash * 31 + secret.GetHashCode();
                }
            }
            return hash;
        }

        // ---- Subtraction ----

        public static SecretsCollection operator -(SecretsCollection left, SecretsCollection right)
        {
            var output = new SecretsCollection();

            foreach (var filename in right.Files)
            {
                if (!left._data.ContainsKey(filename))
                    continue;

                output[filename] = new HashSet<PotentialSecret>(
                    left[filename].Except(right[filename]));
            }

            foreach (var filename in left.Files)
            {
                if (right.Files.Contains(filename))
                    continue;

                output[filename] = new HashSet<PotentialSecret>(left[filename]);
            }

            return output;
        }

        // ---- IEnumerable ----

        public IEnumerator<KeyValuePair<string, PotentialSecret>> GetEnumerator()
        {
            foreach (var filename in Files.OrderBy(f => f))
            {
                var secrets = _data[filename];
                foreach (var secret in secrets.OrderBy(s => s.LineNumber)
                    .ThenBy(s => s.SecretHash)
                    .ThenBy(s => s.Type))
                {
                    yield return new KeyValuePair<string, PotentialSecret>(filename, secret);
                }
            }
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

        // ---- Helpers ----

        private static string GetString(Dictionary<string, object> dict, string key)
        {
            return dict.TryGetValue(key, out var val) ? val?.ToString() ?? "" : "";
        }

        private static int GetInt(Dictionary<string, object> dict, string key)
        {
            if (dict.TryGetValue(key, out var val))
            {
                if (val is int i) return i;
                if (val is long l) return (int)l;
                if (val is double d) return (int)d;
            }
            return 0;
        }

        private static bool GetBool(Dictionary<string, object> dict, string key)
        {
            if (dict.TryGetValue(key, out var val))
            {
                if (val is bool b) return b;
            }
            return false;
        }
    }
}
