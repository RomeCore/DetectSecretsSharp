using System.Collections.Generic;
using System.Linq;

namespace DetectSecretsSharp.Util
{
    /// <summary>
    /// Represents a snippet of code surrounding a potential secret,
    /// used for context-aware filtering and verification.
    /// </summary>
    public class CodeSnippet
    {
        /// <summary>
        /// The lines of code in the snippet.
        /// </summary>
        public IReadOnlyList<string> Lines { get; }

        /// <summary>
        /// The target line number within the snippet (1-based).
        /// </summary>
        public int TargetLineNumber { get; }

        /// <summary>
        /// Creates a new CodeSnippet.
        /// </summary>
        /// <param name="lines">Lines of code surrounding the secret.</param>
        /// <param name="targetLineNumber">The 1-based line number of the secret within the full file.</param>
        public CodeSnippet(IEnumerable<string> lines, int targetLineNumber)
        {
            Lines = lines?.ToList() ?? new List<string>();
            TargetLineNumber = targetLineNumber;
        }

        /// <summary>
        /// Gets the target line (the line containing the secret).
        /// </summary>
        public string GetTargetLine()
        {
            if (Lines.Count == 0)
                return string.Empty;

            return Lines[Lines.Count <= TargetLineNumber ? Lines.Count - 1 : TargetLineNumber - 1];
        }

        /// <summary>
        /// Creates a CodeSnippet from a single line.
        /// </summary>
        public static CodeSnippet FromSingleLine(string line, int lineNumber)
        {
            return new CodeSnippet(new[] { line }, lineNumber);
        }

        /// <summary>
        /// Creates a CodeSnippet from multiple lines, with the specified target line number.
        /// </summary>
        public static CodeSnippet FromLines(IEnumerable<string> lines, int targetLineNumber)
        {
            return new CodeSnippet(lines, targetLineNumber);
        }

        /// <summary>
        /// Returns a brief string representation of the snippet.
        /// </summary>
        public override string ToString()
        {
            if (Lines.Count == 0)
                return string.Empty;

            return string.Join("\n", Lines);
        }
    }
}
