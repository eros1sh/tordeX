using System.Text;
using System.Text.RegularExpressions;
using System.Web;

namespace TordeX.Core.Services;

/// <summary>
/// Lightweight markdown-to-HTML renderer for chat messages.
/// Supports: **bold**, *italic*, `code`, ```code blocks```, ~~strikethrough~~,
/// [links](url), and auto-linked URLs. All output is HTML-escaped for XSS safety.
/// </summary>
public static partial class MarkdownService
{
    /// <summary>
    /// Renders markdown text to safe HTML.
    /// </summary>
    public static string Render(string text)
    {
        if (string.IsNullOrEmpty(text))
            return string.Empty;

        // HTML-encode first to prevent XSS
        var escaped = HttpUtility.HtmlEncode(text);

        // Code blocks (```...```) — must be processed before inline
        escaped = CodeBlockRegex().Replace(escaped, m =>
            $"<pre><code>{m.Groups[1].Value}</code></pre>");

        // Inline code (`...`)
        escaped = InlineCodeRegex().Replace(escaped, m =>
            $"<code>{m.Groups[1].Value}</code>");

        // Bold (**...**)
        escaped = BoldRegex().Replace(escaped, "<strong>$1</strong>");

        // Italic (*...*)
        escaped = ItalicRegex().Replace(escaped, "<em>$1</em>");

        // Strikethrough (~~...~~)
        escaped = StrikeRegex().Replace(escaped, "<del>$1</del>");

        // Markdown links [text](url)
        escaped = LinkRegex().Replace(escaped, m =>
        {
            var linkText = m.Groups[1].Value;
            var url = m.Groups[2].Value;
            // Only allow http/https URLs
            if (url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                return $"<a href=\"{url}\" target=\"_blank\" rel=\"noopener noreferrer\">{linkText}</a>";
            }
            return m.Value;
        });

        // Auto-link bare URLs (http/https only)
        escaped = UrlRegex().Replace(escaped, m =>
        {
            var url = m.Value;
            return $"<a href=\"{url}\" target=\"_blank\" rel=\"noopener noreferrer\">{url}</a>";
        });

        // Newlines to <br>
        escaped = escaped.Replace("\n", "<br/>");

        return escaped;
    }

    /// <summary>
    /// Checks if text contains any markdown formatting.
    /// </summary>
    public static bool HasMarkdown(string text)
    {
        if (string.IsNullOrEmpty(text)) return false;
        return BoldRegex().IsMatch(text) ||
               ItalicRegex().IsMatch(text) ||
               InlineCodeRegex().IsMatch(text) ||
               CodeBlockRegex().IsMatch(text) ||
               StrikeRegex().IsMatch(text) ||
               LinkRegex().IsMatch(text);
    }

    /// <summary>
    /// Extracts all URLs from text.
    /// </summary>
    public static List<string> ExtractUrls(string text)
    {
        if (string.IsNullOrEmpty(text)) return [];
        var matches = UrlRegex().Matches(text);
        return matches.Select(m => m.Value).Distinct().ToList();
    }

    // Regex patterns using source generators for performance
    [GeneratedRegex(@"```([\s\S]*?)```", RegexOptions.Compiled)]
    private static partial Regex CodeBlockRegex();

    [GeneratedRegex(@"`([^`]+)`", RegexOptions.Compiled)]
    private static partial Regex InlineCodeRegex();

    [GeneratedRegex(@"\*\*(.+?)\*\*", RegexOptions.Compiled)]
    private static partial Regex BoldRegex();

    [GeneratedRegex(@"(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)", RegexOptions.Compiled)]
    private static partial Regex ItalicRegex();

    [GeneratedRegex(@"~~(.+?)~~", RegexOptions.Compiled)]
    private static partial Regex StrikeRegex();

    [GeneratedRegex(@"\[([^\]]+)\]\((https?://[^\)]+)\)", RegexOptions.Compiled)]
    private static partial Regex LinkRegex();

    [GeneratedRegex(@"(?<!href="")https?://[^\s<>\""')\]]+", RegexOptions.Compiled)]
    private static partial Regex UrlRegex();
}
