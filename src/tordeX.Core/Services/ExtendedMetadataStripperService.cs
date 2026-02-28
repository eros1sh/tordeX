using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;

namespace TordeX.Core.Services;

/// <summary>
/// Strips metadata from PDF, DOCX, and MP4 files to prevent PII leakage.
/// Extends <see cref="MetadataStripperService"/> (which handles images) to cover
/// document and video formats commonly shared in chat.
/// All parsers are fault-tolerant — on failure, original data is returned unchanged.
/// </summary>
public static partial class ExtendedMetadataStripperService
{
    /// <summary>
    /// Strips metadata from a file based on its MIME type.
    /// Supported: application/pdf, DOCX (OpenXML), video/mp4.
    /// Unsupported types return the original data unchanged.
    /// </summary>
    /// <param name="data">Raw file bytes.</param>
    /// <param name="mimeType">MIME type of the file.</param>
    /// <returns>File bytes with metadata removed, or original data if format is unsupported or parsing fails.</returns>
    public static byte[] StripMetadata(byte[] data, string mimeType)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentException.ThrowIfNullOrWhiteSpace(mimeType);

        if (data.Length < 8) return data;

        return mimeType.ToLowerInvariant() switch
        {
            "application/pdf" => StripPdfMetadata(data),
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => StripDocxMetadata(data),
            "video/mp4" => StripMp4Metadata(data),
            _ => data
        };
    }

    /// <summary>
    /// Checks whether a file likely contains metadata based on its MIME type.
    /// </summary>
    /// <param name="data">Raw file bytes.</param>
    /// <param name="mimeType">MIME type of the file.</param>
    /// <returns>True if metadata was detected.</returns>
    public static bool HasMetadata(byte[] data, string mimeType)
    {
        ArgumentNullException.ThrowIfNull(data);
        if (data.Length < 8) return false;

        return mimeType.ToLowerInvariant() switch
        {
            "application/pdf" => PdfHasMetadata(data),
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => DocxHasMetadata(data),
            "video/mp4" => Mp4HasMetadata(data),
            _ => false
        };
    }

    /// <summary>
    /// Extracts metadata fields from a file for display purposes.
    /// </summary>
    /// <param name="data">Raw file bytes.</param>
    /// <param name="mimeType">MIME type of the file.</param>
    /// <returns>Dictionary of metadata field names to their string values.</returns>
    public static Dictionary<string, string> GetMetadataInfo(byte[] data, string mimeType)
    {
        ArgumentNullException.ThrowIfNull(data);

        if (data.Length < 8)
            return new Dictionary<string, string>();

        return mimeType.ToLowerInvariant() switch
        {
            "application/pdf" => GetPdfMetadataInfo(data),
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => GetDocxMetadataInfo(data),
            "video/mp4" => GetMp4MetadataInfo(data),
            _ => new Dictionary<string, string>()
        };
    }

    // ═══════════════ PDF ═══════════════

    /// <summary>
    /// PDF metadata fields that may contain PII (author, creator, dates, etc.).
    /// </summary>
    private static readonly string[] PdfMetadataKeys =
    [
        "/Author", "/Creator", "/Producer", "/CreationDate",
        "/ModDate", "/Keywords", "/Subject", "/Title"
    ];

    /// <summary>
    /// Strips metadata from a PDF by finding string values for known metadata keys
    /// in the /Info dictionary and replacing them with empty parentheses.
    /// </summary>
    private static byte[] StripPdfMetadata(byte[] data)
    {
        try
        {
            var text = Encoding.Latin1.GetString(data);

            foreach (var key in PdfMetadataKeys)
            {
                // Match patterns like: /Author (John Doe) or /Author <hex>
                text = PdfParenthesizedValueRegex(key).Replace(text, $"{key} ()");
                text = PdfHexValueRegex(key).Replace(text, $"{key} <>");
            }

            return Encoding.Latin1.GetBytes(text);
        }
        catch
        {
            return data;
        }
    }

    private static bool PdfHasMetadata(byte[] data)
    {
        try
        {
            var text = Encoding.Latin1.GetString(data);
            foreach (var key in PdfMetadataKeys)
            {
                // Check for non-empty values
                var parenMatch = PdfParenthesizedValueRegex(key).Match(text);
                if (parenMatch.Success && parenMatch.Groups[1].Length > 0)
                    return true;

                var hexMatch = PdfHexValueRegex(key).Match(text);
                if (hexMatch.Success && hexMatch.Groups[1].Length > 0)
                    return true;
            }
            return false;
        }
        catch
        {
            return false;
        }
    }

    private static Dictionary<string, string> GetPdfMetadataInfo(byte[] data)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var text = Encoding.Latin1.GetString(data);
            foreach (var key in PdfMetadataKeys)
            {
                var parenMatch = PdfParenthesizedValueRegex(key).Match(text);
                if (parenMatch.Success && parenMatch.Groups[1].Length > 0)
                {
                    result[key.TrimStart('/')] = parenMatch.Groups[1].Value;
                    continue;
                }

                var hexMatch = PdfHexValueRegex(key).Match(text);
                if (hexMatch.Success && hexMatch.Groups[1].Length > 0)
                {
                    result[key.TrimStart('/')] = $"<hex:{hexMatch.Groups[1].Value}>";
                }
            }
        }
        catch { /* return partial results */ }
        return result;
    }

    /// <summary>
    /// Generates a regex matching a PDF key followed by a parenthesized string value.
    /// Handles nested parentheses via balancing (up to 1 level).
    /// </summary>
    private static Regex PdfParenthesizedValueRegex(string key)
    {
        var escapedKey = Regex.Escape(key);
        return new Regex(
            $@"{escapedKey}\s*\(([^)]*(?:\([^)]*\))*[^)]*)\)",
            RegexOptions.Compiled | RegexOptions.NonBacktracking,
            TimeSpan.FromSeconds(2));
    }

    /// <summary>
    /// Generates a regex matching a PDF key followed by a hex string value.
    /// </summary>
    private static Regex PdfHexValueRegex(string key)
    {
        var escapedKey = Regex.Escape(key);
        return new Regex(
            $@"{escapedKey}\s*<([0-9A-Fa-f\s]*)>",
            RegexOptions.Compiled | RegexOptions.NonBacktracking,
            TimeSpan.FromSeconds(2));
    }

    // ═══════════════ DOCX ═══════════════

    /// <summary>
    /// DOCX entry paths containing document properties/metadata.
    /// </summary>
    private static readonly string[] DocxMetadataEntries =
    [
        "docProps/core.xml",
        "docProps/app.xml",
        "docProps/custom.xml"
    ];

    /// <summary>
    /// Strips metadata from a DOCX file by removing the docProps/core.xml and docProps/app.xml entries.
    /// DOCX is an OpenXML ZIP archive; we open it, remove metadata entries, and repackage.
    /// </summary>
    private static byte[] StripDocxMetadata(byte[] data)
    {
        try
        {
            using var inputStream = new MemoryStream(data, writable: false);
            using var outputStream = new MemoryStream(data.Length);

            // Copy the ZIP, skipping metadata entries
            using (var inputZip = new ZipArchive(inputStream, ZipArchiveMode.Read, leaveOpen: true))
            using (var outputZip = new ZipArchive(outputStream, ZipArchiveMode.Create, leaveOpen: true))
            {
                foreach (var entry in inputZip.Entries)
                {
                    // Skip metadata entries (case-insensitive comparison)
                    var shouldSkip = false;
                    foreach (var metaEntry in DocxMetadataEntries)
                    {
                        if (string.Equals(entry.FullName, metaEntry, StringComparison.OrdinalIgnoreCase))
                        {
                            shouldSkip = true;
                            break;
                        }
                    }

                    if (shouldSkip) continue;

                    // Update [Content_Types].xml to remove references to deleted parts
                    if (string.Equals(entry.FullName, "[Content_Types].xml", StringComparison.OrdinalIgnoreCase))
                    {
                        var newEntry = outputZip.CreateEntry(entry.FullName, CompressionLevel.Optimal);
                        using var reader = new StreamReader(entry.Open(), Encoding.UTF8);
                        var content = reader.ReadToEnd();

                        // Remove Override entries referencing docProps
                        content = DocxContentTypeOverrideRegex().Replace(content, "");

                        using var writer = new StreamWriter(newEntry.Open(), Encoding.UTF8);
                        writer.Write(content);
                        continue;
                    }

                    // Update .rels to remove relationships pointing to docProps
                    if (entry.FullName.EndsWith(".rels", StringComparison.OrdinalIgnoreCase))
                    {
                        var newEntry = outputZip.CreateEntry(entry.FullName, CompressionLevel.Optimal);
                        using var reader = new StreamReader(entry.Open(), Encoding.UTF8);
                        var content = reader.ReadToEnd();

                        // Remove Relationship elements targeting docProps/
                        content = DocxRelationshipRegex().Replace(content, "");

                        using var writer = new StreamWriter(newEntry.Open(), Encoding.UTF8);
                        writer.Write(content);
                        continue;
                    }

                    // Copy all other entries verbatim
                    var copied = outputZip.CreateEntry(entry.FullName, CompressionLevel.Optimal);
                    using var sourceStream = entry.Open();
                    using var destStream = copied.Open();
                    sourceStream.CopyTo(destStream);
                }
            }

            return outputStream.ToArray();
        }
        catch
        {
            return data;
        }
    }

    private static bool DocxHasMetadata(byte[] data)
    {
        try
        {
            using var stream = new MemoryStream(data, writable: false);
            using var zip = new ZipArchive(stream, ZipArchiveMode.Read);

            foreach (var entry in zip.Entries)
            {
                foreach (var metaEntry in DocxMetadataEntries)
                {
                    if (string.Equals(entry.FullName, metaEntry, StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }
            return false;
        }
        catch
        {
            return false;
        }
    }

    private static Dictionary<string, string> GetDocxMetadataInfo(byte[] data)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var stream = new MemoryStream(data, writable: false);
            using var zip = new ZipArchive(stream, ZipArchiveMode.Read);

            var coreEntry = zip.GetEntry("docProps/core.xml");
            if (coreEntry is not null)
            {
                using var reader = new StreamReader(coreEntry.Open(), Encoding.UTF8);
                var xml = reader.ReadToEnd();
                ExtractXmlElements(xml, result, "dc:creator", "Creator");
                ExtractXmlElements(xml, result, "dc:title", "Title");
                ExtractXmlElements(xml, result, "dc:subject", "Subject");
                ExtractXmlElements(xml, result, "dc:description", "Description");
                ExtractXmlElements(xml, result, "cp:lastModifiedBy", "LastModifiedBy");
                ExtractXmlElements(xml, result, "dcterms:created", "Created");
                ExtractXmlElements(xml, result, "dcterms:modified", "Modified");
                ExtractXmlElements(xml, result, "cp:keywords", "Keywords");
            }

            var appEntry = zip.GetEntry("docProps/app.xml");
            if (appEntry is not null)
            {
                using var reader = new StreamReader(appEntry.Open(), Encoding.UTF8);
                var xml = reader.ReadToEnd();
                ExtractXmlElements(xml, result, "Application", "Application");
                ExtractXmlElements(xml, result, "AppVersion", "AppVersion");
                ExtractXmlElements(xml, result, "Company", "Company");
                ExtractXmlElements(xml, result, "Manager", "Manager");
            }
        }
        catch { /* return partial results */ }
        return result;
    }

    /// <summary>
    /// Extracts the text content of a simple XML element by tag name using regex.
    /// </summary>
    private static void ExtractXmlElements(
        string xml, Dictionary<string, string> result, string elementName, string displayName)
    {
        var match = Regex.Match(xml, $@"<{Regex.Escape(elementName)}[^>]*>([^<]+)</{Regex.Escape(elementName)}>",
            RegexOptions.None, TimeSpan.FromSeconds(1));
        if (match.Success && !string.IsNullOrWhiteSpace(match.Groups[1].Value))
        {
            result[displayName] = match.Groups[1].Value.Trim();
        }
    }

    [GeneratedRegex(
        @"<Override\s+[^>]*PartName\s*=\s*""/docProps/[^""]*""[^>]*/?>",
        RegexOptions.IgnoreCase, matchTimeoutMilliseconds: 2000)]
    private static partial Regex DocxContentTypeOverrideRegex();

    [GeneratedRegex(
        @"<Relationship\s+[^>]*Target\s*=\s*""docProps/[^""]*""[^>]*/?>",
        RegexOptions.IgnoreCase, matchTimeoutMilliseconds: 2000)]
    private static partial Regex DocxRelationshipRegex();

    // ═══════════════ MP4 ═══════════════

    /// <summary>
    /// Strips metadata from an MP4 file by removing 'udta' (user data) atoms/boxes.
    /// MP4 is an ISO Base Media File Format (ISOBMFF) container with a tree of typed boxes.
    /// We parse the top-level and moov-level box structure and omit udta boxes.
    /// </summary>
    private static byte[] StripMp4Metadata(byte[] data)
    {
        try
        {
            using var output = new MemoryStream(data.Length);
            StripMp4Boxes(data.AsSpan(), output, isTopLevel: true);
            return output.ToArray();
        }
        catch
        {
            return data;
        }
    }

    /// <summary>
    /// Recursively processes MP4 boxes, stripping 'udta' and 'meta' boxes.
    /// For container boxes (moov, trak, mdia, minf, stbl), recurse into children.
    /// </summary>
    private static void StripMp4Boxes(ReadOnlySpan<byte> data, MemoryStream output, bool isTopLevel)
    {
        int pos = 0;

        while (pos + 8 <= data.Length)
        {
            // Read box size (4 bytes big-endian) and type (4 ASCII chars)
            var boxSize = (long)BinaryPrimitives.ReadUInt32BigEndian(data.Slice(pos, 4));
            var boxType = Encoding.ASCII.GetString(data.Slice(pos + 4, 4));

            long headerSize = 8;
            long actualSize = boxSize;

            if (boxSize == 1)
            {
                // Extended size (64-bit)
                if (pos + 16 > data.Length) break;
                actualSize = (long)BinaryPrimitives.ReadUInt64BigEndian(data.Slice(pos + 8, 8));
                headerSize = 16;
            }
            else if (boxSize == 0)
            {
                // Box extends to end of data
                actualSize = data.Length - pos;
            }

            if (actualSize < headerSize || pos + actualSize > data.Length)
                break;

            // Skip metadata boxes
            if (boxType is "udta" or "meta")
            {
                pos += (int)actualSize;
                continue;
            }

            // Container boxes that may contain udta: recurse
            if (boxType is "moov" or "trak" or "mdia" or "minf" or "stbl" or "edts" or "dinf")
            {
                // Write box header
                output.Write(data.Slice(pos, (int)headerSize));

                // Recurse into children
                var childrenStart = pos + (int)headerSize;
                var childrenLength = (int)(actualSize - headerSize);
                var childrenData = data.Slice(childrenStart, childrenLength);

                var childOutput = new MemoryStream(childrenLength);
                StripMp4Boxes(childrenData, childOutput, isTopLevel: false);
                var childBytes = childOutput.ToArray();

                // We need to fix up the box size in the header we wrote
                var currentPos = output.Position;
                var boxStart = currentPos - headerSize;
                var newBoxSize = headerSize + childBytes.Length;

                // Rewrite the size
                output.Position = boxStart;
                var sizeBytes = new byte[4];
                BinaryPrimitives.WriteUInt32BigEndian(sizeBytes, (uint)newBoxSize);
                output.Write(sizeBytes);
                output.Position = boxStart + headerSize;

                output.Write(childBytes);
            }
            else
            {
                // Leaf box: copy verbatim
                output.Write(data.Slice(pos, (int)actualSize));
            }

            pos += (int)actualSize;
        }
    }

    private static bool Mp4HasMetadata(byte[] data)
    {
        try
        {
            return FindMp4Box(data.AsSpan(), "udta") || FindMp4Box(data.AsSpan(), "meta");
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Recursively searches for a box type in an MP4 box tree.
    /// </summary>
    private static bool FindMp4Box(ReadOnlySpan<byte> data, string targetType)
    {
        int pos = 0;

        while (pos + 8 <= data.Length)
        {
            var boxSize = (long)BinaryPrimitives.ReadUInt32BigEndian(data.Slice(pos, 4));
            var boxType = Encoding.ASCII.GetString(data.Slice(pos + 4, 4));

            long headerSize = 8;
            long actualSize = boxSize;

            if (boxSize == 1)
            {
                if (pos + 16 > data.Length) break;
                actualSize = (long)BinaryPrimitives.ReadUInt64BigEndian(data.Slice(pos + 8, 8));
                headerSize = 16;
            }
            else if (boxSize == 0)
            {
                actualSize = data.Length - pos;
            }

            if (actualSize < headerSize || pos + actualSize > data.Length)
                break;

            if (boxType == targetType)
                return true;

            // Recurse into container boxes
            if (boxType is "moov" or "trak" or "mdia" or "minf" or "stbl" or "edts" or "dinf")
            {
                var childrenStart = pos + (int)headerSize;
                var childrenLength = (int)(actualSize - headerSize);
                if (FindMp4Box(data.Slice(childrenStart, childrenLength), targetType))
                    return true;
            }

            pos += (int)actualSize;
        }

        return false;
    }

    private static Dictionary<string, string> GetMp4MetadataInfo(byte[] data)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            CollectMp4BoxTypes(data.AsSpan(), result, "");
        }
        catch { /* return partial results */ }
        return result;
    }

    /// <summary>
    /// Collects box type information from an MP4 for metadata display.
    /// </summary>
    private static void CollectMp4BoxTypes(ReadOnlySpan<byte> data, Dictionary<string, string> result, string path)
    {
        int pos = 0;

        while (pos + 8 <= data.Length)
        {
            var boxSize = (long)BinaryPrimitives.ReadUInt32BigEndian(data.Slice(pos, 4));
            var boxType = Encoding.ASCII.GetString(data.Slice(pos + 4, 4));

            long headerSize = 8;
            long actualSize = boxSize;

            if (boxSize == 1)
            {
                if (pos + 16 > data.Length) break;
                actualSize = (long)BinaryPrimitives.ReadUInt64BigEndian(data.Slice(pos + 8, 8));
                headerSize = 16;
            }
            else if (boxSize == 0)
            {
                actualSize = data.Length - pos;
            }

            if (actualSize < headerSize || pos + actualSize > data.Length)
                break;

            var fullPath = string.IsNullOrEmpty(path) ? boxType : $"{path}/{boxType}";

            if (boxType is "udta" or "meta")
            {
                result[$"MetadataBox:{fullPath}"] = $"{actualSize} bytes";
            }

            // Recurse into container boxes
            if (boxType is "moov" or "trak" or "mdia" or "minf" or "stbl" or "udta" or "meta" or "edts" or "dinf")
            {
                var childrenStart = pos + (int)headerSize;
                var childrenLength = (int)(actualSize - headerSize);

                // For 'meta' box, skip version/flags (4 bytes) if present
                if (boxType == "meta" && childrenLength >= 4)
                {
                    CollectMp4BoxTypes(data.Slice(childrenStart + 4, childrenLength - 4), result, fullPath);
                }
                else
                {
                    CollectMp4BoxTypes(data.Slice(childrenStart, childrenLength), result, fullPath);
                }
            }

            pos += (int)actualSize;
        }
    }
}
