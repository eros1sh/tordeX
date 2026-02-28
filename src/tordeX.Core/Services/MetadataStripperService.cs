using System.Buffers.Binary;

namespace TordeX.Core.Services;

/// <summary>
/// Strips EXIF and other metadata from images before sending.
/// Supports JPEG (removes EXIF/APP1/APP2/COM markers) and PNG (removes tEXt/iTXt/zTXt/eXIf chunks).
/// This prevents leaking GPS coordinates, camera model, timestamps, and other PII.
/// </summary>
public static class MetadataStripperService
{
    /// <summary>
    /// Strips all metadata from image bytes based on MIME type.
    /// Returns cleaned image data. If format is unsupported, returns original data unchanged.
    /// </summary>
    public static byte[] StripMetadata(byte[] imageData, string mimeType)
    {
        ArgumentNullException.ThrowIfNull(imageData);
        if (imageData.Length < 8) return imageData;

        return mimeType.ToLowerInvariant() switch
        {
            "image/jpeg" or "image/jpg" => StripJpegMetadata(imageData),
            "image/png" => StripPngMetadata(imageData),
            _ => imageData // Unsupported format — return as-is
        };
    }

    /// <summary>
    /// Checks if image data likely contains metadata.
    /// </summary>
    public static bool HasMetadata(byte[] imageData, string mimeType)
    {
        if (imageData.Length < 8) return false;

        return mimeType.ToLowerInvariant() switch
        {
            "image/jpeg" or "image/jpg" => JpegHasMetadata(imageData),
            "image/png" => PngHasMetadata(imageData),
            _ => false
        };
    }

    // ═══════════════ JPEG ═══════════════

    /// <summary>
    /// Strips EXIF/APP/COM markers from JPEG.
    /// Preserves SOI, APP0 (JFIF), DQT, DHT, SOF, SOS and image data.
    /// </summary>
    private static byte[] StripJpegMetadata(byte[] data)
    {
        if (data.Length < 2 || data[0] != 0xFF || data[1] != 0xD8)
            return data; // Not a valid JPEG

        using var output = new MemoryStream(data.Length);
        // Write SOI marker
        output.WriteByte(0xFF);
        output.WriteByte(0xD8);

        int pos = 2;
        while (pos < data.Length - 1)
        {
            if (data[pos] != 0xFF)
            {
                pos++;
                continue;
            }

            byte marker = data[pos + 1];

            // SOS (Start of Scan) — everything after this is image data, copy rest verbatim
            if (marker == 0xDA)
            {
                output.Write(data.AsSpan(pos));
                break;
            }

            // EOI (End of Image)
            if (marker == 0xD9)
            {
                output.WriteByte(0xFF);
                output.WriteByte(0xD9);
                break;
            }

            // Skip padding bytes (0xFF followed by 0xFF)
            if (marker == 0xFF)
            {
                pos++;
                continue;
            }

            // Markers without length (RST0-RST7, SOI, EOI, TEM)
            if ((marker >= 0xD0 && marker <= 0xD7) || marker == 0xD8 || marker == 0x01)
            {
                output.WriteByte(0xFF);
                output.WriteByte(marker);
                pos += 2;
                continue;
            }

            // Read segment length
            if (pos + 3 >= data.Length) break;
            int segLen = (data[pos + 2] << 8) | data[pos + 3];
            if (segLen < 2 || pos + 2 + segLen > data.Length) break;

            // Decide whether to keep or strip this marker
            bool keep = marker switch
            {
                0xE0 => true,  // APP0 (JFIF) — keep
                0xE1 => false, // APP1 (EXIF, XMP) — STRIP
                0xE2 => false, // APP2 (ICC profile, FlashPix) — STRIP
                0xE3 => false, // APP3-APP15 — STRIP
                0xE4 => false,
                0xE5 => false,
                0xE6 => false,
                0xE7 => false,
                0xE8 => false,
                0xE9 => false,
                0xEA => false,
                0xEB => false,
                0xEC => false,
                0xED => false, // APP13 (Photoshop/IPTC) — STRIP
                0xEE => false, // APP14 (Adobe) — STRIP
                0xEF => false,
                0xFE => false, // COM (Comment) — STRIP
                _ => true      // DQT, DHT, SOF, etc. — keep
            };

            if (keep)
            {
                output.Write(data.AsSpan(pos, 2 + segLen));
            }

            pos += 2 + segLen;
        }

        return output.ToArray();
    }

    private static bool JpegHasMetadata(byte[] data)
    {
        if (data.Length < 2 || data[0] != 0xFF || data[1] != 0xD8)
            return false;

        int pos = 2;
        while (pos < data.Length - 3)
        {
            if (data[pos] != 0xFF) { pos++; continue; }
            byte marker = data[pos + 1];

            // EXIF, XMP, IPTC, Comment markers
            if (marker is 0xE1 or 0xE2 or 0xED or 0xFE)
                return true;

            if (marker == 0xDA || marker == 0xD9) break;
            if ((marker >= 0xD0 && marker <= 0xD7) || marker == 0xFF)
            {
                pos += (marker == 0xFF) ? 1 : 2;
                continue;
            }

            int segLen = (data[pos + 2] << 8) | data[pos + 3];
            if (segLen < 2) break;
            pos += 2 + segLen;
        }
        return false;
    }

    // ═══════════════ PNG ═══════════════

    /// <summary>
    /// Strips metadata chunks from PNG.
    /// Removes: tEXt, iTXt, zTXt, eXIf, tIME, pHYs (non-essential chunks).
    /// Preserves: IHDR, PLTE, IDAT, IEND, tRNS, gAMA, cHRM, sRGB, iCCP, sBIT.
    /// </summary>
    private static byte[] StripPngMetadata(byte[] data)
    {
        // PNG signature: 137 80 78 71 13 10 26 10
        if (data.Length < 8 || data[0] != 0x89 || data[1] != 0x50 ||
            data[2] != 0x4E || data[3] != 0x47)
            return data; // Not a valid PNG

        using var output = new MemoryStream(data.Length);
        // Write PNG signature
        output.Write(data.AsSpan(0, 8));

        int pos = 8;
        while (pos + 12 <= data.Length) // Minimum chunk: 4(len) + 4(type) + 4(crc)
        {
            int chunkLen = BinaryPrimitives.ReadInt32BigEndian(data.AsSpan(pos));
            if (chunkLen < 0 || pos + 12 + chunkLen > data.Length) break;

            var chunkType = System.Text.Encoding.ASCII.GetString(data, pos + 4, 4);

            // Strip metadata chunks
            bool strip = chunkType is "tEXt" or "iTXt" or "zTXt" or "eXIf" or "tIME";

            if (!strip)
            {
                // Write entire chunk (length + type + data + CRC)
                int totalChunkSize = 12 + chunkLen;
                output.Write(data.AsSpan(pos, totalChunkSize));
            }

            pos += 12 + chunkLen;

            // Stop after IEND
            if (chunkType == "IEND") break;
        }

        return output.ToArray();
    }

    private static bool PngHasMetadata(byte[] data)
    {
        if (data.Length < 8 || data[0] != 0x89 || data[1] != 0x50)
            return false;

        int pos = 8;
        while (pos + 12 <= data.Length)
        {
            int chunkLen = BinaryPrimitives.ReadInt32BigEndian(data.AsSpan(pos));
            if (chunkLen < 0 || pos + 12 + chunkLen > data.Length) break;

            var chunkType = System.Text.Encoding.ASCII.GetString(data, pos + 4, 4);
            if (chunkType is "tEXt" or "iTXt" or "zTXt" or "eXIf" or "tIME")
                return true;

            pos += 12 + chunkLen;
            if (chunkType == "IEND") break;
        }
        return false;
    }
}
