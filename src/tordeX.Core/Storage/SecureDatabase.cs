using Microsoft.Data.Sqlite;
using TordeX.Core.Cryptography;
using TordeX.Core.Services;

namespace TordeX.Core.Storage;

/// <summary>
/// Encrypted SQLite database for local storage.
/// Uses SQLCipher for transparent AES-256 encryption at rest.
/// </summary>
public sealed class SecureDatabase : IAsyncDisposable
{
    private SqliteConnection? _connection;
    private readonly string _dbPath;
    private readonly AppLogger? _logger;
    private bool _disposed;

    private static bool _providerInitialized;
    private static readonly object _initLock = new();

    public SecureDatabase(string dbPath, AppLogger? logger = null)
    {
        _dbPath = dbPath;
        _logger = logger;

        lock (_initLock)
        {
            if (!_providerInitialized)
            {
                SQLitePCL.Batteries_V2.Init();
                _providerInitialized = true;
            }
        }
    }

    public async Task InitializeAsync(byte[] masterKey, CancellationToken ct = default)
    {
        var passphrase = Convert.ToHexString(masterKey);

        var connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = _dbPath,
            Mode = SqliteOpenMode.ReadWriteCreate,
        }.ToString();

        _connection = new SqliteConnection(connectionString);
        await _connection.OpenAsync(ct);

        await using (var keyCmd = _connection.CreateCommand())
        {
            keyCmd.CommandText = $"PRAGMA key = '{passphrase}';";
            await keyCmd.ExecuteNonQueryAsync(ct);
        }

        try
        {
            await using var verifyCmd = _connection.CreateCommand();
            verifyCmd.CommandText = "SELECT count(*) FROM sqlite_master;";
            await verifyCmd.ExecuteScalarAsync(ct);
        }
        catch (SqliteException ex)
        {
            await _connection.CloseAsync();
            await _connection.DisposeAsync();
            _connection = null;
            throw new System.Security.Cryptography.CryptographicException(
                $"Failed to decrypt database. Wrong password? (SQLite: {ex.SqliteErrorCode})", ex);
        }

        await ExecuteNonQueryAsync("PRAGMA journal_mode=WAL;", ct);
        await ExecuteNonQueryAsync("PRAGMA foreign_keys=ON;", ct);

        await CreateSchemaAsync(ct);
        await MigrateSchemaAsync(ct);

        await ExecuteNonQueryAsync("PRAGMA wal_checkpoint(TRUNCATE);", ct);
    }

    private async Task CreateSchemaAsync(CancellationToken ct)
    {
        const string schema = """
            CREATE TABLE IF NOT EXISTS user_profile (
                id TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                public_key BLOB NOT NULL,
                encrypted_private_key BLOB NOT NULL,
                password_salt BLOB NOT NULL,
                password_hash BLOB NOT NULL,
                created_at TEXT NOT NULL,
                last_login_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS rooms (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                room_salt BLOB NOT NULL,
                created_at TEXT NOT NULL,
                last_activity_at TEXT NOT NULL,
                unread_count INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS room_peers (
                room_id TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                display_name TEXT NOT NULL,
                public_key BLOB NOT NULL,
                last_seen_at TEXT NOT NULL,
                PRIMARY KEY (room_id, fingerprint),
                FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                room_id TEXT NOT NULL,
                sender_fingerprint TEXT NOT NULL,
                sender_display_name TEXT NOT NULL,
                message_type INTEGER NOT NULL,
                encrypted_content BLOB NOT NULL,
                file_name TEXT,
                file_size INTEGER,
                mime_type TEXT,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_messages_room_time
                ON messages(room_id, timestamp);

            CREATE TABLE IF NOT EXISTS encrypted_files (
                id TEXT PRIMARY KEY,
                message_id TEXT NOT NULL,
                encrypted_data BLOB NOT NULL,
                FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS blocked_users (
                fingerprint TEXT PRIMARY KEY,
                display_name TEXT,
                blocked_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS pinned_messages (
                message_id TEXT NOT NULL,
                room_id TEXT NOT NULL,
                pinned_at TEXT NOT NULL,
                PRIMARY KEY (message_id, room_id),
                FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS reactions (
                message_id TEXT NOT NULL,
                emoji TEXT NOT NULL,
                sender_fingerprint TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (message_id, emoji, sender_fingerprint),
                FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS bookmarks (
                message_id TEXT PRIMARY KEY,
                room_id TEXT NOT NULL,
                room_name TEXT NOT NULL,
                sender_name TEXT NOT NULL,
                content_preview TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS key_rotations (
                id TEXT PRIMARY KEY,
                room_id TEXT NOT NULL,
                old_public_key BLOB NOT NULL,
                new_public_key BLOB NOT NULL,
                rotation_number INTEGER NOT NULL,
                rotated_at TEXT NOT NULL,
                initiator_fingerprint TEXT,
                FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS dead_drops (
                id TEXT PRIMARY KEY,
                drop_address TEXT NOT NULL,
                sender_fingerprint TEXT NOT NULL,
                recipient_fingerprint TEXT NOT NULL,
                encrypted_payload BLOB NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT,
                is_picked_up INTEGER NOT NULL DEFAULT 0,
                picked_up_at TEXT
            );
            """;

        await ExecuteNonQueryAsync(schema, ct);
    }

    /// <summary>
    /// Add columns that may not exist in older DBs (forward-compatible migration).
    /// </summary>
    private async Task MigrateSchemaAsync(CancellationToken ct)
    {
        var migrations = new[]
        {
            "ALTER TABLE messages ADD COLUMN reply_to_id TEXT",
            "ALTER TABLE messages ADD COLUMN reply_to_content TEXT",
            "ALTER TABLE messages ADD COLUMN reply_to_sender TEXT",
            "ALTER TABLE messages ADD COLUMN edited_at TEXT",
            "ALTER TABLE messages ADD COLUMN is_deleted INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE messages ADD COLUMN self_destruct_seconds INTEGER",
            "ALTER TABLE messages ADD COLUMN self_destruct_at TEXT",
            "ALTER TABLE messages ADD COLUMN is_pinned INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE messages ADD COLUMN is_delivered INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE messages ADD COLUMN is_read INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE messages ADD COLUMN voice_duration REAL",
            "ALTER TABLE rooms ADD COLUMN description TEXT",
            "ALTER TABLE rooms ADD COLUMN max_capacity INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE rooms ADD COLUMN invite_token TEXT",
            "ALTER TABLE rooms ADD COLUMN onion_address TEXT",
            "ALTER TABLE user_profile ADD COLUMN avatar_data BLOB",
            "ALTER TABLE user_profile ADD COLUMN language TEXT DEFAULT 'en'",
            "ALTER TABLE user_profile ADD COLUMN auto_lock_minutes INTEGER DEFAULT 0",
            "ALTER TABLE user_profile ADD COLUMN notification_sounds INTEGER DEFAULT 1",
            "ALTER TABLE user_profile ADD COLUMN screen_capture_protection INTEGER DEFAULT 0",
            "ALTER TABLE user_profile ADD COLUMN show_timestamps INTEGER DEFAULT 1",
            "ALTER TABLE messages ADD COLUMN is_view_once INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE messages ADD COLUMN viewed_at TEXT",
            // Security & Privacy settings migrations
            "ALTER TABLE user_profile ADD COLUMN double_ratchet INTEGER DEFAULT 1",
            "ALTER TABLE user_profile ADD COLUMN post_quantum INTEGER DEFAULT 0",
            "ALTER TABLE user_profile ADD COLUMN multi_layer_enc INTEGER DEFAULT 0",
            "ALTER TABLE user_profile ADD COLUMN deniable_enc INTEGER DEFAULT 0",
            "ALTER TABLE user_profile ADD COLUMN traffic_obfuscation INTEGER DEFAULT 1",
            "ALTER TABLE user_profile ADD COLUMN timing_protection INTEGER DEFAULT 1",
            "ALTER TABLE user_profile ADD COLUMN ram_only_mode INTEGER DEFAULT 0",
            "ALTER TABLE user_profile ADD COLUMN dns_leak_protection INTEGER DEFAULT 1",
            "ALTER TABLE user_profile ADD COLUMN dead_man_switch INTEGER DEFAULT 0",
            "ALTER TABLE user_profile ADD COLUMN dead_man_switch_days INTEGER DEFAULT 30",
            "ALTER TABLE user_profile ADD COLUMN tamper_detection INTEGER DEFAULT 1",
            "ALTER TABLE user_profile ADD COLUMN integrity_monitoring INTEGER DEFAULT 1",
            "ALTER TABLE user_profile ADD COLUMN canary_tokens INTEGER DEFAULT 1",
            "ALTER TABLE user_profile ADD COLUMN auto_metadata_strip INTEGER DEFAULT 1",
            "ALTER TABLE user_profile ADD COLUMN tor_bridge_line TEXT",
            "ALTER TABLE user_profile ADD COLUMN tor_pluggable_transport TEXT",
            "ALTER TABLE user_profile ADD COLUMN pinned_guard_nodes TEXT",
            "ALTER TABLE user_profile ADD COLUMN max_login_attempts INTEGER DEFAULT 5",
            "ALTER TABLE user_profile ADD COLUMN lockout_minutes INTEGER DEFAULT 15",
            // Canary tokens table
            @"CREATE TABLE IF NOT EXISTS canary_tokens (
                id TEXT PRIMARY KEY,
                token_hash TEXT NOT NULL,
                location TEXT NOT NULL,
                placed_at TEXT NOT NULL,
                last_verified TEXT
            )",
            // Security audit log table
            @"CREATE TABLE IF NOT EXISTS security_audit_log (
                id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                description TEXT NOT NULL,
                severity TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                details TEXT
            )",
            // Integrity manifest table
            @"CREATE TABLE IF NOT EXISTS integrity_manifest (
                file_path TEXT PRIMARY KEY,
                sha256_hash TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                last_modified TEXT NOT NULL,
                verified_at TEXT NOT NULL
            )",
        };

        foreach (var migration in migrations)
        {
            try
            {
                await ExecuteNonQueryAsync(migration, ct);
            }
            catch (SqliteException)
            {
                // Column already exists — skip
            }
        }
    }

    // ═══════════════ User Profile ═══════════════

    public async Task SaveUserProfileAsync(Models.UserProfile profile, CancellationToken ct = default)
    {
        EnsureOpen();
        const string sql = """
            INSERT OR REPLACE INTO user_profile
                (id, display_name, public_key, encrypted_private_key, password_salt, password_hash,
                 created_at, last_login_at, avatar_data, language, auto_lock_minutes,
                 notification_sounds, screen_capture_protection, show_timestamps,
                 double_ratchet, post_quantum, multi_layer_enc, deniable_enc,
                 traffic_obfuscation, timing_protection, ram_only_mode, dns_leak_protection,
                 dead_man_switch, dead_man_switch_days, tamper_detection, integrity_monitoring,
                 canary_tokens, auto_metadata_strip, tor_bridge_line, tor_pluggable_transport,
                 pinned_guard_nodes, max_login_attempts, lockout_minutes)
            VALUES
                (@id, @name, @pubkey, @privkey, @salt, @hash,
                 @created, @login, @avatar, @lang, @autolock,
                 @notifSounds, @screenCapture, @showTimestamps,
                 @doubleRatchet, @postQuantum, @multiLayerEnc, @deniableEnc,
                 @trafficObf, @timingProt, @ramOnly, @dnsLeak,
                 @deadMan, @deadManDays, @tamperDet, @integrityMon,
                 @canary, @autoMeta, @torBridge, @torTransport,
                 @guardNodes, @maxLogin, @lockout)
            """;

        await using var cmd = _connection!.CreateCommand();
        cmd.CommandText = sql;
        cmd.Parameters.AddWithValue("@id", profile.Id);
        cmd.Parameters.AddWithValue("@name", profile.DisplayName);
        cmd.Parameters.AddWithValue("@pubkey", profile.PublicKey);
        cmd.Parameters.AddWithValue("@privkey", profile.EncryptedPrivateKey);
        cmd.Parameters.AddWithValue("@salt", profile.PasswordSalt);
        cmd.Parameters.AddWithValue("@hash", profile.PasswordHash);
        cmd.Parameters.AddWithValue("@created", profile.CreatedAt.ToString("O"));
        cmd.Parameters.AddWithValue("@login", profile.LastLoginAt.ToString("O"));
        cmd.Parameters.AddWithValue("@avatar", (object?)profile.AvatarData ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@lang", profile.Language);
        cmd.Parameters.AddWithValue("@autolock", profile.AutoLockMinutes);
        cmd.Parameters.AddWithValue("@notifSounds", profile.NotificationSounds ? 1 : 0);
        cmd.Parameters.AddWithValue("@screenCapture", profile.ScreenCaptureProtection ? 1 : 0);
        cmd.Parameters.AddWithValue("@showTimestamps", profile.ShowTimestamps ? 1 : 0);
        cmd.Parameters.AddWithValue("@doubleRatchet", profile.DoubleRatchetEnabled ? 1 : 0);
        cmd.Parameters.AddWithValue("@postQuantum", profile.PostQuantumEnabled ? 1 : 0);
        cmd.Parameters.AddWithValue("@multiLayerEnc", profile.MultiLayerEncryption ? 1 : 0);
        cmd.Parameters.AddWithValue("@deniableEnc", profile.DeniableEncryption ? 1 : 0);
        cmd.Parameters.AddWithValue("@trafficObf", profile.TrafficObfuscation ? 1 : 0);
        cmd.Parameters.AddWithValue("@timingProt", profile.TimingProtection ? 1 : 0);
        cmd.Parameters.AddWithValue("@ramOnly", profile.RamOnlyMode ? 1 : 0);
        cmd.Parameters.AddWithValue("@dnsLeak", profile.DnsLeakProtection ? 1 : 0);
        cmd.Parameters.AddWithValue("@deadMan", profile.DeadManSwitch ? 1 : 0);
        cmd.Parameters.AddWithValue("@deadManDays", profile.DeadManSwitchDays);
        cmd.Parameters.AddWithValue("@tamperDet", profile.TamperDetection ? 1 : 0);
        cmd.Parameters.AddWithValue("@integrityMon", profile.IntegrityMonitoring ? 1 : 0);
        cmd.Parameters.AddWithValue("@canary", profile.CanaryTokens ? 1 : 0);
        cmd.Parameters.AddWithValue("@autoMeta", profile.AutoMetadataStrip ? 1 : 0);
        cmd.Parameters.AddWithValue("@torBridge", (object?)profile.TorBridgeLine ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@torTransport", (object?)profile.TorPluggableTransport ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@guardNodes", (object?)profile.PinnedGuardNodes ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@maxLogin", profile.MaxLoginAttempts);
        cmd.Parameters.AddWithValue("@lockout", profile.LockoutMinutes);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<Models.UserProfile?> GetUserProfileAsync(CancellationToken ct = default)
    {
        EnsureOpen();
        const string sql = """
            SELECT id, display_name, public_key, encrypted_private_key, password_salt,
                   password_hash, created_at, last_login_at, avatar_data, language,
                   auto_lock_minutes, notification_sounds, screen_capture_protection,
                   show_timestamps, double_ratchet, post_quantum, multi_layer_enc,
                   deniable_enc, traffic_obfuscation, timing_protection, ram_only_mode,
                   dns_leak_protection, dead_man_switch, dead_man_switch_days,
                   tamper_detection, integrity_monitoring, canary_tokens, auto_metadata_strip,
                   tor_bridge_line, tor_pluggable_transport, pinned_guard_nodes,
                   max_login_attempts, lockout_minutes
            FROM user_profile LIMIT 1
            """;

        await using var cmd = _connection!.CreateCommand();
        cmd.CommandText = sql;
        await using var reader = await cmd.ExecuteReaderAsync(ct);

        if (!await reader.ReadAsync(ct))
            return null;

        return new Models.UserProfile
        {
            Id = reader.GetString(0),
            DisplayName = reader.GetString(1),
            PublicKey = (byte[])reader.GetValue(2),
            EncryptedPrivateKey = (byte[])reader.GetValue(3),
            PasswordSalt = (byte[])reader.GetValue(4),
            PasswordHash = (byte[])reader.GetValue(5),
            CreatedAt = DateTimeOffset.Parse(reader.GetString(6)),
            LastLoginAt = DateTimeOffset.Parse(reader.GetString(7)),
            AvatarData = reader.IsDBNull(8) ? null : (byte[])reader.GetValue(8),
            Language = reader.IsDBNull(9) ? "en" : reader.GetString(9),
            AutoLockMinutes = reader.IsDBNull(10) ? 0 : reader.GetInt32(10),
            NotificationSounds = reader.IsDBNull(11) || reader.GetInt32(11) == 1,
            ScreenCaptureProtection = !reader.IsDBNull(12) && reader.GetInt32(12) == 1,
            ShowTimestamps = reader.IsDBNull(13) || reader.GetInt32(13) == 1,
            DoubleRatchetEnabled = reader.IsDBNull(14) || reader.GetInt32(14) == 1,
            PostQuantumEnabled = !reader.IsDBNull(15) && reader.GetInt32(15) == 1,
            MultiLayerEncryption = !reader.IsDBNull(16) && reader.GetInt32(16) == 1,
            DeniableEncryption = !reader.IsDBNull(17) && reader.GetInt32(17) == 1,
            TrafficObfuscation = reader.IsDBNull(18) || reader.GetInt32(18) == 1,
            TimingProtection = reader.IsDBNull(19) || reader.GetInt32(19) == 1,
            RamOnlyMode = !reader.IsDBNull(20) && reader.GetInt32(20) == 1,
            DnsLeakProtection = reader.IsDBNull(21) || reader.GetInt32(21) == 1,
            DeadManSwitch = !reader.IsDBNull(22) && reader.GetInt32(22) == 1,
            DeadManSwitchDays = reader.IsDBNull(23) ? 30 : reader.GetInt32(23),
            TamperDetection = reader.IsDBNull(24) || reader.GetInt32(24) == 1,
            IntegrityMonitoring = reader.IsDBNull(25) || reader.GetInt32(25) == 1,
            CanaryTokens = reader.IsDBNull(26) || reader.GetInt32(26) == 1,
            AutoMetadataStrip = reader.IsDBNull(27) || reader.GetInt32(27) == 1,
            TorBridgeLine = reader.IsDBNull(28) ? null : reader.GetString(28),
            TorPluggableTransport = reader.IsDBNull(29) ? null : reader.GetString(29),
            PinnedGuardNodes = reader.IsDBNull(30) ? null : reader.GetString(30),
            MaxLoginAttempts = reader.IsDBNull(31) ? 5 : reader.GetInt32(31),
            LockoutMinutes = reader.IsDBNull(32) ? 15 : reader.GetInt32(32),
        };
    }

    // ═══════════════ Rooms ═══════════════

    public async Task SaveRoomAsync(Models.ChatRoom room, CancellationToken ct = default)
    {
        EnsureOpen();
        const string sql = """
            INSERT OR REPLACE INTO rooms
                (id, name, room_salt, created_at, last_activity_at, unread_count,
                 description, max_capacity, invite_token, onion_address)
            VALUES
                (@id, @name, @salt, @created, @activity, @unread,
                 @desc, @maxCap, @invite, @onion)
            """;

        await using var cmd = _connection!.CreateCommand();
        cmd.CommandText = sql;
        cmd.Parameters.AddWithValue("@id", room.Id);
        cmd.Parameters.AddWithValue("@name", room.Name);
        cmd.Parameters.AddWithValue("@salt", room.RoomSalt);
        cmd.Parameters.AddWithValue("@created", room.CreatedAt.ToString("O"));
        cmd.Parameters.AddWithValue("@activity", room.LastActivityAt.ToString("O"));
        cmd.Parameters.AddWithValue("@unread", room.UnreadCount);
        cmd.Parameters.AddWithValue("@desc", (object?)room.Description ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@maxCap", room.MaxCapacity);
        cmd.Parameters.AddWithValue("@invite", (object?)room.InviteToken ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@onion", (object?)room.OnionAddress ?? DBNull.Value);
        try
        {
            await cmd.ExecuteNonQueryAsync(ct);
        }
        catch (SqliteException ex)
        {
            _logger?.DbError("SaveRoom", ex, $"room_id={room.Id}, name={room.Name}");
            throw;
        }
    }

    public async Task<List<Models.ChatRoom>> GetRoomsAsync(CancellationToken ct = default)
    {
        EnsureOpen();
        const string sql = """
            SELECT id, name, room_salt, created_at, last_activity_at, unread_count,
                   description, max_capacity, invite_token, onion_address
            FROM rooms ORDER BY last_activity_at DESC
            """;

        var rooms = new List<Models.ChatRoom>();
        await using var cmd = _connection!.CreateCommand();
        cmd.CommandText = sql;
        await using var reader = await cmd.ExecuteReaderAsync(ct);

        while (await reader.ReadAsync(ct))
        {
            rooms.Add(new Models.ChatRoom
            {
                Id = reader.GetString(0),
                Name = reader.GetString(1),
                RoomSalt = (byte[])reader.GetValue(2),
                CreatedAt = DateTimeOffset.Parse(reader.GetString(3)),
                LastActivityAt = DateTimeOffset.Parse(reader.GetString(4)),
                UnreadCount = reader.GetInt32(5),
                Description = reader.IsDBNull(6) ? null : reader.GetString(6),
                MaxCapacity = reader.IsDBNull(7) ? 0 : reader.GetInt32(7),
                InviteToken = reader.IsDBNull(8) ? null : reader.GetString(8),
                OnionAddress = reader.IsDBNull(9) ? null : reader.GetString(9),
            });
        }

        return rooms;
    }

    public async Task DeleteRoomAsync(string roomId, CancellationToken ct = default)
    {
        EnsureOpen();
        await using var cmd = _connection!.CreateCommand();
        cmd.CommandText = "DELETE FROM rooms WHERE id = @id";
        cmd.Parameters.AddWithValue("@id", roomId);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    // ═══════════════ Messages ═══════════════

    public async Task SaveMessageAsync(string roomId, Models.ChatMessage message, byte[] roomKey, CancellationToken ct = default)
    {
        EnsureOpen();

        var encryptedContent = MessageEncryption.Encrypt(
            System.Text.Encoding.UTF8.GetBytes(message.Content),
            roomKey);

        const string sql = """
            INSERT OR REPLACE INTO messages
                (id, room_id, sender_fingerprint, sender_display_name, message_type,
                 encrypted_content, file_name, file_size, mime_type, timestamp,
                 reply_to_id, reply_to_content, reply_to_sender, edited_at,
                 is_deleted, self_destruct_seconds, self_destruct_at, is_pinned,
                 is_delivered, is_read, voice_duration, is_view_once, viewed_at)
            VALUES
                (@id, @room, @sender, @senderName, @type,
                 @content, @fileName, @fileSize, @mimeType, @timestamp,
                 @replyToId, @replyToContent, @replyToSender, @editedAt,
                 @isDeleted, @selfDestructSec, @selfDestructAt, @isPinned,
                 @isDelivered, @isRead, @voiceDuration, @isViewOnce, @viewedAt)
            """;

        await using var cmd = _connection!.CreateCommand();
        cmd.CommandText = sql;
        cmd.Parameters.AddWithValue("@id", message.Id);
        cmd.Parameters.AddWithValue("@room", roomId);
        cmd.Parameters.AddWithValue("@sender", message.SenderFingerprint);
        cmd.Parameters.AddWithValue("@senderName", message.SenderDisplayName);
        cmd.Parameters.AddWithValue("@type", (int)message.Type);
        cmd.Parameters.AddWithValue("@content", encryptedContent);
        cmd.Parameters.AddWithValue("@fileName", (object?)message.FileName ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@fileSize", (object?)message.FileSize ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@mimeType", (object?)message.MimeType ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@timestamp", message.Timestamp.ToString("O"));
        cmd.Parameters.AddWithValue("@replyToId", (object?)message.ReplyToId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@replyToContent", (object?)message.ReplyToContent ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@replyToSender", (object?)message.ReplyToSenderName ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@editedAt", message.EditedAt.HasValue ? message.EditedAt.Value.ToString("O") : DBNull.Value);
        cmd.Parameters.AddWithValue("@isDeleted", message.IsDeleted ? 1 : 0);
        cmd.Parameters.AddWithValue("@selfDestructSec", (object?)message.SelfDestructSeconds ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@selfDestructAt", message.SelfDestructAt.HasValue ? message.SelfDestructAt.Value.ToString("O") : DBNull.Value);
        cmd.Parameters.AddWithValue("@isPinned", message.IsPinned ? 1 : 0);
        cmd.Parameters.AddWithValue("@isDelivered", message.IsDelivered ? 1 : 0);
        cmd.Parameters.AddWithValue("@isRead", message.IsRead ? 1 : 0);
        cmd.Parameters.AddWithValue("@voiceDuration", (object?)message.VoiceDuration ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@isViewOnce", message.IsViewOnce ? 1 : 0);
        cmd.Parameters.AddWithValue("@viewedAt", message.ViewedAt.HasValue ? message.ViewedAt.Value.ToString("O") : DBNull.Value);
        try
        {
            await cmd.ExecuteNonQueryAsync(ct);
        }
        catch (SqliteException ex)
        {
            _logger?.DbError("SaveMessage/INSERT", ex, $"room_id={roomId}, msg_id={message.Id}");
            throw;
        }

        // Update room activity
        await using var updateCmd = _connection!.CreateCommand();
        updateCmd.CommandText = "UPDATE rooms SET last_activity_at = @time WHERE id = @room";
        updateCmd.Parameters.AddWithValue("@time", DateTimeOffset.UtcNow.ToString("O"));
        updateCmd.Parameters.AddWithValue("@room", roomId);
        try
        {
            await updateCmd.ExecuteNonQueryAsync(ct);
        }
        catch (SqliteException ex)
        {
            _logger?.DbError("SaveMessage/UpdateRoomActivity", ex, $"room_id={roomId}");
        }
    }

    public async Task<List<Models.ChatMessage>> GetMessagesAsync(
        string roomId, byte[] roomKey, int limit = 50, int offset = 0, CancellationToken ct = default)
    {
        EnsureOpen();
        const string sql = """
            SELECT id, room_id, sender_fingerprint, sender_display_name, message_type,
                   encrypted_content, file_name, file_size, mime_type, timestamp,
                   reply_to_id, reply_to_content, reply_to_sender, edited_at,
                   is_deleted, self_destruct_seconds, self_destruct_at, is_pinned,
                   is_delivered, is_read, voice_duration, is_view_once, viewed_at
            FROM messages
            WHERE room_id = @room
            ORDER BY timestamp DESC
            LIMIT @limit OFFSET @offset
            """;

        var messages = new List<Models.ChatMessage>();
        await using var cmd = _connection!.CreateCommand();
        cmd.CommandText = sql;
        cmd.Parameters.AddWithValue("@room", roomId);
        cmd.Parameters.AddWithValue("@limit", limit);
        cmd.Parameters.AddWithValue("@offset", offset);
        await using var reader = await cmd.ExecuteReaderAsync(ct);

        while (await reader.ReadAsync(ct))
        {
            var encryptedContent = (byte[])reader.GetValue(5);
            string content;
            try
            {
                content = System.Text.Encoding.UTF8.GetString(
                    MessageEncryption.Decrypt(encryptedContent, roomKey));
            }
            catch (System.Security.Cryptography.CryptographicException)
            {
                content = "[Decryption failed]";
            }

            messages.Add(new Models.ChatMessage
            {
                Id = reader.GetString(0),
                RoomId = reader.GetString(1),
                SenderFingerprint = reader.GetString(2),
                SenderDisplayName = reader.GetString(3),
                Type = (Models.MessageType)reader.GetInt32(4),
                Content = content,
                FileName = reader.IsDBNull(6) ? null : reader.GetString(6),
                FileSize = reader.IsDBNull(7) ? null : reader.GetInt64(7),
                MimeType = reader.IsDBNull(8) ? null : reader.GetString(8),
                Timestamp = DateTimeOffset.Parse(reader.GetString(9)),
                ReplyToId = reader.IsDBNull(10) ? null : reader.GetString(10),
                ReplyToContent = reader.IsDBNull(11) ? null : reader.GetString(11),
                ReplyToSenderName = reader.IsDBNull(12) ? null : reader.GetString(12),
                EditedAt = reader.IsDBNull(13) ? null : DateTimeOffset.Parse(reader.GetString(13)),
                IsDeleted = !reader.IsDBNull(14) && reader.GetInt32(14) == 1,
                SelfDestructSeconds = reader.IsDBNull(15) ? null : reader.GetInt32(15),
                SelfDestructAt = reader.IsDBNull(16) ? null : DateTimeOffset.Parse(reader.GetString(16)),
                IsPinned = !reader.IsDBNull(17) && reader.GetInt32(17) == 1,
                IsDelivered = !reader.IsDBNull(18) && reader.GetInt32(18) == 1,
                IsRead = !reader.IsDBNull(19) && reader.GetInt32(19) == 1,
                VoiceDuration = reader.IsDBNull(20) ? null : reader.GetDouble(20),
                IsViewOnce = !reader.IsDBNull(21) && reader.GetInt32(21) == 1,
                ViewedAt = reader.IsDBNull(22) ? null : DateTimeOffset.Parse(reader.GetString(22)),
            });
        }

        messages.Reverse();
        return messages;
    }

    public async Task UpdateMessageContentAsync(string messageId, byte[] encryptedContent, CancellationToken ct = default)
    {
        EnsureOpen();
        await using var cmd = _connection!.CreateCommand();
        cmd.CommandText = "UPDATE messages SET encrypted_content = @content, edited_at = @edited WHERE id = @id";
        cmd.Parameters.AddWithValue("@content", encryptedContent);
        cmd.Parameters.AddWithValue("@edited", DateTimeOffset.UtcNow.ToString("O"));
        cmd.Parameters.AddWithValue("@id", messageId);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task SoftDeleteMessageAsync(string messageId, CancellationToken ct = default)
    {
        EnsureOpen();
        await using var cmd = _connection!.CreateCommand();
        cmd.CommandText = "UPDATE messages SET is_deleted = 1 WHERE id = @id";
        cmd.Parameters.AddWithValue("@id", messageId);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task PinMessageAsync(string messageId, string roomId, CancellationToken ct = default)
    {
        EnsureOpen();
        await using var cmd = _connection!.CreateCommand();
        cmd.CommandText = "UPDATE messages SET is_pinned = 1 WHERE id = @id";
        cmd.Parameters.AddWithValue("@id", messageId);
        await cmd.ExecuteNonQueryAsync(ct);

        await using var pinCmd = _connection!.CreateCommand();
        pinCmd.CommandText = "INSERT OR IGNORE INTO pinned_messages (message_id, room_id, pinned_at) VALUES (@msgId, @roomId, @at)";
        pinCmd.Parameters.AddWithValue("@msgId", messageId);
        pinCmd.Parameters.AddWithValue("@roomId", roomId);
        pinCmd.Parameters.AddWithValue("@at", DateTimeOffset.UtcNow.ToString("O"));
        try
        {
            await pinCmd.ExecuteNonQueryAsync(ct);
        }
        catch (SqliteException ex)
        {
            _logger?.DbError("PinMessage/INSERT", ex, $"message_id={messageId}, room_id={roomId}");
            throw;
        }
    }

    public async Task UnpinMessageAsync(string messageId, CancellationToken ct = default)
    {
        EnsureOpen();
        await using var cmd = _connection!.CreateCommand();
        cmd.CommandText = "UPDATE messages SET is_pinned = 0 WHERE id = @id";
        cmd.Parameters.AddWithValue("@id", messageId);
        await cmd.ExecuteNonQueryAsync(ct);

        await using var unpinCmd = _connection!.CreateCommand();
        unpinCmd.CommandText = "DELETE FROM pinned_messages WHERE message_id = @id";
        unpinCmd.Parameters.AddWithValue("@id", messageId);
        await unpinCmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<List<Models.ChatMessage>> SearchMessagesAsync(
        string roomId, byte[] roomKey, string query, CancellationToken ct = default)
    {
        // Decrypt-then-search: we must load all messages and filter in memory
        // because the content is encrypted in the DB.
        var all = await GetMessagesAsync(roomId, roomKey, limit: 500, offset: 0, ct: ct);
        return all.Where(m => !m.IsDeleted &&
            m.Content.Contains(query, StringComparison.OrdinalIgnoreCase)).ToList();
    }

    public async Task DeleteSelfDestructedMessagesAsync(CancellationToken ct = default)
    {
        EnsureOpen();
        await using var cmd = _connection!.CreateCommand();
        cmd.CommandText = "DELETE FROM messages WHERE self_destruct_at IS NOT NULL AND self_destruct_at <= @now";
        cmd.Parameters.AddWithValue("@now", DateTimeOffset.UtcNow.ToString("O"));
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task MarkMessageReadAsync(string messageId, CancellationToken ct = default)
    {
        EnsureOpen();
        await using var cmd = _connection!.CreateCommand();
        cmd.CommandText = "UPDATE messages SET is_read = 1, is_delivered = 1 WHERE id = @id";
        cmd.Parameters.AddWithValue("@id", messageId);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    // ═══════════════ Blocked Users ═══════════════

    public async Task BlockUserAsync(string fingerprint, string? displayName, CancellationToken ct = default)
    {
        EnsureOpen();
        await using var cmd = _connection!.CreateCommand();
        cmd.CommandText = "INSERT OR REPLACE INTO blocked_users (fingerprint, display_name, blocked_at) VALUES (@fp, @name, @at)";
        cmd.Parameters.AddWithValue("@fp", fingerprint);
        cmd.Parameters.AddWithValue("@name", (object?)displayName ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@at", DateTimeOffset.UtcNow.ToString("O"));
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task UnblockUserAsync(string fingerprint, CancellationToken ct = default)
    {
        EnsureOpen();
        await using var cmd = _connection!.CreateCommand();
        cmd.CommandText = "DELETE FROM blocked_users WHERE fingerprint = @fp";
        cmd.Parameters.AddWithValue("@fp", fingerprint);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<List<Models.BlockedUser>> GetBlockedUsersAsync(CancellationToken ct = default)
    {
        EnsureOpen();
        var list = new List<Models.BlockedUser>();
        await using var cmd = _connection!.CreateCommand();
        cmd.CommandText = "SELECT fingerprint, display_name, blocked_at FROM blocked_users ORDER BY blocked_at DESC";
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            list.Add(new Models.BlockedUser
            {
                Fingerprint = reader.GetString(0),
                DisplayName = reader.IsDBNull(1) ? null : reader.GetString(1),
                BlockedAt = DateTimeOffset.Parse(reader.GetString(2)),
            });
        }
        return list;
    }

    public async Task<bool> IsUserBlockedAsync(string fingerprint, CancellationToken ct = default)
    {
        EnsureOpen();
        await using var cmd = _connection!.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM blocked_users WHERE fingerprint = @fp";
        cmd.Parameters.AddWithValue("@fp", fingerprint);
        var result = await cmd.ExecuteScalarAsync(ct);
        return result is long count && count > 0;
    }

    // ═══════════════ Settings ═══════════════

    public async Task SetSettingAsync(string key, string value, CancellationToken ct = default)
    {
        EnsureOpen();
        await using var cmd = _connection!.CreateCommand();
        cmd.CommandText = "INSERT OR REPLACE INTO settings (key, value) VALUES (@key, @value)";
        cmd.Parameters.AddWithValue("@key", key);
        cmd.Parameters.AddWithValue("@value", value);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<string?> GetSettingAsync(string key, CancellationToken ct = default)
    {
        EnsureOpen();
        await using var cmd = _connection!.CreateCommand();
        cmd.CommandText = "SELECT value FROM settings WHERE key = @key";
        cmd.Parameters.AddWithValue("@key", key);
        var result = await cmd.ExecuteScalarAsync(ct);
        return result as string;
    }

    // ═══════════════ Encrypted Files ═══════════════

    public async Task SaveEncryptedFileAsync(string id, string messageId, byte[] encryptedData, CancellationToken ct = default)
    {
        EnsureOpen();
        await using var cmd = _connection!.CreateCommand();
        cmd.CommandText = "INSERT OR REPLACE INTO encrypted_files (id, message_id, encrypted_data) VALUES (@id, @msgId, @data)";
        cmd.Parameters.AddWithValue("@id", id);
        cmd.Parameters.AddWithValue("@msgId", messageId);
        cmd.Parameters.AddWithValue("@data", encryptedData);
        try
        {
            await cmd.ExecuteNonQueryAsync(ct);
        }
        catch (SqliteException ex)
        {
            _logger?.DbError("SaveEncryptedFile", ex, $"id={id}, message_id={messageId}");
            throw;
        }
    }

    public async Task<byte[]?> GetEncryptedFileAsync(string id, CancellationToken ct = default)
    {
        EnsureOpen();
        await using var cmd = _connection!.CreateCommand();
        cmd.CommandText = "SELECT encrypted_data FROM encrypted_files WHERE id = @id";
        cmd.Parameters.AddWithValue("@id", id);
        var result = await cmd.ExecuteScalarAsync(ct);
        return result as byte[];
    }

    // ═══════════════ Reactions ═══════════════

    public async Task AddReactionAsync(string messageId, string emoji, string senderFingerprint, CancellationToken ct = default)
    {
        EnsureOpen();
        await using var cmd = _connection!.CreateCommand();
        cmd.CommandText = "INSERT OR IGNORE INTO reactions (message_id, emoji, sender_fingerprint, created_at) VALUES (@msgId, @emoji, @sender, @at)";
        cmd.Parameters.AddWithValue("@msgId", messageId);
        cmd.Parameters.AddWithValue("@emoji", emoji);
        cmd.Parameters.AddWithValue("@sender", senderFingerprint);
        cmd.Parameters.AddWithValue("@at", DateTimeOffset.UtcNow.ToString("O"));
        try
        {
            await cmd.ExecuteNonQueryAsync(ct);
        }
        catch (SqliteException ex)
        {
            _logger?.DbError("AddReaction", ex, $"message_id={messageId}, emoji={emoji}");
            throw;
        }
    }

    public async Task RemoveReactionAsync(string messageId, string emoji, string senderFingerprint, CancellationToken ct = default)
    {
        EnsureOpen();
        await using var cmd = _connection!.CreateCommand();
        cmd.CommandText = "DELETE FROM reactions WHERE message_id = @msgId AND emoji = @emoji AND sender_fingerprint = @sender";
        cmd.Parameters.AddWithValue("@msgId", messageId);
        cmd.Parameters.AddWithValue("@emoji", emoji);
        cmd.Parameters.AddWithValue("@sender", senderFingerprint);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<Dictionary<string, List<string>>> GetReactionsAsync(string messageId, CancellationToken ct = default)
    {
        EnsureOpen();
        var reactions = new Dictionary<string, List<string>>();
        await using var cmd = _connection!.CreateCommand();
        cmd.CommandText = "SELECT emoji, sender_fingerprint FROM reactions WHERE message_id = @msgId ORDER BY created_at";
        cmd.Parameters.AddWithValue("@msgId", messageId);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var emoji = reader.GetString(0);
            var sender = reader.GetString(1);
            if (!reactions.ContainsKey(emoji))
                reactions[emoji] = [];
            reactions[emoji].Add(sender);
        }
        return reactions;
    }

    public async Task<Dictionary<string, Dictionary<string, List<string>>>> GetAllReactionsForRoomAsync(string roomId, CancellationToken ct = default)
    {
        EnsureOpen();
        var result = new Dictionary<string, Dictionary<string, List<string>>>();
        await using var cmd = _connection!.CreateCommand();
        cmd.CommandText = """
            SELECT r.message_id, r.emoji, r.sender_fingerprint
            FROM reactions r
            INNER JOIN messages m ON r.message_id = m.id
            WHERE m.room_id = @roomId
            ORDER BY r.created_at
            """;
        cmd.Parameters.AddWithValue("@roomId", roomId);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var msgId = reader.GetString(0);
            var emoji = reader.GetString(1);
            var sender = reader.GetString(2);
            if (!result.ContainsKey(msgId))
                result[msgId] = new Dictionary<string, List<string>>();
            if (!result[msgId].ContainsKey(emoji))
                result[msgId][emoji] = [];
            result[msgId][emoji].Add(sender);
        }
        return result;
    }

    // ═══════════════ View Once ═══════════════

    public async Task MarkViewOnceViewedAsync(string messageId, CancellationToken ct = default)
    {
        EnsureOpen();
        await using var cmd = _connection!.CreateCommand();
        cmd.CommandText = "UPDATE messages SET viewed_at = @at WHERE id = @id AND is_view_once = 1 AND viewed_at IS NULL";
        cmd.Parameters.AddWithValue("@at", DateTimeOffset.UtcNow.ToString("O"));
        cmd.Parameters.AddWithValue("@id", messageId);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    // ═══════════════ Bookmarks ═══════════════

    public async Task AddBookmarkAsync(Models.Bookmark bookmark, CancellationToken ct = default)
    {
        EnsureOpen();
        await using var cmd = _connection!.CreateCommand();
        cmd.CommandText = "INSERT OR REPLACE INTO bookmarks (message_id, room_id, room_name, sender_name, content_preview, created_at) VALUES (@msgId, @roomId, @roomName, @sender, @preview, @at)";
        cmd.Parameters.AddWithValue("@msgId", bookmark.MessageId);
        cmd.Parameters.AddWithValue("@roomId", bookmark.RoomId);
        cmd.Parameters.AddWithValue("@roomName", bookmark.RoomName);
        cmd.Parameters.AddWithValue("@sender", bookmark.SenderName);
        cmd.Parameters.AddWithValue("@preview", bookmark.ContentPreview);
        cmd.Parameters.AddWithValue("@at", bookmark.CreatedAt.ToString("O"));
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task RemoveBookmarkAsync(string messageId, CancellationToken ct = default)
    {
        EnsureOpen();
        await using var cmd = _connection!.CreateCommand();
        cmd.CommandText = "DELETE FROM bookmarks WHERE message_id = @id";
        cmd.Parameters.AddWithValue("@id", messageId);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<List<Models.Bookmark>> GetBookmarksAsync(CancellationToken ct = default)
    {
        EnsureOpen();
        var list = new List<Models.Bookmark>();
        await using var cmd = _connection!.CreateCommand();
        cmd.CommandText = "SELECT message_id, room_id, room_name, sender_name, content_preview, created_at FROM bookmarks ORDER BY created_at DESC";
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            list.Add(new Models.Bookmark
            {
                MessageId = reader.GetString(0),
                RoomId = reader.GetString(1),
                RoomName = reader.GetString(2),
                SenderName = reader.GetString(3),
                ContentPreview = reader.GetString(4),
                CreatedAt = DateTimeOffset.Parse(reader.GetString(5)),
            });
        }
        return list;
    }

    public async Task<bool> IsBookmarkedAsync(string messageId, CancellationToken ct = default)
    {
        EnsureOpen();
        await using var cmd = _connection!.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM bookmarks WHERE message_id = @id";
        cmd.Parameters.AddWithValue("@id", messageId);
        var result = await cmd.ExecuteScalarAsync(ct);
        return result is long count && count > 0;
    }

    // ═══════════════ Key Rotations ═══════════════

    public async Task SaveKeyRotationAsync(Models.KeyRotationRecord record, CancellationToken ct = default)
    {
        EnsureOpen();
        await using var cmd = _connection!.CreateCommand();
        cmd.CommandText = """
            INSERT INTO key_rotations (id, room_id, old_public_key, new_public_key, rotation_number, rotated_at, initiator_fingerprint)
            VALUES (@id, @roomId, @oldKey, @newKey, @num, @at, @initiator)
            """;
        cmd.Parameters.AddWithValue("@id", record.Id);
        cmd.Parameters.AddWithValue("@roomId", record.RoomId);
        cmd.Parameters.AddWithValue("@oldKey", record.OldPublicKey);
        cmd.Parameters.AddWithValue("@newKey", record.NewPublicKey);
        cmd.Parameters.AddWithValue("@num", record.RotationNumber);
        cmd.Parameters.AddWithValue("@at", record.RotatedAt.ToString("O"));
        cmd.Parameters.AddWithValue("@initiator", (object?)record.InitiatorFingerprint ?? DBNull.Value);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<int> GetKeyRotationCountAsync(string roomId, CancellationToken ct = default)
    {
        EnsureOpen();
        await using var cmd = _connection!.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM key_rotations WHERE room_id = @roomId";
        cmd.Parameters.AddWithValue("@roomId", roomId);
        var result = await cmd.ExecuteScalarAsync(ct);
        return result is long count ? (int)count : 0;
    }

    // ═══════════════ Dead Drops ═══════════════

    public async Task SaveDeadDropAsync(Models.DeadDrop drop, CancellationToken ct = default)
    {
        EnsureOpen();
        await using var cmd = _connection!.CreateCommand();
        cmd.CommandText = """
            INSERT INTO dead_drops (id, drop_address, sender_fingerprint, recipient_fingerprint, encrypted_payload, created_at, expires_at, is_picked_up, picked_up_at)
            VALUES (@id, @addr, @sender, @recipient, @payload, @created, @expires, @picked, @pickedAt)
            """;
        cmd.Parameters.AddWithValue("@id", drop.Id);
        cmd.Parameters.AddWithValue("@addr", drop.DropAddress);
        cmd.Parameters.AddWithValue("@sender", drop.SenderFingerprint);
        cmd.Parameters.AddWithValue("@recipient", drop.RecipientFingerprint);
        cmd.Parameters.AddWithValue("@payload", drop.EncryptedPayload);
        cmd.Parameters.AddWithValue("@created", drop.CreatedAt.ToString("O"));
        cmd.Parameters.AddWithValue("@expires", drop.ExpiresAt.HasValue ? drop.ExpiresAt.Value.ToString("O") : DBNull.Value);
        cmd.Parameters.AddWithValue("@picked", drop.IsPickedUp ? 1 : 0);
        cmd.Parameters.AddWithValue("@pickedAt", drop.PickedUpAt.HasValue ? drop.PickedUpAt.Value.ToString("O") : DBNull.Value);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<List<Models.DeadDrop>> GetDeadDropsForRecipientAsync(string fingerprint, CancellationToken ct = default)
    {
        EnsureOpen();
        var list = new List<Models.DeadDrop>();
        await using var cmd = _connection!.CreateCommand();
        cmd.CommandText = "SELECT id, drop_address, sender_fingerprint, recipient_fingerprint, encrypted_payload, created_at, expires_at, is_picked_up, picked_up_at FROM dead_drops WHERE recipient_fingerprint = @fp AND is_picked_up = 0 ORDER BY created_at DESC";
        cmd.Parameters.AddWithValue("@fp", fingerprint);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            list.Add(new Models.DeadDrop
            {
                Id = reader.GetString(0),
                DropAddress = reader.GetString(1),
                SenderFingerprint = reader.GetString(2),
                RecipientFingerprint = reader.GetString(3),
                EncryptedPayload = (byte[])reader.GetValue(4),
                CreatedAt = DateTimeOffset.Parse(reader.GetString(5)),
                ExpiresAt = reader.IsDBNull(6) ? null : DateTimeOffset.Parse(reader.GetString(6)),
                IsPickedUp = reader.GetInt32(7) == 1,
                PickedUpAt = reader.IsDBNull(8) ? null : DateTimeOffset.Parse(reader.GetString(8)),
            });
        }
        return list;
    }

    public async Task MarkDeadDropPickedUpAsync(string dropId, CancellationToken ct = default)
    {
        EnsureOpen();
        await using var cmd = _connection!.CreateCommand();
        cmd.CommandText = "UPDATE dead_drops SET is_picked_up = 1, picked_up_at = @at WHERE id = @id";
        cmd.Parameters.AddWithValue("@at", DateTimeOffset.UtcNow.ToString("O"));
        cmd.Parameters.AddWithValue("@id", dropId);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    // ═══════════════ Panic Wipe ═══════════════

    public async Task WipeAllDataAsync(CancellationToken ct = default)
    {
        EnsureOpen();
        await ExecuteNonQueryAsync("DELETE FROM dead_drops;", ct);
        await ExecuteNonQueryAsync("DELETE FROM key_rotations;", ct);
        await ExecuteNonQueryAsync("DELETE FROM bookmarks;", ct);
        await ExecuteNonQueryAsync("DELETE FROM reactions;", ct);
        await ExecuteNonQueryAsync("DELETE FROM encrypted_files;", ct);
        await ExecuteNonQueryAsync("DELETE FROM pinned_messages;", ct);
        await ExecuteNonQueryAsync("DELETE FROM messages;", ct);
        await ExecuteNonQueryAsync("DELETE FROM room_peers;", ct);
        await ExecuteNonQueryAsync("DELETE FROM rooms;", ct);
        await ExecuteNonQueryAsync("DELETE FROM blocked_users;", ct);
        await ExecuteNonQueryAsync("DELETE FROM settings;", ct);
        await ExecuteNonQueryAsync("DELETE FROM user_profile;", ct);
        await ExecuteNonQueryAsync("VACUUM;", ct);
    }

    // ═══════════════ Helpers ═══════════════

    public async Task ExecuteNonQueryAsync(string sql, CancellationToken ct = default)
    {
        EnsureOpen();
        await using var cmd = _connection!.CreateCommand();
        cmd.CommandText = sql;
        await cmd.ExecuteNonQueryAsync(ct);
    }

    private void EnsureOpen()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_connection is null || _connection.State != System.Data.ConnectionState.Open)
            throw new InvalidOperationException("Database is not initialized. Call InitializeAsync first.");
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;
        if (_connection is not null)
        {
            if (_connection.State == System.Data.ConnectionState.Open)
            {
                try
                {
                    await using var cmd = _connection.CreateCommand();
                    cmd.CommandText = "PRAGMA wal_checkpoint(TRUNCATE);";
                    await cmd.ExecuteNonQueryAsync();
                }
                catch
                {
                    // Best-effort checkpoint on dispose
                }
            }

            await _connection.CloseAsync();
            await _connection.DisposeAsync();
            _connection = null;
        }
    }
}
