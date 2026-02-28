using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace TordeX.Core.Services;

/// <summary>
/// Configuration for RAM-only message storage mode.
/// </summary>
/// <param name="Enabled">Whether RAM-only mode is active (no disk writes for messages).</param>
/// <param name="MaxMessagesPerRoom">Maximum messages retained per room before oldest are evicted.</param>
/// <param name="MaxTotalMessages">Maximum total messages across all rooms before global eviction.</param>
public sealed record RamOnlyConfig(
    bool Enabled,
    int MaxMessagesPerRoom = 1000,
    int MaxTotalMessages = 10000);

/// <summary>
/// An in-memory chat message record. Content is stored as encrypted bytes — never written to disk.
/// </summary>
/// <param name="Id">Unique message identifier.</param>
/// <param name="RoomId">Room this message belongs to.</param>
/// <param name="Sender">Sender's fingerprint or display name.</param>
/// <param name="Content">Encrypted message content (never stored on disk).</param>
/// <param name="Timestamp">When the message was created.</param>
public sealed record InMemoryMessage(
    string Id,
    string RoomId,
    string Sender,
    byte[] Content,
    DateTimeOffset Timestamp);

/// <summary>
/// In-memory message storage service that guarantees zero disk persistence.
/// All messages are held exclusively in RAM and securely wiped on clear.
/// Uses <see cref="ReaderWriterLockSlim"/> per room for concurrent read/write safety
/// and a global <see cref="ConcurrentDictionary{TKey,TValue}"/> for room-level isolation.
/// </summary>
public sealed class RamOnlyModeService : IDisposable
{
    private readonly ConcurrentDictionary<string, RoomStore> _rooms = new(StringComparer.Ordinal);
    private readonly RamOnlyConfig _config;
    private int _totalMessageCount;
    private bool _disposed;

    /// <summary>
    /// Per-room message store with its own reader-writer lock.
    /// </summary>
    private sealed class RoomStore : IDisposable
    {
        public readonly ReaderWriterLockSlim Lock = new(LockRecursionPolicy.NoRecursion);
        public readonly List<InMemoryMessage> Messages = [];
        private bool _disposed;

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;

            Lock.EnterWriteLock();
            try
            {
                SecureWipeMessages(Messages);
                Messages.Clear();
            }
            finally
            {
                Lock.ExitWriteLock();
            }

            Lock.Dispose();
        }
    }

    /// <summary>
    /// Initializes a new instance of <see cref="RamOnlyModeService"/> with the given configuration.
    /// </summary>
    /// <param name="config">RAM-only mode configuration.</param>
    public RamOnlyModeService(RamOnlyConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        _config = config;
    }

    /// <summary>
    /// Initializes a new instance of <see cref="RamOnlyModeService"/> with default configuration.
    /// </summary>
    public RamOnlyModeService()
        : this(new RamOnlyConfig(Enabled: true))
    {
    }

    /// <summary>
    /// Stores a message in RAM for the given room.
    /// If the room exceeds <see cref="RamOnlyConfig.MaxMessagesPerRoom"/>, the oldest message is evicted.
    /// If the global total exceeds <see cref="RamOnlyConfig.MaxTotalMessages"/>, the oldest message
    /// across all rooms is evicted.
    /// </summary>
    /// <param name="roomId">Target room identifier.</param>
    /// <param name="message">The message to store.</param>
    public void StoreMessage(string roomId, InMemoryMessage message)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(roomId);
        ArgumentNullException.ThrowIfNull(message);

        var room = _rooms.GetOrAdd(roomId, _ => new RoomStore());

        room.Lock.EnterWriteLock();
        try
        {
            // Evict oldest in room if at capacity
            while (room.Messages.Count >= _config.MaxMessagesPerRoom && room.Messages.Count > 0)
            {
                SecureWipeMessage(room.Messages[0]);
                room.Messages.RemoveAt(0);
                Interlocked.Decrement(ref _totalMessageCount);
            }

            room.Messages.Add(message);
            Interlocked.Increment(ref _totalMessageCount);
        }
        finally
        {
            room.Lock.ExitWriteLock();
        }

        // Global eviction if total exceeds maximum
        EnforceGlobalLimit();
    }

    /// <summary>
    /// Retrieves all messages for the given room as a defensive copy.
    /// </summary>
    /// <param name="roomId">Room identifier.</param>
    /// <returns>A copy of all messages in the room, or an empty list if the room does not exist.</returns>
    public List<InMemoryMessage> GetMessages(string roomId)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(roomId);

        if (!_rooms.TryGetValue(roomId, out var room))
            return [];

        room.Lock.EnterReadLock();
        try
        {
            return [.. room.Messages];
        }
        finally
        {
            room.Lock.ExitReadLock();
        }
    }

    /// <summary>
    /// Deletes a specific message by ID from the given room.
    /// The message content is securely wiped before removal.
    /// </summary>
    /// <param name="roomId">Room identifier.</param>
    /// <param name="messageId">Message identifier to delete.</param>
    /// <returns>True if the message was found and deleted; false otherwise.</returns>
    public bool DeleteMessage(string roomId, string messageId)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(roomId);
        ArgumentException.ThrowIfNullOrWhiteSpace(messageId);

        if (!_rooms.TryGetValue(roomId, out var room))
            return false;

        room.Lock.EnterWriteLock();
        try
        {
            for (int i = 0; i < room.Messages.Count; i++)
            {
                if (string.Equals(room.Messages[i].Id, messageId, StringComparison.Ordinal))
                {
                    SecureWipeMessage(room.Messages[i]);
                    room.Messages.RemoveAt(i);
                    Interlocked.Decrement(ref _totalMessageCount);
                    return true;
                }
            }
            return false;
        }
        finally
        {
            room.Lock.ExitWriteLock();
        }
    }

    /// <summary>
    /// Clears all messages from a specific room, securely wiping their content.
    /// </summary>
    /// <param name="roomId">Room identifier to clear.</param>
    public void ClearRoom(string roomId)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(roomId);

        if (!_rooms.TryRemove(roomId, out var room))
            return;

        room.Lock.EnterWriteLock();
        try
        {
            var count = room.Messages.Count;
            SecureWipeMessages(room.Messages);
            room.Messages.Clear();
            Interlocked.Add(ref _totalMessageCount, -count);
        }
        finally
        {
            room.Lock.ExitWriteLock();
        }

        room.Dispose();
    }

    /// <summary>
    /// Clears all messages from all rooms, securely wiping all content from memory.
    /// Overwrites all byte arrays with zeros, then random bytes, then zeros again.
    /// </summary>
    public void ClearAll()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var keys = _rooms.Keys.ToArray();
        foreach (var key in keys)
        {
            if (_rooms.TryRemove(key, out var room))
            {
                room.Dispose();
            }
        }

        Interlocked.Exchange(ref _totalMessageCount, 0);
    }

    /// <summary>
    /// Returns the total number of messages across all rooms.
    /// </summary>
    /// <returns>Total message count.</returns>
    public int GetMessageCount()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return Volatile.Read(ref _totalMessageCount);
    }

    /// <summary>
    /// Returns the number of active rooms.
    /// </summary>
    /// <returns>Room count.</returns>
    public int GetRoomCount()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _rooms.Count;
    }

    /// <summary>
    /// Securely clears a byte array: overwrite with zeros, then random bytes, then zeros.
    /// This three-pass wipe reduces the chance of data remanence in RAM.
    /// </summary>
    /// <param name="data">The byte array to securely wipe.</param>
    public static void SecureClear(byte[] data)
    {
        if (data is null || data.Length == 0) return;

        // Pass 1: zeros
        CryptographicOperations.ZeroMemory(data);

        // Pass 2: random overwrite
        RandomNumberGenerator.Fill(data);

        // Pass 3: zeros again
        CryptographicOperations.ZeroMemory(data);
    }

    /// <summary>
    /// Disposes the service and securely wipes all in-memory data.
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        var keys = _rooms.Keys.ToArray();
        foreach (var key in keys)
        {
            if (_rooms.TryRemove(key, out var room))
            {
                room.Dispose();
            }
        }

        Interlocked.Exchange(ref _totalMessageCount, 0);
    }

    /// <summary>
    /// Enforces the global message limit by evicting the oldest message across all rooms.
    /// </summary>
    private void EnforceGlobalLimit()
    {
        while (Volatile.Read(ref _totalMessageCount) > _config.MaxTotalMessages)
        {
            // Find the room with the oldest message
            string? oldestRoomId = null;
            DateTimeOffset oldestTimestamp = DateTimeOffset.MaxValue;

            foreach (var kvp in _rooms)
            {
                kvp.Value.Lock.EnterReadLock();
                try
                {
                    if (kvp.Value.Messages.Count > 0 && kvp.Value.Messages[0].Timestamp < oldestTimestamp)
                    {
                        oldestTimestamp = kvp.Value.Messages[0].Timestamp;
                        oldestRoomId = kvp.Key;
                    }
                }
                finally
                {
                    kvp.Value.Lock.ExitReadLock();
                }
            }

            if (oldestRoomId is null) break;

            if (_rooms.TryGetValue(oldestRoomId, out var room))
            {
                room.Lock.EnterWriteLock();
                try
                {
                    if (room.Messages.Count > 0)
                    {
                        SecureWipeMessage(room.Messages[0]);
                        room.Messages.RemoveAt(0);
                        Interlocked.Decrement(ref _totalMessageCount);
                    }
                }
                finally
                {
                    room.Lock.ExitWriteLock();
                }
            }
            else
            {
                break;
            }
        }
    }

    /// <summary>
    /// Securely wipes the content bytes of a single message.
    /// </summary>
    private static void SecureWipeMessage(InMemoryMessage message)
    {
        SecureClear(message.Content);
    }

    /// <summary>
    /// Securely wipes the content bytes of all messages in a list.
    /// </summary>
    private static void SecureWipeMessages(List<InMemoryMessage> messages)
    {
        foreach (var msg in messages)
        {
            SecureWipeMessage(msg);
        }
    }
}
