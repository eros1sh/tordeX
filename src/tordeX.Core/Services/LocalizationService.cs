using System.Collections.Frozen;

namespace TordeX.Core.Services;

/// <summary>
/// Dictionary-based localization service supporting Turkish (tr) and English (en).
/// Thread-safe via immutable frozen dictionaries and volatile backing field.
/// </summary>
public static class LocalizationService
{
    private static volatile string _currentLanguage = "en";

    private static readonly FrozenDictionary<string, string> EnStrings = new Dictionary<string, string>
    {
        // ──────────────── Login / Profile ────────────────
        ["DisplayName"] = "Display Name",
        ["Password"] = "Password",
        ["ConfirmPassword"] = "Confirm Password",
        ["CreateSecureProfile"] = "Create Secure Profile",
        ["Unlock"] = "Unlock",
        ["MinChars"] = "Min. 8 characters",
        ["RepeatPassword"] = "Repeat password",
        ["EnterYourPassword"] = "Enter your password",
        ["PasswordsDoNotMatch"] = "Passwords do not match",
        ["DisplayNameRequired"] = "Display name is required",
        ["PasswordMinLength"] = "Password must be at least 8 characters",
        ["InvalidPassword"] = "Invalid password. Please try again.",
        ["ProfileCorrupted"] = "Profile data is corrupted.",

        // ──────────────── Main Layout ────────────────
        ["ConnectingToTor"] = "Connecting to Tor...",
        ["TorConnected"] = "Tor Connected",
        ["TorFailed"] = "Tor Failed",
        ["RetryConnection"] = "Retry Connection",
        ["ConnectToTorNetwork"] = "Connect to Tor Network",
        ["NoRoomsYet"] = "No rooms yet.",
        ["CreateOrJoinRoom"] = "Create or join a room to start chatting.",
        ["NewRoom"] = "New Room",
        ["JoinRoom"] = "Join Room",
        ["Settings"] = "Settings",
        ["Unlocked"] = "Unlocked",
        ["Locked"] = "Locked",

        // ──────────────── Chat ────────────────
        ["TypeAMessage"] = "Type a message...",
        ["StartChatting"] = "Start Chatting",
        ["E2EEncryptionNotice"] = "Messages are end-to-end encrypted with AES-256-GCM.",
        ["RoomPasswordNotice"] = "Only members with the room password can read them.",
        ["RoomInformation"] = "Room Information",
        ["DropFileHere"] = "Drop file here to send encrypted",
        ["FileTooLarge"] = "File too large. Maximum size is 50 MB.",
        ["FailedToSend"] = "Failed to send",
        ["Send"] = "Send",
        ["Reply"] = "Reply",
        ["Edit"] = "Edit",
        ["Delete"] = "Delete",
        ["Forward"] = "Forward",
        ["Pin"] = "Pin",
        ["Unpin"] = "Unpin",
        ["Copy"] = "Copy",
        ["SearchMessages"] = "Search messages...",
        ["MessageDeleted"] = "This message was deleted",
        ["Edited"] = "edited",
        ["PinnedMessages"] = "Pinned Messages",

        // ──────────────── Room Dialogs ────────────────
        ["CreateNewRoom"] = "Create New Room",
        ["RoomName"] = "Room Name",
        ["RoomPassword"] = "Room Password",
        ["SharePasswordHint"] = "Share this password with people you want to invite.",
        ["RoomId"] = "Room ID",
        ["PasteRoomId"] = "Paste room ID",
        ["RoomDisplayName"] = "Room display name",
        ["RoomSharedPassword"] = "Room shared password",
        ["UnlockRoom"] = "Unlock Room",
        ["EnterPasswordFor"] = "Enter the password for",
        ["DeleteRoom"] = "Delete Room",
        ["ConfirmDeleteRoom"] = "Are you sure you want to delete",
        ["PermanentDeleteWarning"] = "All messages will be permanently removed from this device.",
        ["Cancel"] = "Cancel",
        ["Close"] = "Close",
        ["Save"] = "Save",

        // ──────────────── Settings ────────────────
        ["YourFingerprint"] = "Your Fingerprint",
        ["FingerprintDescription"] = "Your unique cryptographic identity.",
        ["PublicKey"] = "Public Key",
        ["SecurityInfo"] = "Security Info",
        ["Encryption"] = "Encryption",
        ["KeyDerivation"] = "Key Derivation",
        ["KeyExchange"] = "Key Exchange",
        ["Signatures"] = "Signatures",
        ["Network"] = "Network",
        ["SettingsSaved"] = "Settings saved.",
        ["Language"] = "Language",
        ["AutoLock"] = "Auto-Lock",
        ["Minutes"] = "minutes",
        ["Never"] = "Never",
        ["ChangePassword"] = "Change Password",
        ["CurrentPassword"] = "Current Password",
        ["NewPassword"] = "New Password",
        ["ConfirmNewPassword"] = "Confirm New Password",
        ["PasswordChanged"] = "Password changed successfully.",
        ["NotificationSounds"] = "Notification Sounds",
        ["ScreenCaptureProtection"] = "Screen Capture Protection",
        ["PanicButton"] = "Panic Button",
        ["DeleteAllData"] = "Delete ALL data immediately",
        ["CannotBeUndone"] = "This action cannot be undone!",
        ["RoomDescription"] = "Room Description",
        ["MaxCapacity"] = "Max Capacity",
        ["InviteLink"] = "Invite Link",
        ["CopyAction"] = "Copy",
        ["Copied"] = "Copied!",

        // ──────────────── Security ────────────────
        ["BlockedUsers"] = "Blocked Users",
        ["BlockUser"] = "Block User",
        ["Unblock"] = "Unblock",
        ["NoBlockedUsers"] = "No blocked users",
        ["SelfDestructTimer"] = "Self-destruct timer",
        ["Seconds"] = "seconds",
        ["VoiceMessage"] = "Voice message",
        ["Recording"] = "Recording...",
        ["Typing"] = "Typing...",
        ["Delivered"] = "Delivered",
        ["Read"] = "Read",
        ["WelcomeMessage"] = "Welcome to tordeX",
        ["WelcomeSubtext"] = "Create or join a room to start encrypted messaging.",
        ["EndToEndEncrypted"] = "End-to-End Encrypted",

        // ──────────────── Reactions ────────────────
        ["Reactions"] = "Reactions",
        ["AddReaction"] = "Add reaction",

        // ──────────────── View Once ────────────────
        ["ViewOnce"] = "View once",
        ["ViewOnceOpened"] = "Opened",
        ["ViewOnceNotOpened"] = "Not opened yet",

        // ──────────────── Bookmarks ────────────────
        ["Bookmark"] = "Bookmark",
        ["Bookmarks"] = "Bookmarks",
        ["RemoveBookmark"] = "Remove bookmark",
        ["NoBookmarks"] = "No bookmarks yet",

        // ──────────────── Voice Call ────────────────
        ["VoiceCall"] = "Voice Call",
        ["Calling"] = "Calling...",
        ["IncomingCall"] = "Incoming call",
        ["CallEnded"] = "Call ended",
        ["Answer"] = "Answer",
        ["Hangup"] = "Hang up",
        ["Mute"] = "Mute",
        ["Unmute"] = "Unmute",

        // ──────────────── Screen Share ────────────────
        ["ScreenShare"] = "Screen Share",
        ["StartScreenShare"] = "Start sharing",
        ["StopScreenShare"] = "Stop sharing",
        ["SharingScreen"] = "Sharing screen...",

        // ──────────────── Formatting & Display ────────────────
        ["Formatting"] = "Formatting",
        ["ShowTimestamps"] = "Show Timestamps",
        ["HideTimestamps"] = "Hide Timestamps",
        ["LinkPreview"] = "Link Preview",

        // ──────────────── Tor Circuits ────────────────
        ["TorCircuit"] = "Tor Circuit",
        ["TorCircuits"] = "Tor Circuits",
        ["Guard"] = "Guard",
        ["Middle"] = "Middle",
        ["Exit"] = "Exit",
        ["NoCircuits"] = "No active circuits",

        // ──────────────── Key Rotation ────────────────
        ["KeyRotation"] = "Key Rotation",
        ["KeysRotated"] = "Room keys have been rotated",
        ["RotateKeys"] = "Rotate Keys",
        ["RotationCount"] = "Rotation count",

        // ──────────────── Steganography ────────────────
        ["Steganography"] = "Steganography",
        ["EmbedMessage"] = "Embed message in image",
        ["ExtractMessage"] = "Extract message from image",
        ["StegoCapacity"] = "Capacity",
        ["StegoEmbed"] = "Embed",
        ["StegoExtract"] = "Extract",

        // ──────────────── Dead Drop ────────────────
        ["DeadDrop"] = "Dead Drop",
        ["DeadDrops"] = "Dead Drops",
        ["CreateDeadDrop"] = "Create dead drop",
        ["PickUpDrop"] = "Pick up",
        ["DropExpired"] = "Expired",
        ["RecipientFingerprint"] = "Recipient fingerprint",
        ["ExpiresIn"] = "Expires in",
        ["Hours"] = "hours",

        // ──────────────── Security & Privacy ────────────────
        ["DoubleRatchet"] = "Double Ratchet",
        ["DoubleRatchetDesc"] = "Forward secrecy with Signal protocol",
        ["PostQuantum"] = "Post-Quantum",
        ["PostQuantumDesc"] = "Quantum-resistant encryption layer",
        ["MultiLayerEncryption"] = "Multi-Layer Encryption",
        ["MultiLayerEncryptionDesc"] = "Double AES-256-GCM encryption",
        ["DeniableEncryption"] = "Deniable Encryption",
        ["DeniableEncryptionDesc"] = "Messages cannot be cryptographically attributed",
        ["TrafficObfuscation"] = "Traffic Obfuscation",
        ["TrafficObfuscationDesc"] = "Pad messages to hide real sizes",
        ["TimingProtection"] = "Timing Protection",
        ["TimingProtectionDesc"] = "Random delays to prevent timing analysis",
        ["RamOnlyMode"] = "RAM-Only Mode",
        ["RamOnlyModeDesc"] = "Messages never written to disk",
        ["DnsLeakProtection"] = "DNS Leak Protection",
        ["DnsLeakProtectionDesc"] = "Force all DNS through Tor",
        ["DeadManSwitch"] = "Dead Man's Switch",
        ["DeadManSwitchDesc"] = "Auto-wipe after inactivity period",
        ["DeadManSwitchDays"] = "Inactivity days before wipe",
        ["TamperDetection"] = "Tamper Detection",
        ["TamperDetectionDesc"] = "Detect debuggers and memory injection",
        ["IntegrityMonitoring"] = "Integrity Monitoring",
        ["IntegrityMonitoringDesc"] = "Verify application file hashes",
        ["CanaryTokens"] = "Canary Tokens",
        ["CanaryTokensDesc"] = "Hidden markers to detect data breaches",
        ["AutoMetadataStrip"] = "Auto Metadata Strip",
        ["AutoMetadataStripDesc"] = "Strip EXIF/metadata from all files",
        ["TorBridge"] = "Tor Bridge",
        ["TorBridgeDesc"] = "Use bridge relays to bypass censorship",
        ["BridgeLine"] = "Bridge Line",
        ["PluggableTransport"] = "Pluggable Transport",
        ["GuardPinning"] = "Guard Node Pinning",
        ["GuardPinningDesc"] = "Pin trusted Tor guard nodes",
        ["PinnedGuardNodes"] = "Pinned Guard Nodes",
        ["BruteForceProtection"] = "Brute Force Protection",
        ["MaxLoginAttempts"] = "Max Login Attempts",
        ["LockoutDuration"] = "Lockout Duration",
        ["ShamirSecretSharing"] = "Shamir's Secret Sharing",
        ["ShamirDesc"] = "Split password into recoverable shares",
        ["ZeroKnowledgeProof"] = "Zero-Knowledge Proof",
        ["ZKPDesc"] = "Prove room access without revealing password",
        ["AnonymousProfile"] = "Anonymous Profile",
        ["AnonymousProfileDesc"] = "Zero-information identity",
        ["SecureWipe"] = "Secure Wipe",
        ["SecureWipeDesc"] = "DoD 5220.22-M file deletion",
        ["MemoryProtection"] = "Memory Protection",
        ["MemoryProtectionDesc"] = "Encrypt sensitive data in RAM (DPAPI)",
        ["SecurityDashboard"] = "Security Dashboard",
        ["SecurityScore"] = "Security Score",
        ["SecurityAuditLog"] = "Security Audit Log",
        ["HomomorphicHash"] = "Homomorphic Hashing",
        ["HomomorphicHashDesc"] = "Verify integrity without leaking data",
        ["MultiHopCircuit"] = "Multi-Hop Circuit",
        ["OnionV3"] = "Onion v3 Addresses",
        ["CertificatePinning"] = "Certificate Pinning",
        ["CertificatePinningDesc"] = "Pin Tor relay certificates",
        ["Enabled"] = "Enabled",
        ["Disabled"] = "Disabled",
        ["SecuritySettings"] = "Security Settings",
        ["PrivacySettings"] = "Privacy Settings",
        ["NetworkSecurity"] = "Network Security",
        ["CryptoSettings"] = "Cryptography",
        ["DataProtection"] = "Data Protection",
        ["ThreatMonitoring"] = "Threat Monitoring",
        ["Advanced"] = "Advanced",

        // ──────────────── Auto-Update ────────────────
        ["UpdateAvailable"] = "Update Available",
        ["UpdateVersion"] = "Version {0} is available",
        ["UpdateNow"] = "Update Now",
        ["Downloading"] = "Downloading...",
        ["UpdateCancelled"] = "Update cancelled.",
        ["UpdateFailed"] = "Update failed",
        ["CurrentVersionLabel"] = "Current",
        ["NewVersionLabel"] = "New",

        // ──────────────── Join Room (Improved) ────────────────
        ["RoomIdOrInvite"] = "Room ID or Invite Link",
        ["PasteRoomIdOrInvite"] = "Paste room ID or tordex://join/... link",
        ["InviteLinkDetected"] = "Invite link detected",
        ["RoomNameOptional"] = "Room Name (optional)",
        ["RoomNameOptionalPlaceholder"] = "Display name for this room",
    }.ToFrozenDictionary(StringComparer.Ordinal);

    private static readonly FrozenDictionary<string, string> TrStrings = new Dictionary<string, string>
    {
        // ──────────────── Giriş / Profil ────────────────
        ["DisplayName"] = "Görünen Ad",
        ["Password"] = "Şifre",
        ["ConfirmPassword"] = "Şifreyi Onayla",
        ["CreateSecureProfile"] = "Güvenli Profil Oluştur",
        ["Unlock"] = "Kilidi Aç",
        ["MinChars"] = "Min. 8 karakter",
        ["RepeatPassword"] = "Şifreyi tekrarlayın",
        ["EnterYourPassword"] = "Şifrenizi girin",
        ["PasswordsDoNotMatch"] = "Şifreler eşleşmiyor",
        ["DisplayNameRequired"] = "Görünen ad gereklidir",
        ["PasswordMinLength"] = "Şifre en az 8 karakter olmalıdır",
        ["InvalidPassword"] = "Geçersiz şifre. Lütfen tekrar deneyin.",
        ["ProfileCorrupted"] = "Profil verileri bozulmuş.",

        // ──────────────── Ana Düzen ────────────────
        ["ConnectingToTor"] = "Tor'a bağlanılıyor...",
        ["TorConnected"] = "Tor Bağlandı",
        ["TorFailed"] = "Tor Başarısız",
        ["RetryConnection"] = "Bağlantıyı Tekrar Dene",
        ["ConnectToTorNetwork"] = "Tor Ağına Bağlan",
        ["NoRoomsYet"] = "Henüz oda yok.",
        ["CreateOrJoinRoom"] = "Sohbete başlamak için bir oda oluşturun veya katılın.",
        ["NewRoom"] = "Yeni Oda",
        ["JoinRoom"] = "Odaya Katıl",
        ["Settings"] = "Ayarlar",
        ["Unlocked"] = "Açık",
        ["Locked"] = "Kilitli",

        // ──────────────── Sohbet ────────────────
        ["TypeAMessage"] = "Bir mesaj yazın...",
        ["StartChatting"] = "Sohbete Başla",
        ["E2EEncryptionNotice"] = "Mesajlar AES-256-GCM ile uçtan uca şifrelenmiştir.",
        ["RoomPasswordNotice"] = "Yalnızca oda şifresine sahip üyeler okuyabilir.",
        ["RoomInformation"] = "Oda Bilgileri",
        ["DropFileHere"] = "Şifreli göndermek için dosyayı buraya bırakın",
        ["FileTooLarge"] = "Dosya çok büyük. Maksimum boyut 50 MB.",
        ["FailedToSend"] = "Gönderilemedi",
        ["Send"] = "Gönder",
        ["Reply"] = "Yanıtla",
        ["Edit"] = "Düzenle",
        ["Delete"] = "Sil",
        ["Forward"] = "İlet",
        ["Pin"] = "Sabitle",
        ["Unpin"] = "Sabitlemeyi Kaldır",
        ["Copy"] = "Kopyala",
        ["SearchMessages"] = "Mesajlarda ara...",
        ["MessageDeleted"] = "Bu mesaj silindi",
        ["Edited"] = "düzenlendi",
        ["PinnedMessages"] = "Sabitlenmiş Mesajlar",

        // ──────────────── Oda Diyalogları ────────────────
        ["CreateNewRoom"] = "Yeni Oda Oluştur",
        ["RoomName"] = "Oda Adı",
        ["RoomPassword"] = "Oda Şifresi",
        ["SharePasswordHint"] = "Bu şifreyi davet etmek istediğiniz kişilerle paylaşın.",
        ["RoomId"] = "Oda Kimliği",
        ["PasteRoomId"] = "Oda kimliğini yapıştırın",
        ["RoomDisplayName"] = "Oda görünen adı",
        ["RoomSharedPassword"] = "Oda paylaşılan şifresi",
        ["UnlockRoom"] = "Odanın Kilidini Aç",
        ["EnterPasswordFor"] = "Şifreyi girin:",
        ["DeleteRoom"] = "Odayı Sil",
        ["ConfirmDeleteRoom"] = "Silmek istediğinizden emin misiniz:",
        ["PermanentDeleteWarning"] = "Tüm mesajlar bu cihazdan kalıcı olarak silinecektir.",
        ["Cancel"] = "İptal",
        ["Close"] = "Kapat",
        ["Save"] = "Kaydet",

        // ──────────────── Ayarlar ────────────────
        ["YourFingerprint"] = "Parmak İziniz",
        ["FingerprintDescription"] = "Benzersiz kriptografik kimliğiniz.",
        ["PublicKey"] = "Açık Anahtar",
        ["SecurityInfo"] = "Güvenlik Bilgisi",
        ["Encryption"] = "Şifreleme",
        ["KeyDerivation"] = "Anahtar Türetme",
        ["KeyExchange"] = "Anahtar Değişimi",
        ["Signatures"] = "İmzalar",
        ["Network"] = "Ağ",
        ["SettingsSaved"] = "Ayarlar kaydedildi.",
        ["Language"] = "Dil",
        ["AutoLock"] = "Otomatik Kilitleme",
        ["Minutes"] = "dakika",
        ["Never"] = "Asla",
        ["ChangePassword"] = "Şifreyi Değiştir",
        ["CurrentPassword"] = "Mevcut Şifre",
        ["NewPassword"] = "Yeni Şifre",
        ["ConfirmNewPassword"] = "Yeni Şifreyi Onayla",
        ["PasswordChanged"] = "Şifre başarıyla değiştirildi.",
        ["NotificationSounds"] = "Bildirim Sesleri",
        ["ScreenCaptureProtection"] = "Ekran Görüntüsü Koruması",
        ["PanicButton"] = "Panik Butonu",
        ["DeleteAllData"] = "Tüm verileri hemen sil",
        ["CannotBeUndone"] = "Bu işlem geri alınamaz!",
        ["RoomDescription"] = "Oda Açıklaması",
        ["MaxCapacity"] = "Maksimum Kapasite",
        ["InviteLink"] = "Davet Bağlantısı",
        ["CopyAction"] = "Kopyala",
        ["Copied"] = "Kopyalandı!",

        // ──────────────── Güvenlik ────────────────
        ["BlockedUsers"] = "Engellenen Kullanıcılar",
        ["BlockUser"] = "Kullanıcıyı Engelle",
        ["Unblock"] = "Engeli Kaldır",
        ["NoBlockedUsers"] = "Engellenen kullanıcı yok",
        ["SelfDestructTimer"] = "Kendini imha zamanlayıcısı",
        ["Seconds"] = "saniye",
        ["VoiceMessage"] = "Sesli mesaj",
        ["Recording"] = "Kaydediliyor...",
        ["Typing"] = "Yazıyor...",
        ["Delivered"] = "İletildi",
        ["Read"] = "Okundu",
        ["WelcomeMessage"] = "tordeX'e Hoş Geldiniz",
        ["WelcomeSubtext"] = "Şifreli mesajlaşmaya başlamak için bir oda oluşturun veya katılın.",
        ["EndToEndEncrypted"] = "Uçtan Uca Şifreli",

        // ──────────────── Tepkiler ────────────────
        ["Reactions"] = "Tepkiler",
        ["AddReaction"] = "Tepki ekle",

        // ──────────────── Bir Kez Görüntüle ────────────────
        ["ViewOnce"] = "Bir kez görüntüle",
        ["ViewOnceOpened"] = "Görüntülendi",
        ["ViewOnceNotOpened"] = "Henüz görüntülenmedi",

        // ──────────────── Yer İmleri ────────────────
        ["Bookmark"] = "Yer İmi",
        ["Bookmarks"] = "Yer İmleri",
        ["RemoveBookmark"] = "Yer imini kaldır",
        ["NoBookmarks"] = "Henüz yer imi yok",

        // ──────────────── Sesli Arama ────────────────
        ["VoiceCall"] = "Sesli Arama",
        ["Calling"] = "Aranıyor...",
        ["IncomingCall"] = "Gelen arama",
        ["CallEnded"] = "Arama sona erdi",
        ["Answer"] = "Yanıtla",
        ["Hangup"] = "Kapat",
        ["Mute"] = "Sessiz",
        ["Unmute"] = "Sesi Aç",

        // ──────────────── Ekran Paylaşımı ────────────────
        ["ScreenShare"] = "Ekran Paylaşımı",
        ["StartScreenShare"] = "Paylaşımı başlat",
        ["StopScreenShare"] = "Paylaşımı durdur",
        ["SharingScreen"] = "Ekran paylaşılıyor...",

        // ──────────────── Biçimlendirme & Görüntüleme ────────────────
        ["Formatting"] = "Biçimlendirme",
        ["ShowTimestamps"] = "Zaman Damgalarını Göster",
        ["HideTimestamps"] = "Zaman Damgalarını Gizle",
        ["LinkPreview"] = "Bağlantı Önizleme",

        // ──────────────── Tor Devreleri ────────────────
        ["TorCircuit"] = "Tor Devresi",
        ["TorCircuits"] = "Tor Devreleri",
        ["Guard"] = "Koruma",
        ["Middle"] = "Orta",
        ["Exit"] = "Çıkış",
        ["NoCircuits"] = "Aktif devre yok",

        // ──────────────── Anahtar Rotasyonu ────────────────
        ["KeyRotation"] = "Anahtar Rotasyonu",
        ["KeysRotated"] = "Oda anahtarları yenilendi",
        ["RotateKeys"] = "Anahtarları Yenile",
        ["RotationCount"] = "Yenileme sayısı",

        // ──────────────── Steganografi ────────────────
        ["Steganography"] = "Steganografi",
        ["EmbedMessage"] = "Mesajı görsele göm",
        ["ExtractMessage"] = "Görselden mesaj çıkar",
        ["StegoCapacity"] = "Kapasite",
        ["StegoEmbed"] = "Göm",
        ["StegoExtract"] = "Çıkar",

        // ──────────────── Ölü Nokta ────────────────
        ["DeadDrop"] = "Ölü Nokta",
        ["DeadDrops"] = "Ölü Noktalar",
        ["CreateDeadDrop"] = "Ölü nokta oluştur",
        ["PickUpDrop"] = "Al",
        ["DropExpired"] = "Süresi doldu",
        ["RecipientFingerprint"] = "Alıcı parmak izi",
        ["ExpiresIn"] = "Bitiş süresi",
        ["Hours"] = "saat",

        // ──────────────── Güvenlik & Gizlilik ────────────────
        ["DoubleRatchet"] = "Çift Mandal",
        ["DoubleRatchetDesc"] = "Signal protokolü ile ileri gizlilik",
        ["PostQuantum"] = "Post-Kuantum",
        ["PostQuantumDesc"] = "Kuantum dayanıklı şifreleme katmanı",
        ["MultiLayerEncryption"] = "Çok Katmanlı Şifreleme",
        ["MultiLayerEncryptionDesc"] = "Çift AES-256-GCM şifreleme",
        ["DeniableEncryption"] = "İnkar Edilebilir Şifreleme",
        ["DeniableEncryptionDesc"] = "Mesajlar kriptografik olarak atfedilemez",
        ["TrafficObfuscation"] = "Trafik Gizleme",
        ["TrafficObfuscationDesc"] = "Gerçek boyutları gizlemek için mesaj dolgulama",
        ["TimingProtection"] = "Zamanlama Koruması",
        ["TimingProtectionDesc"] = "Zamanlama analizini önlemek için rastgele gecikmeler",
        ["RamOnlyMode"] = "Sadece RAM Modu",
        ["RamOnlyModeDesc"] = "Mesajlar diske hiç yazılmaz",
        ["DnsLeakProtection"] = "DNS Sızıntı Koruması",
        ["DnsLeakProtectionDesc"] = "Tüm DNS'i Tor üzerinden zorla",
        ["DeadManSwitch"] = "Ölü Adam Anahtarı",
        ["DeadManSwitchDesc"] = "Hareketsizlik sonrası otomatik silme",
        ["DeadManSwitchDays"] = "Silme öncesi hareketsizlik günü",
        ["TamperDetection"] = "Müdahale Tespiti",
        ["TamperDetectionDesc"] = "Hata ayıklayıcı ve bellek enjeksiyonu tespiti",
        ["IntegrityMonitoring"] = "Bütünlük İzleme",
        ["IntegrityMonitoringDesc"] = "Uygulama dosya hash doğrulaması",
        ["CanaryTokens"] = "Kanarya Jetonları",
        ["CanaryTokensDesc"] = "Veri ihlalini tespit eden gizli işaretçiler",
        ["AutoMetadataStrip"] = "Otomatik Metadata Temizleme",
        ["AutoMetadataStripDesc"] = "Tüm dosyalardan EXIF/metadata temizle",
        ["TorBridge"] = "Tor Köprüsü",
        ["TorBridgeDesc"] = "Sansürü atlamak için köprü aktarıcıları kullan",
        ["BridgeLine"] = "Köprü Satırı",
        ["PluggableTransport"] = "Takılabilir Aktarım",
        ["GuardPinning"] = "Koruma Düğümü Sabitleme",
        ["GuardPinningDesc"] = "Güvenilen Tor koruma düğümlerini sabitle",
        ["PinnedGuardNodes"] = "Sabitlenmiş Koruma Düğümleri",
        ["BruteForceProtection"] = "Kaba Kuvvet Koruması",
        ["MaxLoginAttempts"] = "Maksimum Giriş Denemesi",
        ["LockoutDuration"] = "Kilitleme Süresi",
        ["ShamirSecretSharing"] = "Shamir Gizli Paylaşımı",
        ["ShamirDesc"] = "Şifreyi kurtarılabilir parçalara böl",
        ["ZeroKnowledgeProof"] = "Sıfır Bilgi Kanıtı",
        ["ZKPDesc"] = "Şifreyi açıklamadan oda erişimini kanıtla",
        ["AnonymousProfile"] = "Anonim Profil",
        ["AnonymousProfileDesc"] = "Sıfır bilgi kimliği",
        ["SecureWipe"] = "Güvenli Silme",
        ["SecureWipeDesc"] = "DoD 5220.22-M dosya silme",
        ["MemoryProtection"] = "Bellek Koruması",
        ["MemoryProtectionDesc"] = "Hassas verileri RAM'de şifrele (DPAPI)",
        ["SecurityDashboard"] = "Güvenlik Paneli",
        ["SecurityScore"] = "Güvenlik Puanı",
        ["SecurityAuditLog"] = "Güvenlik Denetim Günlüğü",
        ["HomomorphicHash"] = "Homomorfik Hashleme",
        ["HomomorphicHashDesc"] = "Veri sızdırmadan bütünlük doğrulama",
        ["MultiHopCircuit"] = "Çoklu Atlama Devresi",
        ["OnionV3"] = "Onion v3 Adresleri",
        ["CertificatePinning"] = "Sertifika Sabitleme",
        ["CertificatePinningDesc"] = "Tor aktarıcı sertifikalarını sabitle",
        ["Enabled"] = "Etkin",
        ["Disabled"] = "Devre Dışı",
        ["SecuritySettings"] = "Güvenlik Ayarları",
        ["PrivacySettings"] = "Gizlilik Ayarları",
        ["NetworkSecurity"] = "Ağ Güvenliği",
        ["CryptoSettings"] = "Kriptografi",
        ["DataProtection"] = "Veri Koruma",
        ["ThreatMonitoring"] = "Tehdit İzleme",
        ["Advanced"] = "Gelişmiş",

        // ──────────────── Otomatik Güncelleme ────────────────
        ["UpdateAvailable"] = "Güncelleme Mevcut",
        ["UpdateVersion"] = "Sürüm {0} mevcut",
        ["UpdateNow"] = "Şimdi Güncelle",
        ["Downloading"] = "İndiriliyor...",
        ["UpdateCancelled"] = "Güncelleme iptal edildi.",
        ["UpdateFailed"] = "Güncelleme başarısız",
        ["CurrentVersionLabel"] = "Mevcut",
        ["NewVersionLabel"] = "Yeni",

        // ──────────────── Odaya Katıl (Gelişmiş) ────────────────
        ["RoomIdOrInvite"] = "Oda Kimliği veya Davet Bağlantısı",
        ["PasteRoomIdOrInvite"] = "Oda kimliği veya tordex://join/... bağlantısı yapıştırın",
        ["InviteLinkDetected"] = "Davet bağlantısı algılandı",
        ["RoomNameOptional"] = "Oda Adı (isteğe bağlı)",
        ["RoomNameOptionalPlaceholder"] = "Bu oda için görünen ad",
    }.ToFrozenDictionary(StringComparer.Ordinal);

    private static readonly FrozenDictionary<string, FrozenDictionary<string, string>> Languages =
        new Dictionary<string, FrozenDictionary<string, string>>(StringComparer.OrdinalIgnoreCase)
        {
            ["en"] = EnStrings,
            ["tr"] = TrStrings,
        }.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Gets or sets the current language code ("en" or "tr").
    /// Defaults to "en". Thread-safe via volatile field.
    /// </summary>
    public static string CurrentLanguage
    {
        get => _currentLanguage;
        set
        {
            var normalized = (value ?? "en").Trim().ToLowerInvariant();
            if (!Languages.ContainsKey(normalized))
                normalized = "en";
            _currentLanguage = normalized;
        }
    }

    /// <summary>
    /// Gets the available language codes.
    /// </summary>
    public static IReadOnlyList<string> AvailableLanguages { get; } = ["en", "tr"];

    /// <summary>
    /// Translates the given key to the current language.
    /// Returns the key itself if no translation is found.
    /// </summary>
    /// <param name="key">The localization key.</param>
    /// <returns>The translated string, or the key if not found.</returns>
    public static string T(string key)
    {
        if (string.IsNullOrEmpty(key))
            return string.Empty;

        if (Languages.TryGetValue(_currentLanguage, out var dict) && dict.TryGetValue(key, out var value))
            return value;

        // Fallback to English
        if (EnStrings.TryGetValue(key, out var fallback))
            return fallback;

        // Key not found in any dictionary — return the key itself as last resort
        return key;
    }
}
