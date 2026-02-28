<div align="center">

<img src="logo.png" alt="tordeX" width="200" />

# tordeX

### Decentralized End-to-End Encrypted Messenger Over Tor

[![.NET 9](https://img.shields.io/badge/.NET-9.0-512BD4?style=flat-square&logo=dotnet)](https://dotnet.microsoft.com/)
[![Blazor Hybrid](https://img.shields.io/badge/Blazor-Hybrid-512BD4?style=flat-square&logo=blazor)](https://learn.microsoft.com/aspnet/core/blazor/hybrid/)
[![Tor Network](https://img.shields.io/badge/Tor-Onion%20v3-7D4698?style=flat-square&logo=torproject)](https://www.torproject.org/)
[![SQLCipher](https://img.shields.io/badge/SQLCipher-AES--256-green?style=flat-square)](https://www.zetetic.net/sqlcipher/)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=flat-square&logo=windows)](https://github.com/eros1sh/tordeX/releases)

**No servers. No metadata. No compromise.**

tordeX is a fully decentralized, peer-to-peer encrypted messaging application that routes all communication through the Tor network. Built from the ground up with 32+ security features, military-grade cryptography, and zero-trust architecture.

[Features](#-features) | [Security](#-security-architecture) | [Install](#-installation) | [Build](#%EF%B8%8F-building-from-source) | [Architecture](#-architecture) | [Screenshots](#-screenshots)

</div>

---

## Why tordeX?

Most "encrypted" messengers still rely on central servers, collect metadata, and require phone numbers or emails. **tordeX eliminates all of that.**

| | tordeX | Signal | Telegram | WhatsApp |
|---|:---:|:---:|:---:|:---:|
| **E2E Encryption** | AES-256-GCM | Signal Protocol | Optional | Signal Protocol |
| **Decentralized** | Fully P2P | Central servers | Central servers | Central servers |
| **Tor Routed** | All traffic | No | No | No |
| **No Phone/Email** | Anonymous | Phone required | Phone required | Phone required |
| **No Metadata** | Zero collection | Minimal | Extensive | Extensive |
| **Open Source** | Full stack | Client only | Client only | No |
| **Post-Quantum** | Lattice-based | No | No | No |
| **RAM-Only Mode** | Available | No | No | No |
| **Anti-Forensics** | DoD 5220.22-M | No | No | No |

---

## Key Features

### Communication
- **Encrypted Text Messaging** - AES-256-GCM with per-message keys
- **Encrypted Voice Messages** - Record, encrypt (AES-256-GCM), send via Tor, playback with waveform
- **Encrypted Image Sharing** - Full metadata stripping before transmission
- **Encrypted File Transfer** - Any file type, zero metadata leakage
- **Disappearing Messages** - Client-enforced TTL (5–300 seconds), auto-delete from database
- **View-Once Messages** - Self-destructing images and media
- **Message Reactions** - Express yourself without compromising privacy
- **Markdown Support** - Rich text formatting with **bold**, *italic*, `code`, and more
- **Link Previews** - Safe URL previewing with metadata protection
- **Message Bookmarks** - Save important messages locally (encrypted)
- **Emoji Picker** - Full emoji support with categorized picker
- **Typing Indicators** - Real-time presence (over Tor)
- **P2P Message Delivery** - Real-time via Tor hidden services (ephemeral onion addresses)

### Room System
- **Password-Protected Rooms** - PBKDF2-SHA512 derived room keys (600K iterations)
- **Room Descriptions** - Describe your room's purpose
- **Room Capacity Limits** - Control maximum participants
- **User Blocking** - Block users by cryptographic fingerprint
- **Dead Drops** - Anonymous async message exchange via onion addresses
- **Steganography** - Hide encrypted messages inside innocent-looking images

### Security & Privacy (32 Features)
See [Security Architecture](#-security-architecture) below for the complete breakdown.

### User Experience
- **Dark Theme UI** - Purple accent, eye-friendly dark interface
- **System Tray** - Minimize to tray, background operation
- **Desktop Notifications** - Content-hidden native Windows notifications
- **Multi-Language** - English and Turkish (extensible i18n system)
- **Auto-Lock** - Configurable inactivity timeout
- **Timestamp Toggle** - Show/hide message timestamps

---

## Security Architecture

tordeX implements defense-in-depth with 32 dedicated security services across 5 layers:

### Layer 1: Encryption & Cryptography

| Feature | Implementation | Purpose |
|---------|---------------|---------|
| **Double Ratchet Protocol** | HKDF-SHA256 key chains | Forward secrecy - compromised keys can't decrypt past messages |
| **Post-Quantum Cryptography** | Lattice-based KEM (Kyber-inspired, q=12289) | Resistance against quantum computer attacks |
| **Multi-Layer Encryption** | Sequential dual AES-256-GCM | Defense-in-depth - two independent encryption layers |
| **Auto Key Rotation** | Ephemeral keys with message/lifetime limits | Limits exposure window if a key is compromised |
| **Ephemeral Keys** | ECDH P-256 per-session keys | Zero long-term key exposure |
| **Deniable Encryption** | OTR-style HMAC-SHA256 deniability | Cryptographic plausible deniability |
| **Zero-Knowledge Proofs** | Schnorr ZKP for room access | Prove room password knowledge without revealing it |
| **Shamir's Secret Sharing** | GF(256) polynomial splitting | Distribute keys across N parties, recover with K threshold |
| **Homomorphic Hashing** | Merkle tree integrity proofs | Verify data integrity without exposing content |

### Layer 2: Network Security

| Feature | Implementation | Purpose |
|---------|---------------|---------|
| **Multi-Hop Tor Circuits** | Onion v3 hidden services | 3+ relay hops, geographic diversity |
| **Bridge & Pluggable Transports** | obfs4, meek, snowflake | Bypass censorship in restricted regions |
| **Guard Node Pinning** | Configurable fingerprint pinning | Prevent Sybil attacks on entry nodes |
| **Traffic Obfuscation** | PKCS7 padding + decoy packets | Prevent traffic analysis and fingerprinting |
| **DNS Leak Protection** | System-level DNS monitoring | Ensure all DNS goes through Tor |
| **WebRTC Leak Prevention** | Protocol-level blocking | Prevent IP exposure via WebRTC |
| **Timing Attack Protection** | Constant-time comparisons + random delays | Defeat timing-based side channels |
| **Certificate Pinning** | SHA-256 public key pinning | Prevent MITM via compromised CAs |

### Layer 3: Identity & Access

| Feature | Implementation | Purpose |
|---------|---------------|---------|
| **Anonymous Profiles** | Cryptographic identity only | No PII required - ever |
| **IP Masking** | Tor-only networking | Real IP never exposed to peers |
| **Brute Force Protection** | Rate limiting + exponential lockout | Prevent credential stuffing attacks |

### Layer 4: Data Protection

| Feature | Implementation | Purpose |
|---------|---------------|---------|
| **Dead Man's Switch** | Configurable inactivity auto-wipe | Destroy all data after N days of inactivity |
| **RAM-Only Mode** | In-memory message storage, zero disk writes | Leave no forensic trace on disk |
| **Secure File Deletion** | DoD 5220.22-M (3-pass overwrite) | Military-standard anti-forensic deletion |
| **Memory Protection (DPAPI)** | Windows Data Protection API | Encrypt sensitive data in RAM against cold-boot attacks |
| **Screenshot Prevention** | DRM flag on application window | Prevent screen capture of conversations |
| **Metadata Stripping** | EXIF, PDF, DOCX, MP4 cleaning | Remove all identifying metadata before sending |

### Layer 5: Threat Monitoring

| Feature | Implementation | Purpose |
|---------|---------------|---------|
| **Canary Tokens** | Hidden database markers | Detect unauthorized database access |
| **Integrity Monitoring** | SHA-256 file manifests | Detect tampering with application files |
| **Tamper Detection** | Anti-debug P/Invoke checks | Detect debuggers and memory analysis tools |
| **Security Audit Log** | Structured event logging | Full audit trail of security-relevant events |

### Encryption Flow

```
Sender                                                 Receiver
  │                                                       │
  │  1. Generate ephemeral ECDH P-256 keypair             │
  │  2. Derive shared secret (ECDH + HKDF-SHA256)         │
  │  3. Double Ratchet: advance chain key                  │
  │  4. Encrypt: AES-256-GCM (Layer 1)                    │
  │  5. Encrypt: AES-256-GCM (Layer 2 - independent key)  │
  │  6. Pad: PKCS7 traffic obfuscation                     │
  │  7. Sign: ECDSA P-256                                  │
  │  8. Route: Tor onion v3 (3+ hops)                      │
  │ ──────────────── Tor Circuit ──────────────────────►   │
  │                                                        │
  │                  9. Verify: ECDSA P-256 signature      │
  │                 10. Unpad: Remove PKCS7 padding        │
  │                 11. Decrypt: AES-256-GCM (Layer 2)     │
  │                 12. Decrypt: AES-256-GCM (Layer 1)     │
  │                 13. Ratchet: Advance receiver chain     │
  │                 14. Store: SQLCipher encrypted DB       │
  │                                                        │
```

### Key Derivation

```
Room Password
     │
     ▼
PBKDF2-SHA512 (600,000 iterations) + random salt
     │
     ▼
256-bit Room Key ──► AES-256-GCM encryption
     │
     ▼
ECDH P-256 Key Exchange ──► Per-session ephemeral keys
     │
     ▼
HKDF-SHA256 ──► Double Ratchet chain keys (forward secrecy)
```

---

## Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Runtime** | .NET 9 | Modern, high-performance, cross-platform |
| **UI Framework** | WPF + Blazor Hybrid (WebView2) | Native desktop with web UI flexibility |
| **Cryptography** | NSec (libsodium) | Audited, high-performance crypto primitives |
| **Database** | SQLCipher (AES-256) | Encrypted-at-rest SQLite |
| **Serialization** | MessagePack | Compact binary protocol |
| **Networking** | TorSharp 2.15.0 | Managed Tor SOCKS5 proxy |
| **Memory Protection** | Windows DPAPI | In-RAM data encryption |
| **Notifications** | WPF Toolkit | Native Windows toast notifications |
| **Testing** | xUnit + Coverlet | Unit testing with code coverage |

---

## Installation

### Pre-built Binary (Windows)

1. Download the latest release from [Releases](https://github.com/eros1sh/tordeX/releases)
2. Extract `tordeX.exe` to your preferred location
3. Run `tordeX.exe` - Tor binaries are downloaded automatically on first launch
4. Create a profile with a strong password

> **Note:** The self-contained EXE (~192MB) includes the .NET runtime. No additional dependencies required.

### Requirements

- Windows 10 (build 19041) or later
- WebView2 Runtime (usually pre-installed on Windows 10/11)
- Internet connection for initial Tor bootstrap

---

## Building from Source

### Prerequisites

- [.NET 9 SDK](https://dotnet.microsoft.com/download/dotnet/9.0)
- Windows 10 SDK (19041+)
- Git

### Clone & Build

```bash
git clone https://github.com/eros1sh/tordeX.git
cd tordeX
dotnet restore
dotnet build
```

### Run (Debug)

```bash
dotnet run --project src/tordeX.Desktop/tordeX.Desktop.csproj
```

### Publish (Self-Contained Release)

```bash
dotnet publish src/tordeX.Desktop/tordeX.Desktop.csproj \
  -c Release \
  --self-contained \
  -r win-x64 \
  -p:PublishSingleFile=true \
  -o publish
```

### Run Tests

```bash
dotnet test src/tordeX.Tests/tordeX.Tests.csproj
```

---

## Architecture

### System Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                        tordeX.Desktop                             │
│                   WPF + Blazor Hybrid (WebView2)                  │
│  ┌──────────┐  ┌────────────┐  ┌──────────┐  ┌──────────────┐   │
│  │ LoginPage│  │ MainLayout │  │ ChatView │  │ EmojiPicker  │   │
│  └──────────┘  └────────────┘  └──────────┘  └──────────────┘   │
└────────────────────────┬─────────────────────────────────────────┘
                         │
┌────────────────────────┴─────────────────────────────────────────┐
│                         tordeX.Core                               │
│                                                                   │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │  Cryptography   │  │    Network      │  │    Storage      │  │
│  │                 │  │                 │  │                 │  │
│  │ - KeyDerivation │  │ - TorManager    │  │ - SecureDatabase│  │
│  │ - KeyExchange   │  │ - P2PServer     │  │   (SQLCipher)   │  │
│  │ - MessageEncrypt│  │ - PeerConnection│  │                 │  │
│  │ - IdentityMgr   │  │                 │  │                 │  │
│  │ - SecureRandom  │  │                 │  │                 │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘  │
│                                                                   │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │                   Services (29 modules)                    │   │
│  │                                                            │   │
│  │  CRYPTO            NETWORK           DATA PROTECTION       │   │
│  │  DoubleRatchet     TorCircuitMgr     BruteForceProtect    │   │
│  │  PostQuantum       TrafficObfusc     DeadManSwitch        │   │
│  │  MultiLayerEnc     NetworkLeak       RamOnlyMode          │   │
│  │  EphemeralKey      TimingProtect     SecureWipe           │   │
│  │  DeniableEnc       CertPinning       MemoryProtect        │   │
│  │  ZeroKnowledge                       MetadataStrip        │   │
│  │  ShamirSecret      MONITORING        Privacy              │   │
│  │  HomomorphicHash   CanaryToken       Steganography        │   │
│  │                    IntegrityMon      Markdown             │   │
│  │                    TamperDetect      Localization         │   │
│  │                    SecurityAudit                           │   │
│  └───────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
                         │
              ┌──────────┴──────────┐
              │                     │
        ┌─────▼─────┐        ┌─────▼─────┐
        │    Tor     │        │ SQLCipher  │
        │  (SOCKS5)  │        │    (DB)    │
        │  Onion v3  │        │  AES-256   │
        └───────────┘        └───────────┘
```

### Project Structure

```
tordeX/
├── logo.png                          # Project branding
├── tordeX.sln                        # Visual Studio solution
├── README.md                         # This file
│
└── src/
    ├── tordeX.Core/                  # Core library (.NET 9)
    │   ├── Cryptography/             # Crypto primitives
    │   │   ├── IdentityManager.cs    # ECDSA P-256 identity keypairs
    │   │   ├── KeyDerivation.cs      # PBKDF2-SHA512 key derivation
    │   │   ├── KeyExchange.cs        # ECDH P-256 key agreement
    │   │   ├── MessageEncryption.cs  # AES-256-GCM encrypt/decrypt
    │   │   └── SecureRandom.cs       # CSPRNG entropy source
    │   │
    │   ├── Network/                  # P2P networking
    │   │   ├── TorManager.cs         # Tor lifecycle management
    │   │   ├── P2PServer.cs          # Onion service listener
    │   │   └── PeerConnection.cs     # SOCKS5 peer connections
    │   │
    │   ├── Storage/
    │   │   └── SecureDatabase.cs     # SQLCipher encrypted storage
    │   │
    │   ├── Models/                   # Domain models (9)
    │   │   ├── ChatMessage.cs        # Encrypted messages
    │   │   ├── ChatRoom.cs           # Password-protected rooms
    │   │   ├── UserProfile.cs        # Local profile (32 security fields)
    │   │   ├── DeadDrop.cs           # Async anonymous exchange
    │   │   ├── TorCircuitInfo.cs     # Tor circuit topology
    │   │   └── ...
    │   │
    │   └── Services/                 # Security services (29)
    │       ├── ChatService.cs        # Main orchestrator
    │       ├── DoubleRatchetService.cs
    │       ├── PostQuantumCryptoService.cs
    │       ├── MultiLayerEncryptionService.cs
    │       ├── EphemeralKeyService.cs
    │       ├── DeniableEncryptionService.cs
    │       ├── ZeroKnowledgeProofService.cs
    │       ├── ShamirSecretService.cs
    │       ├── HomomorphicHashService.cs
    │       ├── TorCircuitManagerService.cs
    │       ├── TrafficObfuscationService.cs
    │       ├── NetworkLeakProtectionService.cs
    │       ├── TimingProtectionService.cs
    │       ├── CertificatePinningService.cs
    │       ├── BruteForceProtectionService.cs
    │       ├── DeadManSwitchService.cs
    │       ├── RamOnlyModeService.cs
    │       ├── SecureWipeService.cs
    │       ├── MemoryProtectionService.cs
    │       ├── ExtendedMetadataStripperService.cs
    │       ├── PrivacyService.cs
    │       ├── CanaryTokenService.cs
    │       ├── IntegrityMonitorService.cs
    │       ├── TamperDetectionService.cs
    │       ├── SecurityAuditService.cs
    │       ├── SteganographyService.cs
    │       ├── MarkdownService.cs
    │       ├── MetadataStripperService.cs
    │       └── LocalizationService.cs
    │
    ├── tordeX.Desktop/               # WPF Blazor Hybrid UI
    │   ├── Pages/
    │   │   ├── LoginPage.razor       # Authentication
    │   │   ├── Main.razor            # App entry point
    │   │   └── MainLayout.razor      # Layout + settings
    │   ├── Components/
    │   │   ├── ChatView.razor        # Chat interface
    │   │   └── EmojiPicker.razor     # Emoji selection
    │   ├── wwwroot/
    │   │   ├── css/app.css           # UI styles
    │   │   └── img/logo.png          # App logo
    │   ├── App.xaml                   # WPF application
    │   └── MainWindow.xaml            # Host window
    │
    └── tordeX.Tests/                 # xUnit test suite
        └── tordeX.Tests.csproj
```

---

## Data Storage

All data is stored locally in `%APPDATA%/tordeX/`:

```
%APPDATA%/tordeX/
├── tordeX.db          # SQLCipher encrypted database (AES-256)
├── salt.bin           # PBKDF2 salt (random, per-installation)
└── tor/               # Tor binaries (auto-downloaded)
    ├── tor.exe
    └── ...
```

### Database Schema

| Table | Purpose | Encryption |
|-------|---------|------------|
| `user_profile` | Local identity, settings, 19 security flags | SQLCipher AES-256 |
| `chat_rooms` | Room metadata, derived keys | SQLCipher + room key encryption |
| `messages` | Encrypted messages per room | SQLCipher + E2E AES-256-GCM |
| `blocked_users` | Blocked fingerprints | SQLCipher AES-256 |
| `bookmarks` | Saved messages | SQLCipher AES-256 |
| `canary_tokens` | Breach detection markers | SQLCipher AES-256 |
| `security_audit_log` | Security event trail | SQLCipher AES-256 |
| `integrity_manifest` | File hash manifests | SQLCipher AES-256 |

---

## Security Settings

tordeX provides granular security controls through the Settings panel:

### Cryptography
- Double Ratchet (forward secrecy) - **ON by default**
- Post-Quantum Encryption - optional
- Multi-Layer Encryption - optional
- Deniable Encryption - optional

### Network
- Traffic Obfuscation - **ON by default**
- Timing Protection - **ON by default**
- DNS Leak Protection - **ON by default**
- Tor Bridge Configuration (obfs4/meek/snowflake)
- Guard Node Pinning

### Data Protection
- Dead Man's Switch (configurable: 1-365 days)
- RAM-Only Mode (zero disk writes)
- Auto Metadata Stripping - **ON by default**
- Brute Force Protection (configurable max attempts)

### Monitoring
- Tamper Detection - **ON by default**
- Integrity Monitoring - **ON by default**
- Canary Tokens - **ON by default**

---

## Threat Model

### Assets Protected
- Message content and metadata
- User identity and IP address
- Contact lists and room memberships
- Encryption keys and session state
- Local database and files

### Trust Boundaries

```
┌─────────────────────────────────────────────┐
│              User's Machine                  │
│  ┌────────────┐     ┌───────────────────┐   │
│  │  tordeX    │ ←──►│  SQLCipher DB     │   │
│  │  (process) │     │  (encrypted)      │   │
│  └──────┬─────┘     └───────────────────┘   │
│         │                                    │
│         │ SOCKS5                             │
│  ┌──────▼─────┐                              │
│  │  Tor Proxy │                              │
│  └──────┬─────┘                              │
└─────────┼───────────────────────────────────┘
          │ Onion v3
┌─────────▼───────────────────────────────────┐
│              Tor Network                     │
│  Guard → Middle → Exit/Rendezvous            │
└─────────┬───────────────────────────────────┘
          │
┌─────────▼───────────────────────────────────┐
│              Peer's Machine                  │
│  (Same architecture, reverse direction)      │
└─────────────────────────────────────────────┘
```

### STRIDE Analysis

| Threat | Vector | Mitigation |
|--------|--------|------------|
| **Spoofing** | Impersonating a peer | ECDSA P-256 signatures on all messages |
| **Tampering** | Modifying messages in transit | AES-256-GCM authenticated encryption (AEAD) |
| **Repudiation** | Denying sent messages | Deniable encryption mode (intentional) + audit logs |
| **Info Disclosure** | Extracting message content | Multi-layer E2E encryption + Tor routing |
| **Denial of Service** | Flooding a peer | Rate limiting + brute force protection |
| **Elevation** | Accessing other rooms | Per-room PBKDF2 derived keys + ZKP access |

---

## Localization

tordeX supports multiple languages via a built-in i18n system:

| Language | Code | Status |
|----------|------|--------|
| English | `en` | Complete |
| Turkish | `tr` | Complete |

Adding a new language requires adding entries to `LocalizationService.cs`. PRs welcome.

---

## Contributing

Contributions are welcome. Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- All code must compile with **zero warnings** (`<TreatWarningsAsErrors>true</TreatWarningsAsErrors>`)
- Nullable reference types are **always enabled**
- Security-critical code must include inline comments explaining the rationale
- New cryptographic features must reference their academic papers/standards

---

## Security Disclosure

Found a vulnerability? **Please report responsibly.**

- **DO NOT** open public issues for security vulnerabilities
- Contact: Open a private security advisory on GitHub
- PGP-encrypted reports preferred

We take all security reports seriously and will respond within 48 hours.

---

## Roadmap

### Completed
- [x] Encrypted text messaging (AES-256-GCM)
- [x] Tor integration (onion v3 hidden services)
- [x] Room-based access (PBKDF2-SHA512)
- [x] Encrypted image/file sharing
- [x] View-once messages
- [x] Message reactions & bookmarks
- [x] Markdown rendering
- [x] Double Ratchet forward secrecy
- [x] Post-quantum cryptography
- [x] Multi-layer encryption
- [x] Traffic obfuscation
- [x] DNS/WebRTC leak protection
- [x] RAM-only mode
- [x] Dead Man's Switch
- [x] Secure file deletion (DoD 5220.22-M)
- [x] Memory protection (DPAPI)
- [x] Tamper detection
- [x] Canary tokens
- [x] Steganography
- [x] Zero-knowledge proofs
- [x] Shamir's Secret Sharing
- [x] Bridge/pluggable transport support
- [x] Multi-language (EN/TR)

### Recently Completed
- [x] Voice messages (encrypted) — MediaRecorder + AES-256-GCM + Web Audio playback
- [x] Disappearing messages with client-enforced TTL — auto-delete timer (5–300s)
- [x] P2P message delivery via Tor hidden services — ephemeral onion addresses
- [x] Auto-update from GitHub Releases — download + apply + restart

### Planned
- [ ] Linux native build (Photino.Blazor)
- [ ] Android (MAUI)
- [ ] iOS (PWA/MAUI)
- [ ] Group video calls (E2E)
- [ ] Hardware key support (YubiKey/FIDO2)
- [ ] Decentralized room discovery (DHT)
- [ ] Plugin system for custom security modules

---

## License

This project is licensed under the **GNU General Public License v3.0** - see the [LICENSE](LICENSE) file for details.

---

## Disclaimer

This software is provided for **educational and privacy research purposes**. It is experimental and under active development. The developers assume no liability for data loss, privacy breaches, or any damages resulting from its use.

**Use at your own risk. Know your local laws regarding encryption and anonymous communication.**

---

<div align="center">

Built with paranoia by [eros1sh](https://github.com/eros1sh)

<img src="logo.png" alt="tordeX" width="60" />

*Privacy is not a privilege. It's a right.*

</div>
