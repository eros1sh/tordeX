using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace TordeX.Core.Services;

/// <summary>
/// Represents a Schnorr zero-knowledge proof consisting of commitment, challenge, and response.
/// Used to prove knowledge of a secret (e.g., room password) without revealing it.
/// </summary>
/// <param name="Commitment">The commitment point R = r*G serialized as SPKI bytes.</param>
/// <param name="Challenge">The Fiat-Shamir challenge c = SHA-256(R || publicInfo).</param>
/// <param name="Response">The response s = (r + c * secret) mod n.</param>
public sealed record ZKProof(byte[] Commitment, byte[] Challenge, byte[] Response);

/// <summary>
/// Schnorr-based zero-knowledge proof service for proving room access
/// without revealing the room password.
/// <para>
/// Uses ECDSA P-256 curve operations with the Fiat-Shamir heuristic for
/// non-interactive proofs. The prover demonstrates knowledge of a discrete
/// logarithm (derived from a password) without revealing the secret itself.
/// </para>
/// <para>
/// Protocol flow:
/// 1. Prover derives scalar secret from password via HKDF
/// 2. Prover generates random nonce r, computes commitment R = r*G
/// 3. Challenge c = SHA-256(R || publicInfo) [Fiat-Shamir]
/// 4. Response s = r + c * secret (mod n)
/// 5. Verifier checks: s*G == R + c*P where P = secret*G is the public key
/// </para>
/// </summary>
public static class ZeroKnowledgeProofService
{
    /// <summary>
    /// The order of the P-256 curve group (number of points on the curve).
    /// NIST P-256 order n.
    /// </summary>
    private static readonly BigInteger CurveOrder = BigInteger.Parse(
        "115792089210356248762697446949407573529996955224135760342422259061068512044369");

    private static readonly byte[] ProofDomainInfo =
        Encoding.UTF8.GetBytes("tordeX-zkp-proof-v1");

    private static readonly byte[] RoomAccessDomainInfo =
        Encoding.UTF8.GetBytes("tordeX-zkp-room-access-v1");

    /// <summary>
    /// Generates a Schnorr zero-knowledge proof of knowledge of <paramref name="secret"/>.
    /// </summary>
    /// <param name="secret">The secret value (e.g., derived from a password). Must not be empty.</param>
    /// <param name="publicInfo">Public context information bound into the challenge (e.g., room ID, salt).</param>
    /// <returns>A <see cref="ZKProof"/> that proves knowledge of <paramref name="secret"/>.</returns>
    public static ZKProof GenerateProof(byte[] secret, byte[] publicInfo)
    {
        ArgumentNullException.ThrowIfNull(secret);
        ArgumentNullException.ThrowIfNull(publicInfo);
        if (secret.Length == 0)
            throw new ArgumentException("Secret cannot be empty.", nameof(secret));

        // Derive a scalar from the secret that is within the curve order
        var secretScalar = DeriveScalar(secret);

        // Generate random nonce r
        var nonceBytes = RandomNumberGenerator.GetBytes(32);
        var nonceScalar = DeriveScalar(nonceBytes);

        // Compute commitment R = r*G by creating an ECDsa key pair with nonce as private key
        var commitmentPoint = ScalarMultiplyBasePoint(nonceScalar);

        // Compute public key P = secret*G
        var publicPoint = ScalarMultiplyBasePoint(secretScalar);

        // Fiat-Shamir challenge: c = H(R || publicInfo || P)
        var challengeBytes = ComputeChallenge(commitmentPoint, publicInfo, publicPoint);
        var challengeScalar = BytesToBigInteger(challengeBytes);

        // Response: s = (r + c * secret) mod n
        var responseScalar = BigInteger.ModPow(BigInteger.One, 1, CurveOrder); // identity
        responseScalar = (nonceScalar + challengeScalar * secretScalar) % CurveOrder;
        if (responseScalar < 0) responseScalar += CurveOrder;

        var responseBytes = BigIntegerToBytes(responseScalar);

        CryptographicOperations.ZeroMemory(nonceBytes);

        return new ZKProof(commitmentPoint, challengeBytes, responseBytes);
    }

    /// <summary>
    /// Verifies a Schnorr zero-knowledge proof against a public key and public information.
    /// Checks that s*G == R + c*P.
    /// </summary>
    /// <param name="proof">The proof to verify.</param>
    /// <param name="publicKey">The prover's public key (SPKI-encoded EC point = secret*G).</param>
    /// <param name="publicInfo">The public context information that was bound into the challenge.</param>
    /// <returns><c>true</c> if the proof is valid.</returns>
    public static bool VerifyProof(ZKProof proof, byte[] publicKey, byte[] publicInfo)
    {
        ArgumentNullException.ThrowIfNull(proof);
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(publicInfo);

        try
        {
            // Recompute challenge from the commitment and public info
            var expectedChallenge = ComputeChallenge(proof.Commitment, publicInfo, publicKey);

            // Verify the challenge matches (prevents proof transplant attacks)
            if (!CryptographicOperations.FixedTimeEquals(proof.Challenge, expectedChallenge))
                return false;

            // Verify: s*G should equal R + c*P
            // We verify this by checking the algebraic relationship:
            // Compute s*G
            var responseScalar = BytesToBigInteger(proof.Response);
            var sG = ScalarMultiplyBasePoint(BigIntegerToBytes(responseScalar));

            // Compute R + c*P using EC point addition
            // We use an indirect verification: create signature from proof components
            // and verify using ECDsa Verify operation.
            // Alternative approach: verify by recomputing the commitment from response and challenge.
            var challengeScalar = BytesToBigInteger(proof.Challenge);
            var rPlusCp = AddPoints(proof.Commitment, publicKey, challengeScalar);

            // Compare the two EC points
            return PointsEqual(sG, rPlusCp);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    /// <summary>
    /// Generates a zero-knowledge proof of knowledge of a room password
    /// without revealing the password itself.
    /// </summary>
    /// <param name="roomPassword">The room password to prove knowledge of.</param>
    /// <param name="roomSalt">Room-specific salt for domain separation.</param>
    /// <returns>A <see cref="ZKProof"/> that proves knowledge of the password.</returns>
    public static ZKProof ProveRoomAccess(string roomPassword, byte[] roomSalt)
    {
        ArgumentException.ThrowIfNullOrEmpty(roomPassword);
        ArgumentNullException.ThrowIfNull(roomSalt);
        if (roomSalt.Length < 16)
            throw new ArgumentException("Room salt must be at least 16 bytes.", nameof(roomSalt));

        // Derive a secret scalar from the password + salt
        var passwordBytes = Encoding.UTF8.GetBytes(roomPassword);
        var secret = HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            ikm: passwordBytes,
            outputLength: 32,
            salt: roomSalt,
            info: RoomAccessDomainInfo);

        try
        {
            // Public info for the proof includes the salt and domain tag
            var publicInfo = BuildRoomPublicInfo(roomSalt);
            return GenerateProof(secret, publicInfo);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    /// <summary>
    /// Verifies a zero-knowledge proof of room password knowledge.
    /// The verifier needs the password hash (public key) and room salt.
    /// </summary>
    /// <param name="proof">The proof to verify.</param>
    /// <param name="roomPasswordHash">
    /// Public key corresponding to the room password (i.e., passwordScalar * G as SPKI bytes).
    /// This is stored by the room and does not reveal the password.
    /// </param>
    /// <param name="roomSalt">Room-specific salt used during proof generation.</param>
    /// <returns><c>true</c> if the proof is valid (prover knows the password).</returns>
    public static bool VerifyRoomAccess(ZKProof proof, byte[] roomPasswordHash, byte[] roomSalt)
    {
        ArgumentNullException.ThrowIfNull(proof);
        ArgumentNullException.ThrowIfNull(roomPasswordHash);
        ArgumentNullException.ThrowIfNull(roomSalt);

        var publicInfo = BuildRoomPublicInfo(roomSalt);
        return VerifyProof(proof, roomPasswordHash, publicInfo);
    }

    /// <summary>
    /// Derives the public key (point on P-256) from a room password and salt.
    /// This is stored by the room as the "password hash" for ZKP verification.
    /// </summary>
    /// <param name="roomPassword">The room password.</param>
    /// <param name="roomSalt">Room-specific salt.</param>
    /// <returns>SPKI-encoded public key bytes representing passwordScalar * G.</returns>
    public static byte[] DeriveRoomPasswordPublicKey(string roomPassword, byte[] roomSalt)
    {
        ArgumentException.ThrowIfNullOrEmpty(roomPassword);
        ArgumentNullException.ThrowIfNull(roomSalt);

        var passwordBytes = Encoding.UTF8.GetBytes(roomPassword);
        var secret = HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            ikm: passwordBytes,
            outputLength: 32,
            salt: roomSalt,
            info: RoomAccessDomainInfo);

        try
        {
            var scalar = DeriveScalar(secret);
            return ScalarMultiplyBasePoint(scalar);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    /// <summary>
    /// Computes the Fiat-Shamir challenge: c = SHA-256(R || publicInfo || P) reduced mod n.
    /// </summary>
    private static byte[] ComputeChallenge(byte[] commitment, byte[] publicInfo, byte[] publicKey)
    {
        var dataLength = commitment.Length + publicInfo.Length + publicKey.Length + ProofDomainInfo.Length;
        var data = new byte[dataLength];
        var offset = 0;

        Buffer.BlockCopy(ProofDomainInfo, 0, data, offset, ProofDomainInfo.Length);
        offset += ProofDomainInfo.Length;
        Buffer.BlockCopy(commitment, 0, data, offset, commitment.Length);
        offset += commitment.Length;
        Buffer.BlockCopy(publicInfo, 0, data, offset, publicInfo.Length);
        offset += publicInfo.Length;
        Buffer.BlockCopy(publicKey, 0, data, offset, publicKey.Length);

        return SHA256.HashData(data);
    }

    /// <summary>
    /// Derives a scalar value from input bytes, ensuring it is within [1, n-1]
    /// where n is the P-256 curve order.
    /// </summary>
    private static BigInteger DeriveScalar(byte[] input)
    {
        var hash = SHA256.HashData(input);
        var scalar = BytesToBigInteger(hash);
        // Reduce to valid range [1, n-1]
        scalar = scalar % (CurveOrder - 1) + 1;
        return scalar;
    }

    /// <summary>
    /// Computes scalar * G (base point multiplication) on P-256 and returns the
    /// resulting point as an SPKI-encoded public key.
    /// </summary>
    private static byte[] ScalarMultiplyBasePoint(BigInteger scalar)
    {
        var scalarBytes = BigIntegerToFixedBytes(scalar, 32);
        return ScalarMultiplyBasePoint(scalarBytes);
    }

    /// <summary>
    /// Computes scalar * G (base point multiplication) on P-256 and returns the
    /// resulting point as an SPKI-encoded public key.
    /// </summary>
    private static byte[] ScalarMultiplyBasePoint(byte[] scalarBytes)
    {
        // Create an ECDsa key from the scalar (private key = scalar, public key = scalar*G)
        var parameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = scalarBytes
        };

        using var ecdsa = ECDsa.Create(parameters);
        return ecdsa.ExportSubjectPublicKeyInfo();
    }

    /// <summary>
    /// Computes point addition: R + c*P on P-256 by leveraging ECDsa.
    /// Returns the result as SPKI-encoded bytes.
    /// </summary>
    private static byte[] AddPoints(byte[] pointR, byte[] pointP, BigInteger scalar)
    {
        // We cannot directly add EC points with BCL, so we verify algebraically:
        // Instead of computing R + c*P, we'll export both points and compare X,Y coordinates.
        // For verification, we recompute by generating proof from response.
        //
        // Alternative: use the verification equation indirectly.
        // s*G = R + c*P means we can verify by checking:
        // Derive R from s*G - c*P. This requires point subtraction.
        //
        // With BCL constraints, we use a SHA-256 fingerprint comparison approach:
        // Export the uncompressed point coordinates from both sides and compare.

        // Extract R coordinates
        var rParams = ImportPublicKeyParameters(pointR);

        // Extract P coordinates
        var pParams = ImportPublicKeyParameters(pointP);

        // Compute c*P by creating key with scalar c and point P combined
        // We use the double-and-add method via the curve equation
        var cP = EcPointScalarMultiply(pParams.Q.X!, pParams.Q.Y!, scalar);

        // Add R + c*P
        var sumPoint = EcPointAdd(
            rParams.Q.X!, rParams.Q.Y!,
            cP.x, cP.y);

        // Export as SPKI
        var resultParams = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = sumPoint.x, Y = sumPoint.y }
        };

        using var ecdsa = ECDsa.Create(resultParams);
        return ecdsa.ExportSubjectPublicKeyInfo();
    }

    /// <summary>
    /// Checks whether two SPKI-encoded EC points represent the same point.
    /// Uses constant-time comparison.
    /// </summary>
    private static bool PointsEqual(byte[] point1, byte[] point2)
    {
        if (point1.Length != point2.Length)
            return false;
        return CryptographicOperations.FixedTimeEquals(point1, point2);
    }

    /// <summary>
    /// Imports an SPKI-encoded EC public key and returns its parameters.
    /// </summary>
    private static ECParameters ImportPublicKeyParameters(byte[] spkiBytes)
    {
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportSubjectPublicKeyInfo(spkiBytes, out _);
        return ecdsa.ExportParameters(false);
    }

    /// <summary>
    /// Builds the public information byte array for room access proofs.
    /// </summary>
    private static byte[] BuildRoomPublicInfo(byte[] roomSalt)
    {
        var info = new byte[RoomAccessDomainInfo.Length + roomSalt.Length];
        Buffer.BlockCopy(RoomAccessDomainInfo, 0, info, 0, RoomAccessDomainInfo.Length);
        Buffer.BlockCopy(roomSalt, 0, info, RoomAccessDomainInfo.Length, roomSalt.Length);
        return info;
    }

    /// <summary>
    /// Converts a byte array to a positive BigInteger (unsigned, big-endian).
    /// </summary>
    private static BigInteger BytesToBigInteger(byte[] bytes)
    {
        // BigInteger constructor expects little-endian with unsigned flag
        var reversed = new byte[bytes.Length + 1]; // +1 for unsigned
        for (int i = 0; i < bytes.Length; i++)
            reversed[bytes.Length - 1 - i] = bytes[i];
        // Last byte is 0x00 to ensure positive
        return new BigInteger(reversed, isUnsigned: true);
    }

    /// <summary>
    /// Converts a BigInteger to a big-endian byte array of exactly the specified length.
    /// </summary>
    private static byte[] BigIntegerToFixedBytes(BigInteger value, int length)
    {
        var bytes = value.ToByteArray(isUnsigned: true);
        var result = new byte[length];
        // bytes is little-endian, we need big-endian
        for (int i = 0; i < Math.Min(bytes.Length, length); i++)
            result[length - 1 - i] = bytes[i];
        return result;
    }

    /// <summary>
    /// Converts a BigInteger to a big-endian byte array (variable length, 32 bytes typical).
    /// </summary>
    private static byte[] BigIntegerToBytes(BigInteger value)
    {
        return BigIntegerToFixedBytes(value, 32);
    }

    // ═══════════════════════════════════════════════════════════
    // P-256 Curve Arithmetic (Weierstrass form: y^2 = x^3 + ax + b mod p)
    // ═══════════════════════════════════════════════════════════

    /// <summary>P-256 prime field modulus.</summary>
    private static readonly BigInteger P256_P = BigInteger.Parse(
        "115792089210356248762697446949407573530086143415290314195533631308867097853951");

    /// <summary>P-256 curve parameter a = -3.</summary>
    private static readonly BigInteger P256_A = P256_P - 3;

    /// <summary>
    /// Performs EC point addition on P-256 in affine coordinates.
    /// </summary>
    private static (byte[] x, byte[] y) EcPointAdd(byte[] x1Bytes, byte[] y1Bytes, byte[] x2Bytes, byte[] y2Bytes)
    {
        var x1 = BytesToBigInteger(x1Bytes);
        var y1 = BytesToBigInteger(y1Bytes);
        var x2 = BytesToBigInteger(x2Bytes);
        var y2 = BytesToBigInteger(y2Bytes);

        BigInteger lambda;
        if (x1 == x2 && y1 == y2)
        {
            // Point doubling: lambda = (3*x1^2 + a) / (2*y1)
            var numerator = ModP(3 * ModP(x1 * x1) + P256_A);
            var denominator = ModP(2 * y1);
            lambda = ModP(numerator * ModInverse(denominator, P256_P));
        }
        else
        {
            // Point addition: lambda = (y2 - y1) / (x2 - x1)
            var numerator = ModP(y2 - y1);
            var denominator = ModP(x2 - x1);
            lambda = ModP(numerator * ModInverse(denominator, P256_P));
        }

        var x3 = ModP(lambda * lambda - x1 - x2);
        var y3 = ModP(lambda * (x1 - x3) - y1);

        return (BigIntegerToFixedBytes(x3, 32), BigIntegerToFixedBytes(y3, 32));
    }

    /// <summary>
    /// Performs EC scalar multiplication using double-and-add.
    /// </summary>
    private static (byte[] x, byte[] y) EcPointScalarMultiply(byte[] xBytes, byte[] yBytes, BigInteger scalar)
    {
        scalar = ((scalar % CurveOrder) + CurveOrder) % CurveOrder;

        // Double-and-add algorithm
        var currentX = xBytes;
        var currentY = yBytes;
        byte[]? resultX = null;
        byte[]? resultY = null;

        var bits = scalar.GetBitLength();
        for (int i = (int)bits - 1; i >= 0; i--)
        {
            if (resultX is not null && resultY is not null)
            {
                // Double
                (resultX, resultY) = EcPointAdd(resultX, resultY, resultX, resultY);
            }

            if (((scalar >> i) & 1) == 1)
            {
                if (resultX is null || resultY is null)
                {
                    resultX = currentX;
                    resultY = currentY;
                }
                else
                {
                    (resultX, resultY) = EcPointAdd(resultX, resultY, currentX, currentY);
                }
            }
        }

        return (resultX ?? xBytes, resultY ?? yBytes);
    }

    /// <summary>
    /// Reduces a value modulo P-256 prime, always returning a non-negative result.
    /// </summary>
    private static BigInteger ModP(BigInteger value)
    {
        var result = value % P256_P;
        return result < 0 ? result + P256_P : result;
    }

    /// <summary>
    /// Computes the modular multiplicative inverse using Fermat's little theorem:
    /// a^(-1) = a^(p-2) mod p (valid when p is prime).
    /// </summary>
    private static BigInteger ModInverse(BigInteger a, BigInteger modulus)
    {
        a = ((a % modulus) + modulus) % modulus;
        return BigInteger.ModPow(a, modulus - 2, modulus);
    }
}
