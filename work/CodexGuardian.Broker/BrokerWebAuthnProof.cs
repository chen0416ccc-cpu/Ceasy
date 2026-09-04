using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Threading;

namespace CodexGuardian.Broker;

internal static class BrokerWebAuthnDerSignatureV1
{
    internal const int SignatureBytes = 64;

    private const int ScalarBytes = 32;
    private const int MinimumDerSignatureBytes = 8;
    private const int MaximumDerSignatureBytes = 72;

    private static ReadOnlySpan<byte> P256Order =>
    [
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
        0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
    ];

    internal static byte[] NormalizeToP1363(ReadOnlySpan<byte> nativeDerSignature)
    {
        if (nativeDerSignature.Length is < MinimumDerSignatureBytes or > MaximumDerSignatureBytes)
        {
            throw InvalidDer("The DER signature is outside the supported bound.");
        }

        var offset = 0;
        if (ReadByte(nativeDerSignature, ref offset) != 0x30)
        {
            throw InvalidDer("The DER signature must be one SEQUENCE.");
        }

        var sequenceLength = ReadShortLength(nativeDerSignature, ref offset);
        if (sequenceLength != nativeDerSignature.Length - offset)
        {
            throw InvalidDer("The DER signature SEQUENCE length is not exact.");
        }

        var result = new byte[SignatureBytes];
        try
        {
            ReadScalar(nativeDerSignature, ref offset, result.AsSpan(0, ScalarBytes));
            ReadScalar(nativeDerSignature, ref offset, result.AsSpan(ScalarBytes, ScalarBytes));
            if (offset != nativeDerSignature.Length)
            {
                throw InvalidDer("The DER signature contains trailing data.");
            }

            return result;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(result);
            throw;
        }
    }

    internal static void ValidateP1363(ReadOnlySpan<byte> signatureP1363)
    {
        if (signatureP1363.Length != SignatureBytes)
        {
            throw new ArgumentException(
                "The P1363 signature must contain exactly 64 bytes.",
                nameof(signatureP1363));
        }

        ValidateScalar(signatureP1363[..ScalarBytes], nameof(signatureP1363));
        ValidateScalar(signatureP1363[ScalarBytes..], nameof(signatureP1363));
    }

    private static void ReadScalar(
        ReadOnlySpan<byte> encoded,
        ref int offset,
        Span<byte> destination)
    {
        if (ReadByte(encoded, ref offset) != 0x02)
        {
            throw InvalidDer("The DER signature must contain exactly two INTEGER values.");
        }

        var encodedLength = ReadShortLength(encoded, ref offset);
        if (encodedLength == 0 || encoded.Length - offset < encodedLength)
        {
            throw InvalidDer("The DER signature INTEGER length is invalid.");
        }

        var scalar = encoded.Slice(offset, encodedLength);
        offset += encodedLength;
        if (scalar[0] == 0)
        {
            if (scalar.Length == 1 || (scalar[1] & 0x80) == 0)
            {
                throw InvalidDer("The DER signature INTEGER has a non-minimal leading zero.");
            }

            scalar = scalar[1..];
        }
        else if ((scalar[0] & 0x80) != 0)
        {
            throw InvalidDer("The DER signature INTEGER is negative.");
        }

        if (scalar.Length > ScalarBytes)
        {
            throw InvalidDer("The DER signature INTEGER exceeds P-256.");
        }

        destination.Clear();
        scalar.CopyTo(destination[^scalar.Length..]);
        ValidateScalar(destination, "nativeDerSignature");
    }

    private static void ValidateScalar(ReadOnlySpan<byte> scalar, string parameterName)
    {
        var nonzero = 0;
        foreach (var value in scalar)
        {
            nonzero |= value;
        }

        if (nonzero == 0 || scalar.SequenceCompareTo(P256Order) >= 0)
        {
            throw new ArgumentException(
                "The ECDSA scalar is outside the P-256 order.",
                parameterName);
        }
    }

    private static int ReadShortLength(ReadOnlySpan<byte> encoded, ref int offset)
    {
        var value = ReadByte(encoded, ref offset);
        if ((value & 0x80) != 0)
        {
            throw InvalidDer("Long-form and indefinite DER lengths are unsupported.");
        }

        return value;
    }

    private static byte ReadByte(ReadOnlySpan<byte> encoded, ref int offset)
    {
        if (offset >= encoded.Length)
        {
            throw InvalidDer("The DER signature is truncated.");
        }

        return encoded[offset++];
    }

    private static ArgumentException InvalidDer(string message) =>
        new(message, "nativeDerSignature");
}

internal static class BrokerWebAuthnAssertionAuthenticatorDataV1
{
    internal const int ExactBytes = 37;

    private const byte UserPresentFlag = 0x01;
    private const byte UserVerifiedFlag = 0x04;
    private const byte AttestedCredentialDataFlag = 0x40;
    private const byte ExtensionDataFlag = 0x80;
    private const byte UnsupportedReservedFlags = 0x22;

    private static ReadOnlySpan<byte> FixedRpIdHash =>
    [
        0x98, 0xCC, 0x7D, 0x7B, 0x6E, 0xB4, 0x4A, 0xE2,
        0x01, 0xCA, 0x88, 0x95, 0xA5, 0x8B, 0x4F, 0x07,
        0x15, 0xB2, 0x55, 0xC3, 0xAF, 0x04, 0x31, 0x62,
        0xE8, 0xA7, 0x1C, 0x45, 0xFB, 0xEB, 0x34, 0x78
    ];

    internal static uint ValidateFixedRp(ReadOnlySpan<byte> authenticatorData) =>
        Validate(authenticatorData, FixedRpIdHash);

    private static uint Validate(
        ReadOnlySpan<byte> authenticatorData,
        ReadOnlySpan<byte> expectedRpIdHash)
    {
        if (authenticatorData.Length != ExactBytes)
        {
            throw new ArgumentException(
                "Assertion authenticator data must contain exactly 37 bytes.",
                nameof(authenticatorData));
        }

        if (expectedRpIdHash.Length != 32)
        {
            throw new ArgumentException(
                "The expected RP ID hash must contain exactly 32 bytes.",
                nameof(expectedRpIdHash));
        }

        if (!CryptographicOperations.FixedTimeEquals(authenticatorData[..32], expectedRpIdHash))
        {
            throw new ArgumentException(
                "Assertion authenticator data has the wrong RP ID hash.",
                nameof(authenticatorData));
        }

        var flags = authenticatorData[32];
        if ((flags & UserPresentFlag) == 0)
        {
            throw new ArgumentException(
                "Assertion authenticator data is missing user presence.",
                nameof(authenticatorData));
        }

        if ((flags & UserVerifiedFlag) == 0)
        {
            throw new ArgumentException(
                "Assertion authenticator data is missing user verification.",
                nameof(authenticatorData));
        }

        if ((flags & (AttestedCredentialDataFlag | ExtensionDataFlag | UnsupportedReservedFlags)) != 0)
        {
            throw new ArgumentException(
                "Assertion authenticator data contains unsupported flags.",
                nameof(authenticatorData));
        }

        return BinaryPrimitives.ReadUInt32BigEndian(authenticatorData[33..]);
    }
}

internal sealed class BrokerWebAuthnAssertionProofV1 : IDisposable
{
    internal const int EnvelopeBytes = 210;
    internal const int SubjectPublicKeyInfoBytes = 91;

    private const int AuthenticatorDataBytes = BrokerWebAuthnAssertionAuthenticatorDataV1.ExactBytes;
    private const int SignatureBytes = BrokerWebAuthnDerSignatureV1.SignatureBytes;
    private const int SubjectPublicKeyInfoOffset = 18;
    private const int AuthenticatorDataOffset = SubjectPublicKeyInfoOffset + SubjectPublicKeyInfoBytes;
    private const int SignatureOffset = AuthenticatorDataOffset + AuthenticatorDataBytes;
    private readonly byte[] _subjectPublicKeyInfo;
    private readonly byte[] _authenticatorData;
    private readonly byte[] _signatureP1363;
    private int _disposed;

    private static ReadOnlySpan<byte> Magic =>
    [
        (byte)'C', (byte)'G', (byte)'W', (byte)'A',
        (byte)'P', (byte)'F', (byte)'1', 0x00
    ];

    private static ReadOnlySpan<byte> P256SubjectPublicKeyInfoPrefix =>
    [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86,
        0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,
        0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03,
        0x42, 0x00, 0x04
    ];

    private BrokerWebAuthnAssertionProofV1(
        ReadOnlySpan<byte> subjectPublicKeyInfo,
        ReadOnlySpan<byte> authenticatorData,
        ReadOnlySpan<byte> signatureP1363)
    {
        _subjectPublicKeyInfo = subjectPublicKeyInfo.ToArray();
        _authenticatorData = authenticatorData.ToArray();
        _signatureP1363 = signatureP1363.ToArray();
    }

    internal byte[] SubjectPublicKeyInfo
    {
        get
        {
            ThrowIfDisposed();
            return (byte[])_subjectPublicKeyInfo.Clone();
        }
    }

    internal byte[] AuthenticatorData
    {
        get
        {
            ThrowIfDisposed();
            return (byte[])_authenticatorData.Clone();
        }
    }

    internal byte[] SignatureP1363
    {
        get
        {
            ThrowIfDisposed();
            return (byte[])_signatureP1363.Clone();
        }
    }

    internal static BrokerWebAuthnAssertionProofV1 Create(
        ReadOnlySpan<byte> subjectPublicKeyInfo,
        ReadOnlySpan<byte> authenticatorData,
        ReadOnlySpan<byte> nativeDerSignature)
    {
        ValidateCanonicalSubjectPublicKeyInfo(subjectPublicKeyInfo, nameof(subjectPublicKeyInfo));
        _ = BrokerWebAuthnAssertionAuthenticatorDataV1.ValidateFixedRp(authenticatorData);
        var signatureP1363 = BrokerWebAuthnDerSignatureV1.NormalizeToP1363(nativeDerSignature);
        try
        {
            return new BrokerWebAuthnAssertionProofV1(
                subjectPublicKeyInfo,
                authenticatorData,
                signatureP1363);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signatureP1363);
        }
    }

    internal static BrokerWebAuthnAssertionProofV1 Parse(ReadOnlySpan<byte> envelope)
    {
        if (envelope.Length != EnvelopeBytes)
        {
            throw new ArgumentException(
                "The WebAuthn proof envelope must contain exactly 210 bytes.",
                nameof(envelope));
        }

        if (!envelope[..Magic.Length].SequenceEqual(Magic) ||
            envelope[8] != 1 ||
            envelope[9] != 1 ||
            envelope[10] != 0 ||
            envelope[11] != 0 ||
            BinaryPrimitives.ReadUInt16BigEndian(envelope[12..14]) != SubjectPublicKeyInfoBytes ||
            BinaryPrimitives.ReadUInt16BigEndian(envelope[14..16]) != AuthenticatorDataBytes ||
            BinaryPrimitives.ReadUInt16BigEndian(envelope[16..18]) != SignatureBytes)
        {
            throw new ArgumentException(
                "The WebAuthn proof envelope header is not canonical.",
                nameof(envelope));
        }

        var subjectPublicKeyInfo = envelope.Slice(
            SubjectPublicKeyInfoOffset,
            SubjectPublicKeyInfoBytes);
        var authenticatorData = envelope.Slice(
            AuthenticatorDataOffset,
            AuthenticatorDataBytes);
        var signatureP1363 = envelope.Slice(SignatureOffset, SignatureBytes);
        ValidateCanonicalSubjectPublicKeyInfo(subjectPublicKeyInfo, nameof(envelope));
        _ = BrokerWebAuthnAssertionAuthenticatorDataV1.ValidateFixedRp(authenticatorData);
        BrokerWebAuthnDerSignatureV1.ValidateP1363(signatureP1363);
        return new BrokerWebAuthnAssertionProofV1(
            subjectPublicKeyInfo,
            authenticatorData,
            signatureP1363);
    }

    internal byte[] Serialize()
    {
        ThrowIfDisposed();
        var envelope = new byte[EnvelopeBytes];
        Magic.CopyTo(envelope);
        envelope[8] = 1;
        envelope[9] = 1;
        BinaryPrimitives.WriteUInt16BigEndian(envelope.AsSpan(12, 2), SubjectPublicKeyInfoBytes);
        BinaryPrimitives.WriteUInt16BigEndian(envelope.AsSpan(14, 2), AuthenticatorDataBytes);
        BinaryPrimitives.WriteUInt16BigEndian(envelope.AsSpan(16, 2), SignatureBytes);
        _subjectPublicKeyInfo.CopyTo(envelope, SubjectPublicKeyInfoOffset);
        _authenticatorData.CopyTo(envelope, AuthenticatorDataOffset);
        _signatureP1363.CopyTo(envelope, SignatureOffset);
        return envelope;
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        CryptographicOperations.ZeroMemory(_subjectPublicKeyInfo);
        CryptographicOperations.ZeroMemory(_authenticatorData);
        CryptographicOperations.ZeroMemory(_signatureP1363);
    }

    private static void ValidateCanonicalSubjectPublicKeyInfo(
        ReadOnlySpan<byte> subjectPublicKeyInfo,
        string parameterName)
    {
        if (subjectPublicKeyInfo.Length != SubjectPublicKeyInfoBytes ||
            !subjectPublicKeyInfo[..P256SubjectPublicKeyInfoPrefix.Length]
                .SequenceEqual(P256SubjectPublicKeyInfoPrefix))
        {
            throw new ArgumentException(
                "The WebAuthn public key is not canonical P-256 SubjectPublicKeyInfo.",
                parameterName);
        }

        byte[]? canonical = null;
        try
        {
            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo, out var bytesRead);
            canonical = key.ExportSubjectPublicKeyInfo();
            if (bytesRead != subjectPublicKeyInfo.Length ||
                !canonical.AsSpan().SequenceEqual(subjectPublicKeyInfo))
            {
                throw new ArgumentException(
                    "The WebAuthn public key is not canonical P-256 SubjectPublicKeyInfo.",
                    parameterName);
            }
        }
        catch (Exception exception) when (
            exception is CryptographicException or PlatformNotSupportedException)
        {
            throw new ArgumentException(
                "The WebAuthn public key is not a valid P-256 SubjectPublicKeyInfo.",
                parameterName,
                exception);
        }
        finally
        {
            if (canonical is not null)
            {
                CryptographicOperations.ZeroMemory(canonical);
            }
        }
    }

    private void ThrowIfDisposed() =>
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
}
