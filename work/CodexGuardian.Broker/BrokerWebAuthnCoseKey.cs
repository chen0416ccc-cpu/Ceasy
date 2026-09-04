using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Threading;

namespace CodexGuardian.Broker;

internal sealed class BrokerWebAuthnRegisteredCredentialV1 : IDisposable
{
    private readonly byte[] _credentialId;
    private readonly byte[] _subjectPublicKeyInfo;
    private readonly string _subjectPublicKeyInfoSha256;
    private int _disposed;

    internal BrokerWebAuthnRegisteredCredentialV1(
        ReadOnlySpan<byte> credentialId,
        ReadOnlySpan<byte> subjectPublicKeyInfo,
        string subjectPublicKeyInfoSha256)
    {
        ArgumentNullException.ThrowIfNull(subjectPublicKeyInfoSha256);
        _credentialId = credentialId.ToArray();
        _subjectPublicKeyInfo = subjectPublicKeyInfo.ToArray();
        _subjectPublicKeyInfoSha256 = subjectPublicKeyInfoSha256;
    }

    internal byte[] CredentialId
    {
        get
        {
            ThrowIfDisposed();
            return (byte[])_credentialId.Clone();
        }
    }

    internal byte[] SubjectPublicKeyInfo
    {
        get
        {
            ThrowIfDisposed();
            return (byte[])_subjectPublicKeyInfo.Clone();
        }
    }

    internal string SubjectPublicKeyInfoSha256
    {
        get
        {
            ThrowIfDisposed();
            return _subjectPublicKeyInfoSha256;
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        CryptographicOperations.ZeroMemory(_credentialId);
        CryptographicOperations.ZeroMemory(_subjectPublicKeyInfo);
    }

    private void ThrowIfDisposed() =>
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
}

internal static class BrokerWebAuthnRegistrationParserV1
{
    internal const int MaximumAuthenticatorDataBytes = 4096;
    internal const int MaximumCredentialIdBytes = 1024;

    private const int RpIdHashBytes = 32;
    private const int AaguidBytes = 16;
    private const int SubjectPublicKeyInfoBytes = 91;
    private const byte UserPresentFlag = 0x01;
    private const byte UserVerifiedFlag = 0x04;
    private const byte AttestedCredentialDataFlag = 0x40;
    private const byte ExtensionDataFlag = 0x80;
    private const byte UnsupportedReservedFlags = 0x22;
    private const int RequiredCoseMapEntries = 5;
    private const int RequiredCoseLabelsMask = 0x1F;

    internal static BrokerWebAuthnRegisteredCredentialV1 Parse(
        ReadOnlySpan<byte> authenticatorData,
        ReadOnlySpan<byte> expectedRpIdHash,
        ReadOnlySpan<byte> expectedCredentialId)
    {
        if (authenticatorData.Length is < 57 or > MaximumAuthenticatorDataBytes)
        {
            throw new ArgumentException(
                "Registration authenticator data is outside the supported bound.",
                nameof(authenticatorData));
        }

        if (expectedRpIdHash.Length != RpIdHashBytes)
        {
            throw new ArgumentException(
                "The expected RP ID hash must contain exactly 32 bytes.",
                nameof(expectedRpIdHash));
        }

        if (expectedCredentialId.Length > MaximumCredentialIdBytes)
        {
            throw new ArgumentException(
                "The expected credential ID exceeds the supported bound.",
                nameof(expectedCredentialId));
        }

        if (!CryptographicOperations.FixedTimeEquals(
                authenticatorData[..RpIdHashBytes],
                expectedRpIdHash))
        {
            throw new ArgumentException(
                "Registration authenticator data has the wrong RP ID hash.",
                nameof(authenticatorData));
        }

        ValidateFlags(authenticatorData[RpIdHashBytes]);

        var offset = RpIdHashBytes + 1 + sizeof(uint) + AaguidBytes;
        var credentialIdLength = BinaryPrimitives.ReadUInt16BigEndian(
            authenticatorData.Slice(offset, sizeof(ushort)));
        offset += sizeof(ushort);
        if (credentialIdLength is < 1 or > MaximumCredentialIdBytes ||
            authenticatorData.Length - offset <= credentialIdLength)
        {
            throw new ArgumentException(
                "Registration authenticator data has an invalid credential ID length.",
                nameof(authenticatorData));
        }

        var credentialId = authenticatorData.Slice(offset, credentialIdLength);
        if (!expectedCredentialId.IsEmpty &&
            (expectedCredentialId.Length != credentialId.Length ||
             !CryptographicOperations.FixedTimeEquals(expectedCredentialId, credentialId)))
        {
            throw new ArgumentException(
                "Registration authenticator data has the wrong credential ID.",
                nameof(authenticatorData));
        }

        offset += credentialIdLength;
        byte[]? frozenCredentialId = null;
        byte[]? subjectPublicKeyInfo = null;
        try
        {
            frozenCredentialId = credentialId.ToArray();
            subjectPublicKeyInfo = ParseCoseP256Key(authenticatorData[offset..]);
            var subjectPublicKeyInfoSha256 = Convert.ToHexString(
                SHA256.HashData(subjectPublicKeyInfo));
            return new BrokerWebAuthnRegisteredCredentialV1(
                frozenCredentialId,
                subjectPublicKeyInfo,
                subjectPublicKeyInfoSha256);
        }
        catch (FormatException exception)
        {
            throw new ArgumentException(
                "Registration authenticator data contains a non-canonical COSE key.",
                nameof(authenticatorData),
                exception);
        }
        catch (Exception exception) when (
            exception is CryptographicException or PlatformNotSupportedException)
        {
            throw new ArgumentException(
                "Registration authenticator data contains an invalid P-256 key.",
                nameof(authenticatorData),
                exception);
        }
        finally
        {
            if (frozenCredentialId is not null)
            {
                CryptographicOperations.ZeroMemory(frozenCredentialId);
            }

            if (subjectPublicKeyInfo is not null)
            {
                CryptographicOperations.ZeroMemory(subjectPublicKeyInfo);
            }
        }
    }

    private static void ValidateFlags(byte flags)
    {
        if ((flags & UserPresentFlag) == 0)
        {
            throw new ArgumentException(
                "Registration authenticator data is missing user presence.",
                "authenticatorData");
        }

        if ((flags & UserVerifiedFlag) == 0)
        {
            throw new ArgumentException(
                "Registration authenticator data is missing user verification.",
                "authenticatorData");
        }

        if ((flags & AttestedCredentialDataFlag) == 0)
        {
            throw new ArgumentException(
                "Registration authenticator data is missing attested credential data.",
                "authenticatorData");
        }

        if ((flags & ExtensionDataFlag) != 0 ||
            (flags & UnsupportedReservedFlags) != 0)
        {
            throw new ArgumentException(
                "Registration authenticator data contains unsupported flags.",
                "authenticatorData");
        }
    }

    private static byte[] ParseCoseP256Key(ReadOnlySpan<byte> encodedKey)
    {
        var reader = new CanonicalCborReader(encodedKey);
        if (reader.ReadMapLength() != RequiredCoseMapEntries)
        {
            throw new FormatException("The COSE key must contain exactly five entries.");
        }

        var seenLabels = 0;
        byte[]? x = null;
        byte[]? y = null;
        try
        {
            for (var index = 0; index < RequiredCoseMapEntries; index++)
            {
                var label = reader.ReadInteger();
                var bit = label switch
                {
                    1 => 0x01,
                    3 => 0x02,
                    -1 => 0x04,
                    -2 => 0x08,
                    -3 => 0x10,
                    _ => throw new FormatException("The COSE key contains an unknown label.")
                };
                if ((seenLabels & bit) != 0)
                {
                    throw new FormatException("The COSE key contains a duplicate label.");
                }

                seenLabels |= bit;
                switch (label)
                {
                    case 1 when reader.ReadInteger() == BrokerWebAuthnConstantsV1.Ec2KeyType:
                    case 3 when reader.ReadInteger() == BrokerWebAuthnConstantsV1.Es256Algorithm:
                    case -1 when reader.ReadInteger() == BrokerWebAuthnConstantsV1.P256Curve:
                        break;
                    case -2:
                        x = reader.ReadByteString(32).ToArray();
                        break;
                    case -3:
                        y = reader.ReadByteString(32).ToArray();
                        break;
                    default:
                        throw new FormatException("The COSE key contains an unsupported value.");
                }
            }

            if (seenLabels != RequiredCoseLabelsMask || x is null || y is null || !reader.AtEnd)
            {
                throw new FormatException("The COSE key is incomplete or has trailing data.");
            }

            using var key = ECDsa.Create();
            key.ImportParameters(
                new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    Q = new ECPoint
                    {
                        X = x,
                        Y = y
                    }
                });
            var subjectPublicKeyInfo = key.ExportSubjectPublicKeyInfo();
            if (subjectPublicKeyInfo.Length != SubjectPublicKeyInfoBytes)
            {
                CryptographicOperations.ZeroMemory(subjectPublicKeyInfo);
                throw new CryptographicException("The P-256 SubjectPublicKeyInfo length changed.");
            }

            using var canonicalKey = ECDsa.Create();
            canonicalKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo, out var bytesRead);
            var canonicalSubjectPublicKeyInfo = canonicalKey.ExportSubjectPublicKeyInfo();
            try
            {
                if (bytesRead != subjectPublicKeyInfo.Length ||
                    !canonicalSubjectPublicKeyInfo.AsSpan().SequenceEqual(subjectPublicKeyInfo))
                {
                    CryptographicOperations.ZeroMemory(subjectPublicKeyInfo);
                    throw new CryptographicException("The P-256 SubjectPublicKeyInfo is not canonical.");
                }

                return subjectPublicKeyInfo;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(canonicalSubjectPublicKeyInfo);
            }
        }
        finally
        {
            if (x is not null)
            {
                CryptographicOperations.ZeroMemory(x);
            }

            if (y is not null)
            {
                CryptographicOperations.ZeroMemory(y);
            }
        }
    }

    private ref struct CanonicalCborReader
    {
        private readonly ReadOnlySpan<byte> _data;
        private int _offset;

        internal CanonicalCborReader(ReadOnlySpan<byte> data)
        {
            _data = data;
            _offset = 0;
        }

        internal bool AtEnd => _offset == _data.Length;

        internal int ReadMapLength()
        {
            var (majorType, value) = ReadInitialValue();
            if (majorType != 5 || value > int.MaxValue)
            {
                throw new FormatException("A definite CBOR map is required.");
            }

            return (int)value;
        }

        internal long ReadInteger()
        {
            var (majorType, value) = ReadInitialValue();
            if (value > long.MaxValue)
            {
                throw new FormatException("The CBOR integer is outside the supported range.");
            }

            return majorType switch
            {
                0 => (long)value,
                1 => -1 - (long)value,
                _ => throw new FormatException("A CBOR integer is required.")
            };
        }

        internal ReadOnlySpan<byte> ReadByteString(int expectedLength)
        {
            var (majorType, value) = ReadInitialValue();
            if (majorType != 2 || value != (ulong)expectedLength)
            {
                throw new FormatException("The COSE coordinate has the wrong byte-string length.");
            }

            return ReadBytes(expectedLength);
        }

        private (int MajorType, ulong Value) ReadInitialValue()
        {
            var initial = ReadByte();
            var majorType = initial >> 5;
            var additionalInformation = initial & 0x1F;
            return (majorType, ReadCanonicalArgument(additionalInformation));
        }

        private ulong ReadCanonicalArgument(int additionalInformation) =>
            additionalInformation switch
            {
                <= 23 => (ulong)additionalInformation,
                24 => ReadCanonicalUInt8(),
                25 => ReadCanonicalUInt16(),
                26 => ReadCanonicalUInt32(),
                27 => ReadCanonicalUInt64(),
                _ => throw new FormatException("Indefinite or reserved CBOR lengths are unsupported.")
            };

        private ulong ReadCanonicalUInt8()
        {
            var value = ReadByte();
            if (value < 24)
            {
                throw new FormatException("The CBOR integer or length is not minimally encoded.");
            }

            return value;
        }

        private ulong ReadCanonicalUInt16()
        {
            var value = BinaryPrimitives.ReadUInt16BigEndian(ReadBytes(sizeof(ushort)));
            if (value <= byte.MaxValue)
            {
                throw new FormatException("The CBOR integer or length is not minimally encoded.");
            }

            return value;
        }

        private ulong ReadCanonicalUInt32()
        {
            var value = BinaryPrimitives.ReadUInt32BigEndian(ReadBytes(sizeof(uint)));
            if (value <= ushort.MaxValue)
            {
                throw new FormatException("The CBOR integer or length is not minimally encoded.");
            }

            return value;
        }

        private ulong ReadCanonicalUInt64()
        {
            var value = BinaryPrimitives.ReadUInt64BigEndian(ReadBytes(sizeof(ulong)));
            if (value <= uint.MaxValue)
            {
                throw new FormatException("The CBOR integer or length is not minimally encoded.");
            }

            return value;
        }

        private byte ReadByte()
        {
            if (_offset >= _data.Length)
            {
                throw new FormatException("The CBOR value is truncated.");
            }

            return _data[_offset++];
        }

        private ReadOnlySpan<byte> ReadBytes(int count)
        {
            if (count < 0 || _data.Length - _offset < count)
            {
                throw new FormatException("The CBOR value is truncated.");
            }

            var value = _data.Slice(_offset, count);
            _offset += count;
            return value;
        }
    }
}
