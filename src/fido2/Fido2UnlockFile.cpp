/*
 *  Copyright (C) 2026 KeePassXC Team <team@keepassxc.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 */

#include "Fido2UnlockFile.h"

#include "config-keepassx.h"
#include "crypto/CryptoHash.h"

#include <QObject>
#include <QSet>

#include <algorithm>
#include <exception>
#include <memory>
#include <span>

#include <botan/aead.h>
#include <botan/ec_group.h>
#include <botan/ecdsa.h>
#include <botan/kdf.h>
#include <botan/mem_ops.h>
#include <botan/pubkey.h>
#include <botan/secmem.h>

namespace
{
    constexpr int headerSize = 94;
    constexpr int wireVersionOffset = 8;
    constexpr int totalLengthOffset = 10;
    constexpr int envelopeIdOffset = 14;
    constexpr int rpIdOffset = 30;
    constexpr int envelopeSaltOffset = 58;
    constexpr int payloadPolicyOffset = 90;
    constexpr int wrapperCountOffset = 91;
    constexpr int headerReservedOffset = 92;
    constexpr int headerReservedSize = 2;
    constexpr quint16 wireVersion = 1;
    constexpr quint32 aadVersion = 1;
    constexpr char userVerificationRequired = 0x01;
    constexpr quint8 userPresentFlag = 0x01;
    constexpr quint8 userVerifiedFlag = 0x04;
    const QByteArray unlockFileMagic("KPYKUNLK", 8);
    const QByteArray aadMagic("KPYKSID1", 8);
    const QByteArray rpId("fido2-envelope.keepassxc.org", 28);

    // Unlock file integers are encoded as unsigned, big-endian values.
    void appendUint16(QByteArray& output, quint16 value)
    {
        output.append(static_cast<char>((value >> 8) & 0xff));
        output.append(static_cast<char>(value & 0xff));
    }

    void appendUint32(QByteArray& output, quint32 value)
    {
        output.append(static_cast<char>((value >> 24) & 0xff));
        output.append(static_cast<char>((value >> 16) & 0xff));
        output.append(static_cast<char>((value >> 8) & 0xff));
        output.append(static_cast<char>(value & 0xff));
    }

    quint16 readUint16(const QByteArray& input, int offset)
    {
        return static_cast<quint16>((static_cast<quint8>(input.at(offset)) << 8)
                                    | static_cast<quint8>(input.at(offset + 1)));
    }

    quint32 readUint32(const QByteArray& input, int offset)
    {
        return (static_cast<quint32>(static_cast<quint8>(input.at(offset))) << 24)
               | (static_cast<quint32>(static_cast<quint8>(input.at(offset + 1))) << 16)
               | (static_cast<quint32>(static_cast<quint8>(input.at(offset + 2))) << 8)
               | static_cast<quint32>(static_cast<quint8>(input.at(offset + 3)));
    }

    std::unique_ptr<Botan::ECDSA_PublicKey> decodeEs256PublicKey(const QByteArray& publicKey)
    {
        if (publicKey.size() != Fido2UnlockFile::ES256_PUBLIC_KEY_SIZE) {
            return {};
        }

        try {
            QByteArray encodedPoint("\x04", 1);
            encodedPoint.append(publicKey);

            Botan::EC_Group group("secp256r1");
            auto point = group.OS2ECP(reinterpret_cast<const uint8_t*>(encodedPoint.constData()), encodedPoint.size());
            if (!group.verify_public_element(point)) {
                return {};
            }
            return std::make_unique<Botan::ECDSA_PublicKey>(group, point);
        } catch (const std::exception&) {
            return {};
        }
    }

    bool take(const QByteArray& input, int& offset, int size, QByteArray& value)
    {
        if (size < 0 || offset < 0 || offset > input.size() || size > input.size() - offset) {
            return false;
        }
        value = QByteArray(input.constData() + offset, size);
        offset += size;
        return true;
    }

    bool takeUint16(const QByteArray& input, int& offset, quint16& value)
    {
        if (offset > input.size() - 2) {
            return false;
        }
        value = readUint16(input, offset);
        offset += 2;
        return true;
    }

    Botan::secure_vector<uint8_t> deriveKek(const Fido2UnlockFile::Envelope& envelope,
                                            const Fido2UnlockFile::Wrapper& wrapper,
                                            const QByteArray& hmacSecret)
    {
        const QByteArray info = QByteArrayLiteral("keepassxc-fido2-unlock-file-v1-kek") + wrapper.slotId;
        auto hkdf = Botan::KDF::create_or_throw("HKDF(SHA-256)");
#ifdef WITH_BOTAN3
        return hkdf->derive_key(
            32,
            std::span(reinterpret_cast<const uint8_t*>(hmacSecret.constData()), static_cast<size_t>(hmacSecret.size())),
            std::span(reinterpret_cast<const uint8_t*>(envelope.envelopeId.constData()),
                      static_cast<size_t>(envelope.envelopeId.size())),
            std::span(reinterpret_cast<const uint8_t*>(info.constData()), static_cast<size_t>(info.size())));
#else
        return hkdf->derive_key(32,
                                reinterpret_cast<const uint8_t*>(hmacSecret.constData()),
                                hmacSecret.size(),
                                reinterpret_cast<const uint8_t*>(envelope.envelopeId.constData()),
                                envelope.envelopeId.size(),
                                reinterpret_cast<const uint8_t*>(info.constData()),
                                info.size());
#endif
    }
} // namespace

bool Fido2UnlockFile::parse(const QByteArray& data, Envelope& envelope, QString& error)
{
    envelope = {};

    if (data.size() < headerSize || data.size() > MAXIMUM_FILE_SIZE
        || data.left(unlockFileMagic.size()) != unlockFileMagic || readUint16(data, wireVersionOffset) != wireVersion
        || readUint32(data, totalLengthOffset) != static_cast<quint32>(data.size())
        || data.mid(rpIdOffset, rpId.size()) != rpId
        || data.mid(headerReservedOffset, headerReservedSize) != QByteArray(headerReservedSize, '\0')) {
        error = QObject::tr("Invalid FIDO2 unlock file header.");
        return false;
    }

    const auto payloadPolicy = static_cast<PayloadPolicy>(static_cast<quint8>(data.at(payloadPolicyOffset)));
    const quint8 wrapperCount = static_cast<quint8>(data.at(wrapperCountOffset));
    if (payloadPolicy != PayloadPolicy::PasswordOnly && payloadPolicy != PayloadPolicy::PasswordAndKeyFile) {
        error = QObject::tr("Invalid FIDO2 unlock file header.");
        return false;
    }
    if (wrapperCount == 0 || wrapperCount > MAX_WRAPPERS) {
        error = QObject::tr("Invalid FIDO2 unlock file wrapper count.");
        return false;
    }

    Envelope parsed;
    parsed.envelopeId = data.mid(envelopeIdOffset, ENVELOPE_ID_SIZE);
    parsed.envelopeSalt = data.mid(envelopeSaltOffset, HMAC_SECRET_SIZE);
    parsed.payloadPolicy = payloadPolicy;

    int offset = headerSize;
    QSet<QByteArray> credentialIds;
    QByteArray previousSlot;
    for (quint8 index = 0; index < wrapperCount; ++index) {
        Wrapper wrapper;
        QByteArray labelBytes;
        QByteArray reserved;
        quint16 credentialLength = 0;

        if (!take(data, offset, SLOT_ID_SIZE, wrapper.slotId) || offset >= data.size()) {
            error = QObject::tr("Truncated FIDO2 unlock file wrapper.");
            return false;
        }

        const auto labelLength = static_cast<quint8>(data.at(offset++));
        if (labelLength == 0 || labelLength > 128 || !take(data, offset, labelLength, labelBytes)
            || labelBytes.contains('\0')) {
            error = QObject::tr("Invalid FIDO2 unlock file label.");
            return false;
        }
        wrapper.label = QString::fromUtf8(labelBytes.constData(), labelBytes.size());

        if (wrapper.label.toUtf8() != labelBytes || !takeUint16(data, offset, credentialLength) || credentialLength == 0
            || credentialLength > 1024 || !take(data, offset, credentialLength, wrapper.credentialId)
            || !take(data, offset, ES256_PUBLIC_KEY_SIZE, wrapper.publicKey) || !decodeEs256PublicKey(wrapper.publicKey)
            || !take(data, offset, GCM_NONCE_SIZE, wrapper.nonce)
            || !take(data, offset, GCM_CIPHERTEXT_SIZE, wrapper.ciphertext) || offset >= data.size()
            || data.at(offset++) != userVerificationRequired || !take(data, offset, 3, reserved)
            || reserved != QByteArray(3, '\0')) {
            error = QObject::tr("Invalid FIDO2 unlock file wrapper.");
            return false;
        }

        // Canonical wrappers are strictly sorted by slot ID and use unique credential IDs.
        if ((!previousSlot.isEmpty() && previousSlot >= wrapper.slotId)
            || credentialIds.contains(wrapper.credentialId)) {
            error = QObject::tr("Non-canonical FIDO2 unlock file wrappers.");
            return false;
        }
        previousSlot = wrapper.slotId;
        credentialIds.insert(wrapper.credentialId);
        parsed.wrappers.append(wrapper);
    }

    if (offset != data.size()) {
        error = QObject::tr("Trailing bytes in FIDO2 unlock file.");
        return false;
    }
    envelope = parsed;
    return true;
}

QByteArray Fido2UnlockFile::associatedData(const Envelope& envelope, const Wrapper& wrapper)
{
    // Canonical field order: magic, version, policy, envelope ID, slot ID, RP ID, credential ID,
    // ES256 public key, envelope salt, and UV policy. Variable fields include their length first.
    QByteArray result(aadMagic);
    appendUint32(result, aadVersion);
    result.append(static_cast<char>(envelope.payloadPolicy));
    result.append(envelope.envelopeId);
    result.append(wrapper.slotId);

    appendUint16(result, static_cast<quint16>(rpId.size()));
    result.append(rpId);
    appendUint16(result, static_cast<quint16>(wrapper.credentialId.size()));
    result.append(wrapper.credentialId);

    result.append(wrapper.publicKey);
    result.append(envelope.envelopeSalt);
    result.append(userVerificationRequired);
    return result;
}

bool Fido2UnlockFile::verifyAssertion(const Wrapper& wrapper,
                                      const QByteArray& clientDataHash,
                                      const QByteArray& authenticatorData,
                                      const QByteArray& signature,
                                      QString& error)
{
    if (clientDataHash.size() != HMAC_SECRET_SIZE || authenticatorData.size() < 37 || authenticatorData.size() > 2048
        || signature.isEmpty() || signature.size() > 256 || wrapper.publicKey.size() != ES256_PUBLIC_KEY_SIZE) {
        error = QObject::tr("Invalid FIDO2 assertion data.");
        return false;
    }

    if (authenticatorData.left(32) != CryptoHash::hash(rpId, CryptoHash::Sha256)) {
        error = QObject::tr("FIDO2 assertion RP ID mismatch.");
        return false;
    }

    const auto assertionFlags = static_cast<quint8>(authenticatorData.at(32));
    if ((assertionFlags & (userPresentFlag | userVerifiedFlag)) != (userPresentFlag | userVerifiedFlag)) {
        error = QObject::tr("FIDO2 assertion is missing user presence or verification.");
        return false;
    }

    try {
        const auto publicKey = decodeEs256PublicKey(wrapper.publicKey);
        if (!publicKey) {
            error = QObject::tr("Invalid FIDO2 assertion data.");
            return false;
        }
#ifdef WITH_BOTAN3
        Botan::PK_Verifier verifier(*publicKey, "EMSA1(SHA-256)", Botan::Signature_Format::DerSequence);
#else
        Botan::PK_Verifier verifier(*publicKey, "EMSA1(SHA-256)", Botan::DER_SEQUENCE);
#endif

        // WebAuthn signs authenticatorData followed by clientDataHash.
        const QByteArray signedData = authenticatorData + clientDataHash;
        if (!verifier.verify_message(reinterpret_cast<const uint8_t*>(signedData.constData()),
                                     signedData.size(),
                                     reinterpret_cast<const uint8_t*>(signature.constData()),
                                     signature.size())) {
            error = QObject::tr("Invalid FIDO2 assertion signature.");
            return false;
        }

        return true;
    } catch (const std::exception& exception) {
        error = exception.what();
        return false;
    }
}

bool Fido2UnlockFile::unwrapKeys(const Envelope& envelope,
                                 const Wrapper& wrapper,
                                 const QByteArray& hmacSecret,
                                 QByteArray& passwordKey,
                                 QByteArray& fileKey,
                                 QString& error)
{
    clearSecret(passwordKey);
    clearSecret(fileKey);

    if (envelope.envelopeId.size() != ENVELOPE_ID_SIZE || envelope.envelopeSalt.size() != HMAC_SECRET_SIZE
        || (envelope.payloadPolicy != PayloadPolicy::PasswordOnly
            && envelope.payloadPolicy != PayloadPolicy::PasswordAndKeyFile)
        || wrapper.slotId.size() != SLOT_ID_SIZE || wrapper.credentialId.isEmpty()
        || wrapper.publicKey.size() != ES256_PUBLIC_KEY_SIZE || wrapper.nonce.size() != GCM_NONCE_SIZE
        || wrapper.ciphertext.size() != GCM_CIPHERTEXT_SIZE || hmacSecret.size() != HMAC_SECRET_SIZE) {
        error = QObject::tr("Invalid FIDO2 unlock file unwrap data.");
        return false;
    }

    try {
        const auto kek = deriveKek(envelope, wrapper, hmacSecret);
#ifdef WITH_BOTAN3
        auto cipher = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Decryption);
#else
        auto cipher = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::DECRYPTION);
#endif
        cipher->set_key(kek);

        const auto aad = associatedData(envelope, wrapper);
        cipher->set_associated_data(reinterpret_cast<const uint8_t*>(aad.constData()), aad.size());
        cipher->start(reinterpret_cast<const uint8_t*>(wrapper.nonce.constData()), wrapper.nonce.size());

        Botan::secure_vector<uint8_t> output(wrapper.ciphertext.begin(), wrapper.ciphertext.end());
        cipher->finish(output);

        if (output.size() != PASSWORD_KEY_SIZE + FILE_KEY_SIZE) {
            error = QObject::tr("Invalid FIDO2 unlock file payload.");
            return false;
        }
        if (envelope.payloadPolicy == PayloadPolicy::PasswordOnly
            && std::any_of(
                output.cbegin() + PASSWORD_KEY_SIZE, output.cend(), [](uint8_t value) { return value != 0; })) {
            error = QObject::tr("Invalid FIDO2 unlock file payload.");
            return false;
        }

        passwordKey = QByteArray(reinterpret_cast<const char*>(output.data()), PASSWORD_KEY_SIZE);
        if (envelope.payloadPolicy == PayloadPolicy::PasswordAndKeyFile) {
            fileKey = QByteArray(reinterpret_cast<const char*>(output.data() + PASSWORD_KEY_SIZE), FILE_KEY_SIZE);
        }

        return true;
    } catch (const std::exception& exception) {
        clearSecret(passwordKey);
        clearSecret(fileKey);
        error = exception.what();
        return false;
    }
}

void Fido2UnlockFile::clearSecret(QByteArray& secret)
{
    if (!secret.isEmpty()) {
        // Detach before scrubbing shared Qt storage; capacity covers bytes beyond the logical size.
        secret.detach();
        Botan::secure_scrub_memory(secret.data(), static_cast<std::size_t>(secret.capacity()));
    }

    secret.clear();
}
