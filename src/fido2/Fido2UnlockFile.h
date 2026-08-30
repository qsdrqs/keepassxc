/*
 *  Copyright (C) 2026 KeePassXC Team <team@keepassxc.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 */

#ifndef KEEPASSXC_FIDO2UNLOCKFILE_H
#define KEEPASSXC_FIDO2UNLOCKFILE_H

#include <QByteArray>
#include <QList>
#include <QString>

namespace Fido2UnlockFile
{
    constexpr int ENVELOPE_ID_SIZE = 16;
    constexpr int SLOT_ID_SIZE = 16;
    constexpr int HMAC_SECRET_SIZE = 32;
    constexpr int PASSWORD_KEY_SIZE = 32;
    constexpr int FILE_KEY_SIZE = 32;
    constexpr int ES256_PUBLIC_KEY_SIZE = 64;
    constexpr int GCM_NONCE_SIZE = 12;
    constexpr int GCM_CIPHERTEXT_SIZE = 80;
    constexpr int MAX_WRAPPERS = 8;
    constexpr int MAXIMUM_FILE_SIZE = 64 * 1024;

    enum class PayloadPolicy : quint8
    {
        PasswordOnly = 1,
        PasswordAndKeyFile = 2
    };

    struct Wrapper
    {
        QByteArray slotId;
        QString label;
        QByteArray credentialId;
        QByteArray publicKey;
        QByteArray nonce;
        QByteArray ciphertext;
    };

    struct Envelope
    {
        QByteArray envelopeId;
        QByteArray envelopeSalt;
        PayloadPolicy payloadPolicy = static_cast<PayloadPolicy>(0);
        QList<Wrapper> wrappers;
    };

    /// Parse a canonical unlock file envelope. The output is cleared before validation.
    bool parse(const QByteArray& data, Envelope& envelope, QString& error);

    /// Build the canonical authenticated metadata for a wrapped key payload.
    QByteArray associatedData(const Envelope& envelope, const Wrapper& wrapper);

    /// Verify the RP ID, UP/UV flags, and ES256 signature of an assertion.
    bool verifyAssertion(const Wrapper& wrapper,
                         const QByteArray& clientDataHash,
                         const QByteArray& authenticatorData,
                         const QByteArray& signature,
                         QString& error);

    /// Decrypt wrapped password and file keys. Both outputs are cleared on entry and on failure.
    bool unwrapKeys(const Envelope& envelope,
                    const Wrapper& wrapper,
                    const QByteArray& hmacSecret,
                    QByteArray& passwordKey,
                    QByteArray& fileKey,
                    QString& error);

    /// For non-empty arrays, detach shared storage and scrub its full capacity before clearing.
    void clearSecret(QByteArray& secret);
} // namespace Fido2UnlockFile

#endif // KEEPASSXC_FIDO2UNLOCKFILE_H
