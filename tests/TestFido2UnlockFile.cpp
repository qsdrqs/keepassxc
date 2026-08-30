/*
 *  Copyright (C) 2026 KeePassXC Team <team@keepassxc.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 */

#include "TestFido2UnlockFile.h"

#include "config-keepassx.h"
#include "core/Config.h"
#include "crypto/Crypto.h"
#include "crypto/CryptoHash.h"
#include "crypto/Random.h"
#include "fido2/Fido2UnlockFile.h"
#include "gui/FileDialog.h"
#include "keys/ChallengeResponseKey.h"
#include "keys/CompositeKey.h"
#include "keys/FileKey.h"
#include "keys/PasswordKey.h"
#include "util/TemporaryFile.h"

#include <QSettings>
#include <QTest>

#include <botan/aead.h>
#include <botan/bigint.h>
#include <botan/ec_group.h>
#include <botan/ecdsa.h>
#include <botan/pubkey.h>

QTEST_GUILESS_MAIN(TestFido2UnlockFile)

namespace
{
    constexpr char userPresentFlag = 0x01;
    constexpr char userPresentAndVerifiedFlags = 0x05;

    QByteArray hex(const char* value)
    {
        return QByteArray::fromHex(value);
    }

    // Frozen cross-language unlock file vector. Keep these bytes independent of production encoding.
    QByteArray frozenUnlockFileVector(Fido2UnlockFile::PayloadPolicy policy)
    {
        if (policy == Fido2UnlockFile::PayloadPolicy::PasswordOnly) {
            return hex(
                "4b50594b554e4c4b000100000201000102030405060708090a0b0c0d0e0f6669646f322d656e76656c6f70652e6b656"
                "57061737378"
                "632e6f7267202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f010200001011121314151"
                "61718191a1b"
                "1c1d1e1f0f5072696d61727920597562694b65790010a0a1a2a3a4a5a6a7a8a9aaabacadaeaf6b17d1f2e12c4247f8b"
                "ce6e563a440"
                "f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf5"
                "1f5c0c1c2c3"
                "c4c5c6c7c8c9cacbb8b6dafdb625f7a9cf872ef84021a1ebd1e7d234af5e21c7182d650c30ccfbad78782a9eaa00fa8c"
                "622f709c68344cbf8a0c45aadf6806bc45d0a3156c8d2070d4c57e355761a5f55ab16dae6e1cf077010000005051525"
                "3545556575"
                "8595a5b5c5d"
                "5e5f0e4261636b757020597562694b65790010b0b1b2b3b4b5b6b7b8b9babbbcbdbebf7cf27b188d034f7e8a5238030"
                "4b51ac3c089"
                "69e277f21b35a60b48fc4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1d0d"
                "1d2d3d4d5d6"
                "d7d8d9dadb8a8e39431f2950638ee55895d62d86da0c321f061b7708390ec0a604706407422125cd0bc0cda5f33a6511"
                "e29690c1b6f586e6cd2bcef6b5b2df1165831f2ebddcf09f4b2928d0ba3beb373a5ea581b601000000");
        }

        return hex(
            "4b50594b554e4c4b000100000201000102030405060708090a0b0c0d0e0f6669646f322d656e76656c6f70652e6b65657061737378"
            "632e6f7267202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f02020000101112131415161718191a1b"
            "1c1d1e1f0f5072696d61727920597562694b65790010a0a1a2a3a4a5a6a7a8a9aaabacadaeaf6b17d1f2e12c4247f8bce6e563a440"
            "f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5c0c1c2c3"
            "c4c5c6c7c8c9cacbb8b6dafdb625f7a9cf872ef84021a1ebd1e7d234af5e21c7182d650c30ccfbad7879289dae05fc8b6a267a9764"
            "3942b09a1d57b9cb7d10ab5dc9b90e70903e6f75821c833fbb0663a8852f1d8be2f12801000000505152535455565758595a5b5c5d"
            "5e5f0e4261636b757020597562694b65790010b0b1b2b3b4b5b6b7b8b9babbbcbdbebf7cf27b188d034f7e8a52380304b51ac3c089"
            "69e277f21b35a60b48fc4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1d0d1d2d3d4d5d6"
            "d7d8d9dadb8a8e39431f2950638ee55895d62d86da0c321f061b7708390ec0a604706407422124cf08c4c8a3f4326c1be99a9dcfb9"
            "e597f4de3fdbe0a2aac60b7e9f0230a27bf9bc9cb56ff7ccbcb6fd4d4beb31b801000000");
    }

    QByteArray frozenHmacSecret()
    {
        return hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    }

    QByteArray frozenBackupHmacSecret()
    {
        return hex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf");
    }

    QByteArray frozenPasswordKey()
    {
        return hex("e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    }

    QByteArray frozenFileKey()
    {
        return hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    }

    QByteArray frozenAad(Fido2UnlockFile::PayloadPolicy policy, int wrapper)
    {
        const auto policyByte = policy == Fido2UnlockFile::PayloadPolicy::PasswordOnly ? "01" : "02";
        const auto slotAndCredential =
            wrapper == 0
                ? "101112131415161718191a1b1c1d1e1f001c6669646f322d656e76656c6f70652e6b65657061737378632e6f72670010"
                  "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
                  "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
                : "505152535455565758595a5b5c5d5e5f001c6669646f322d656e76656c6f70652e6b65657061737378632e6f72670010"
                  "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978"
                  "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1";
        return QByteArray::fromHex(QByteArray("4b50594b5349443100000001") + policyByte
                                   + "000102030405060708090a0b0c0d0e0f" + slotAndCredential
                                   + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f01");
    }

    QByteArray frozenCiphertext(Fido2UnlockFile::PayloadPolicy policy, int wrapper)
    {
        if (policy == Fido2UnlockFile::PayloadPolicy::PasswordOnly && wrapper == 0) {
            return hex("b8b6dafdb625f7a9cf872ef84021a1ebd1e7d234af5e21c7182d650c30ccfbad78782a9eaa00fa8c622f709c68344cb"
                       "f8a0c45aadf6806bc45d0a3156c8d2070d4c57e355761a5f55ab16dae6e1cf077");
        }
        if (policy == Fido2UnlockFile::PayloadPolicy::PasswordOnly) {
            return hex("8a8e39431f2950638ee55895d62d86da0c321f061b7708390ec0a604706407422125cd0bc0cda5f33a6511e29690c1b"
                       "6f586e6cd2bcef6b5b2df1165831f2ebddcf09f4b2928d0ba3beb373a5ea581b6");
        }
        if (wrapper == 0) {
            return hex("b8b6dafdb625f7a9cf872ef84021a1ebd1e7d234af5e21c7182d650c30ccfbad7879289dae05fc8b6a267a97643942b"
                       "09a1d57b9cb7d10ab5dc9b90e70903e6f75821c833fbb0663a8852f1d8be2f128");
        }
        return hex("8a8e39431f2950638ee55895d62d86da0c321f061b7708390ec0a604706407422124cf08c4c8a3f4326c1be99a9dcfb"
                   "9e597f4de3fdbe0a2aac60b7e9f0230a27bf9bc9cb56ff7ccbcb6fd4d4beb31b8");
    }

    QByteArray
    encryptPayload(const QByteArray& key, const QByteArray& nonce, const QByteArray& aad, const QByteArray& plaintext)
    {
#ifdef WITH_BOTAN3
        auto cipher = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Encryption);
#else
        auto cipher = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::ENCRYPTION);
#endif
        cipher->set_key(reinterpret_cast<const uint8_t*>(key.constData()), key.size());
        cipher->set_associated_data(reinterpret_cast<const uint8_t*>(aad.constData()), aad.size());
        cipher->start(reinterpret_cast<const uint8_t*>(nonce.constData()), nonce.size());
        Botan::secure_vector<uint8_t> output(plaintext.begin(), plaintext.end());
        cipher->finish(output);
        return QByteArray(reinterpret_cast<const char*>(output.data()), output.size());
    }

    QByteArray encodeCoordinate(Botan::BigInt value)
    {
        auto valueHex = QByteArray::fromStdString(value.to_hex_string());
        if (valueHex.startsWith("0x")) {
            valueHex.remove(0, 2);
        }
        if (valueHex.size() % 2 != 0) {
            valueHex.prepend('0');
        }
        auto result = QByteArray::fromHex(valueHex);
        result.prepend(QByteArray(32 - result.size(), '\0'));
        return result;
    }
} // namespace

void TestFido2UnlockFile::initTestCase()
{
    QVERIFY(Crypto::init());
}

void TestFido2UnlockFile::testVector()
{
    const QList<Fido2UnlockFile::PayloadPolicy> policies{Fido2UnlockFile::PayloadPolicy::PasswordOnly,
                                                         Fido2UnlockFile::PayloadPolicy::PasswordAndKeyFile};
    const QList<QByteArray> hmacSecrets{frozenHmacSecret(), frozenBackupHmacSecret()};
    QCOMPARE(frozenPasswordKey().size(), Fido2UnlockFile::PASSWORD_KEY_SIZE);

    for (const auto policy : policies) {
        const auto vector = frozenUnlockFileVector(policy);
        QCOMPARE(vector.size(), 513);

        Fido2UnlockFile::Envelope envelope;
        QString error;
        QVERIFY2(Fido2UnlockFile::parse(vector, envelope, error), qPrintable(error));
        QCOMPARE(static_cast<quint8>(envelope.payloadPolicy), static_cast<quint8>(policy));
        QCOMPARE(envelope.wrappers.size(), 2);
        QCOMPARE(envelope.wrappers.at(0).label, QStringLiteral("Primary YubiKey"));

        for (int wrapper = 0; wrapper < envelope.wrappers.size(); ++wrapper) {
            QCOMPARE(frozenAad(policy, wrapper).size(), 190);
            QCOMPARE(Fido2UnlockFile::associatedData(envelope, envelope.wrappers.at(wrapper)),
                     frozenAad(policy, wrapper));
            QCOMPARE(envelope.wrappers.at(wrapper).ciphertext, frozenCiphertext(policy, wrapper));

            QByteArray passwordKey;
            QByteArray fileKey;
            QVERIFY2(Fido2UnlockFile::unwrapKeys(
                         envelope, envelope.wrappers.at(wrapper), hmacSecrets.at(wrapper), passwordKey, fileKey, error),
                     qPrintable(error));
            QCOMPARE(passwordKey, frozenPasswordKey());
            if (policy == Fido2UnlockFile::PayloadPolicy::PasswordOnly) {
                QVERIFY(fileKey.isEmpty());
            } else {
                QCOMPARE(fileKey, frozenFileKey());
            }
            Fido2UnlockFile::clearSecret(passwordKey);
            Fido2UnlockFile::clearSecret(fileKey);
        }
    }
}

void TestFido2UnlockFile::testCanonicalRejection()
{
    auto malformed = frozenUnlockFileVector(Fido2UnlockFile::PayloadPolicy::PasswordOnly);
    malformed[13] = '\0';
    Fido2UnlockFile::Envelope envelope;
    envelope.envelopeId = QByteArrayLiteral("stale");
    envelope.wrappers.append(Fido2UnlockFile::Wrapper{});
    QString error;
    QVERIFY(!Fido2UnlockFile::parse(malformed, envelope, error));
    QVERIFY(envelope.envelopeId.isEmpty());
    QVERIFY(envelope.wrappers.isEmpty());

    malformed = frozenUnlockFileVector(Fido2UnlockFile::PayloadPolicy::PasswordOnly);
    malformed.append('\0');
    QVERIFY(!Fido2UnlockFile::parse(malformed, envelope, error));

    malformed = frozenUnlockFileVector(Fido2UnlockFile::PayloadPolicy::PasswordOnly);
    const auto firstWrapper = malformed.mid(94, 210);
    const auto secondWrapper = malformed.mid(304, 209);
    malformed = malformed.left(94) + secondWrapper + firstWrapper;
    QVERIFY(!Fido2UnlockFile::parse(malformed, envelope, error));

    malformed = frozenUnlockFileVector(Fido2UnlockFile::PayloadPolicy::PasswordOnly);
    malformed[90] = '\x03';
    QVERIFY(!Fido2UnlockFile::parse(malformed, envelope, error));

    malformed = frozenUnlockFileVector(Fido2UnlockFile::PayloadPolicy::PasswordOnly);
    malformed[92] = '\x01';
    QVERIFY(!Fido2UnlockFile::parse(malformed, envelope, error));

    malformed = frozenUnlockFileVector(Fido2UnlockFile::PayloadPolicy::PasswordOnly);
    const auto publicKey =
        hex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e16"
            "2bce33576b315ececbb6406837bf51f5");
    const auto publicKeyOffset = malformed.indexOf(publicKey);
    QVERIFY(publicKeyOffset >= 0);
    malformed.replace(publicKeyOffset, publicKey.size(), QByteArray(publicKey.size(), '\0'));
    envelope.envelopeId = QByteArrayLiteral("stale");
    envelope.envelopeSalt = QByteArrayLiteral("stale");
    envelope.wrappers.append(Fido2UnlockFile::Wrapper{});
    QVERIFY(!Fido2UnlockFile::parse(malformed, envelope, error));
    QVERIFY(envelope.envelopeId.isEmpty());
    QVERIFY(envelope.envelopeSalt.isEmpty());
    QCOMPARE(static_cast<quint8>(envelope.payloadPolicy), static_cast<quint8>(0));
    QVERIFY(envelope.wrappers.isEmpty());
}

void TestFido2UnlockFile::testUnwrapFailureClearsOutput()
{
    Fido2UnlockFile::Envelope envelope;
    QString error;
    QVERIFY(
        Fido2UnlockFile::parse(frozenUnlockFileVector(Fido2UnlockFile::PayloadPolicy::PasswordOnly), envelope, error));
    auto wrapper = envelope.wrappers.first();
    wrapper.ciphertext[0] ^= 1;
    QByteArray passwordKey = QByteArrayLiteral("stale-password-key");
    QByteArray fileKey = QByteArrayLiteral("stale-file-key");
    QVERIFY(!Fido2UnlockFile::unwrapKeys(envelope, wrapper, frozenHmacSecret(), passwordKey, fileKey, error));
    QVERIFY(passwordKey.isEmpty());
    QVERIFY(fileKey.isEmpty());

    wrapper = envelope.wrappers.first();
    envelope.payloadPolicy = Fido2UnlockFile::PayloadPolicy::PasswordAndKeyFile;
    passwordKey = QByteArrayLiteral("stale-password-key");
    fileKey = QByteArrayLiteral("stale-file-key");
    QVERIFY(!Fido2UnlockFile::unwrapKeys(envelope, wrapper, frozenHmacSecret(), passwordKey, fileKey, error));
    QVERIFY(passwordKey.isEmpty());
    QVERIFY(fileKey.isEmpty());
}

void TestFido2UnlockFile::testPasswordOnlyRejectsNonZeroFileKey()
{
    Fido2UnlockFile::Envelope envelope;
    QString error;
    QVERIFY(
        Fido2UnlockFile::parse(frozenUnlockFileVector(Fido2UnlockFile::PayloadPolicy::PasswordOnly), envelope, error));
    auto wrapper = envelope.wrappers.first();
    auto plaintext = frozenPasswordKey() + QByteArray(Fido2UnlockFile::FILE_KEY_SIZE, '\0');
    plaintext[plaintext.size() - 1] = '\x01';
    wrapper.ciphertext = encryptPayload(hex("7cd7d262476ba3900819bec1ac1f1734ead09312a38d15fccbc9aa85e85ea080"),
                                        wrapper.nonce,
                                        frozenAad(Fido2UnlockFile::PayloadPolicy::PasswordOnly, 0),
                                        plaintext);

    QByteArray passwordKey = QByteArrayLiteral("stale-password-key");
    QByteArray fileKey = QByteArrayLiteral("stale-file-key");
    QVERIFY(!Fido2UnlockFile::unwrapKeys(envelope, wrapper, frozenHmacSecret(), passwordKey, fileKey, error));
    QVERIFY(passwordKey.isEmpty());
    QVERIFY(fileKey.isEmpty());
}

void TestFido2UnlockFile::testAssertionVerification()
{
    Botan::ECDSA_PrivateKey privateKey(*randomGen()->getRng(), Botan::EC_Group("secp256r1"), Botan::BigInt(1));
    const auto& publicPoint = privateKey.public_point();
    Fido2UnlockFile::Wrapper wrapper;
    wrapper.publicKey = encodeCoordinate(publicPoint.get_affine_x()) + encodeCoordinate(publicPoint.get_affine_y());
    const auto clientDataHash = QByteArray(32, '\x80');
    QByteArray authenticatorData =
        CryptoHash::hash(QByteArrayLiteral("fido2-envelope.keepassxc.org"), CryptoHash::Sha256);
    authenticatorData.append(userPresentAndVerifiedFlags);
    authenticatorData.append(QByteArray(4, '\0'));
    const auto signAssertion = [&privateKey](const QByteArray& data) {
#ifdef WITH_BOTAN3
        Botan::PK_Signer signer(
            privateKey, *randomGen()->getRng(), "EMSA1(SHA-256)", Botan::Signature_Format::DerSequence);
#else
        Botan::PK_Signer signer(privateKey, *randomGen()->getRng(), "EMSA1(SHA-256)", Botan::DER_SEQUENCE);
#endif
        signer.update(reinterpret_cast<const uint8_t*>(data.constData()), data.size());
        const auto signedBytes = signer.signature(*randomGen()->getRng());
        return QByteArray(reinterpret_cast<const char*>(signedBytes.data()), signedBytes.size());
    };

    QString error;
    const auto signature = signAssertion(authenticatorData + clientDataHash);
    QVERIFY2(Fido2UnlockFile::verifyAssertion(wrapper, clientDataHash, authenticatorData, signature, error),
             qPrintable(error));
    authenticatorData[32] = userPresentFlag;
    const auto upOnlySignature = signAssertion(authenticatorData + clientDataHash);
    QVERIFY(!Fido2UnlockFile::verifyAssertion(wrapper, clientDataHash, authenticatorData, upOnlySignature, error));
}

void TestFido2UnlockFile::testCompositeKeyEquivalence()
{
    Fido2UnlockFile::Envelope passwordOnlyEnvelope;
    Fido2UnlockFile::Envelope passwordAndKeyFileEnvelope;
    QString error;
    QVERIFY(Fido2UnlockFile::parse(
        frozenUnlockFileVector(Fido2UnlockFile::PayloadPolicy::PasswordOnly), passwordOnlyEnvelope, error));
    QVERIFY(Fido2UnlockFile::parse(
        frozenUnlockFileVector(Fido2UnlockFile::PayloadPolicy::PasswordAndKeyFile), passwordAndKeyFileEnvelope, error));

    QByteArray passwordOnlyPassword;
    QByteArray passwordOnlyFile;
    QVERIFY(Fido2UnlockFile::unwrapKeys(passwordOnlyEnvelope,
                                        passwordOnlyEnvelope.wrappers.first(),
                                        frozenHmacSecret(),
                                        passwordOnlyPassword,
                                        passwordOnlyFile,
                                        error));
    QVERIFY(passwordOnlyFile.isEmpty());

    QByteArray wrappedPassword;
    QByteArray wrappedFile;
    QVERIFY(Fido2UnlockFile::unwrapKeys(passwordAndKeyFileEnvelope,
                                        passwordAndKeyFileEnvelope.wrappers.first(),
                                        frozenHmacSecret(),
                                        wrappedPassword,
                                        wrappedFile,
                                        error));

    auto externalFileKey = QSharedPointer<FileKey>::create();
    externalFileKey->setRawKey(frozenFileKey());
    auto wrappedFileKey = QSharedPointer<FileKey>::create();
    wrappedFileKey->setRawKey(wrappedFile);

    CompositeKey passwordOnlyComposite;
    passwordOnlyComposite.addKey(PasswordKey::fromRawKey(passwordOnlyPassword));
    passwordOnlyComposite.addKey(externalFileKey);

    CompositeKey passwordAndKeyFileComposite;
    passwordAndKeyFileComposite.addKey(PasswordKey::fromRawKey(wrappedPassword));
    passwordAndKeyFileComposite.addKey(wrappedFileKey);
    passwordAndKeyFileComposite.addChallengeResponseKey(QSharedPointer<ChallengeResponseKey>::create());

    QCOMPARE(passwordOnlyComposite.keys().size(), 2);
    QCOMPARE(passwordAndKeyFileComposite.keys().size(), 2);
    QCOMPARE(passwordAndKeyFileComposite.challengeResponseKeys().size(), 1);
    QCOMPARE(passwordOnlyComposite.rawKey(), passwordAndKeyFileComposite.rawKey());

    CompositeKey duplicateExternalFileComposite;
    duplicateExternalFileComposite.addKey(PasswordKey::fromRawKey(wrappedPassword));
    duplicateExternalFileComposite.addKey(wrappedFileKey);
    duplicateExternalFileComposite.addKey(externalFileKey);
    QVERIFY(duplicateExternalFileComposite.rawKey() != passwordAndKeyFileComposite.rawKey());

    Fido2UnlockFile::clearSecret(passwordOnlyPassword);
    Fido2UnlockFile::clearSecret(passwordOnlyFile);
    Fido2UnlockFile::clearSecret(wrappedPassword);
    Fido2UnlockFile::clearSecret(wrappedFile);
}

void TestFido2UnlockFile::testLocalUnlockFilePathMemory()
{
    TemporaryFile configFile;
    TemporaryFile localConfigFile;
    QVERIFY(configFile.open());
    QVERIFY(localConfigFile.open());
    Config::createConfigFromFile(configFile.fileName(), localConfigFile.fileName());
    const QString databasePath = QStringLiteral("/tmp/example.kdbx");
    const QString unlockFilePath = QStringLiteral("/tmp/example.kpxc-fido2");
    config()->set(Config::LastFido2UnlockFiles, QVariantHash{{databasePath, unlockFilePath}});
    config()->sync();

    QSettings roaming(configFile.fileName(), QSettings::IniFormat);
    QSettings local(localConfigFile.fileName(), QSettings::IniFormat);
    QVERIFY(!roaming.contains(QStringLiteral("LastFido2UnlockFiles")));
    QCOMPARE(local.value(QStringLiteral("LastFido2UnlockFiles")).toHash().value(databasePath).toString(),
             unlockFilePath);

    config()->remove(Config::LastFido2UnlockFiles);
    config()->sync();
    QVERIFY(!local.contains(QStringLiteral("LastFido2UnlockFiles")));
}

void TestFido2UnlockFile::testLocalUnlockModeMemory()
{
    TemporaryFile configFile;
    TemporaryFile localConfigFile;
    QVERIFY(configFile.open());
    QVERIFY(localConfigFile.open());
    Config::createConfigFromFile(configFile.fileName(), localConfigFile.fileName());
    const QString passwordDatabasePath = QStringLiteral("/tmp/password.kdbx");
    const QString fido2DatabasePath = QStringLiteral("/tmp/fido2.kdbx");
    config()->set(Config::LastUnlockModes, QVariantHash{{passwordDatabasePath, 0}, {fido2DatabasePath, 1}});
    config()->sync();

    QSettings roaming(configFile.fileName(), QSettings::IniFormat);
    QSettings local(localConfigFile.fileName(), QSettings::IniFormat);
    QVERIFY(!roaming.contains(QStringLiteral("LastUnlockModes")));
    const auto lastUnlockModes = local.value(QStringLiteral("LastUnlockModes")).toHash();
    QCOMPARE(lastUnlockModes.value(passwordDatabasePath).toInt(), 0);
    QCOMPARE(lastUnlockModes.value(fido2DatabasePath).toInt(), 1);

    config()->remove(Config::LastUnlockModes);
    config()->sync();
    QVERIFY(!local.contains(QStringLiteral("LastUnlockModes")));
}

void TestFido2UnlockFile::testUnlockFileLastDirectoryPreference()
{
    TemporaryFile unlockFile;
    QVERIFY(unlockFile.open());
    config()->set(Config::RememberLastDatabases, true);
    config()->set(Config::RememberLastKeyFiles, true);

    const auto role = QStringLiteral("fido2-unlock-file");
    FileDialog::saveLastDir(role, unlockFile.fileName(), true);
    QVERIFY(config()->get(Config::LastDir).toHash().contains(role));

    config()->set(Config::RememberLastKeyFiles, false);
    FileDialog::saveLastDir(role, {});
    QVERIFY(!config()->get(Config::LastDir).toHash().contains(role));
}
