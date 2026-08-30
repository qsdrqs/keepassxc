/*
 *  Copyright (C) 2026 KeePassXC Team <team@keepassxc.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 */

#include "TestFido2Broker.h"

#include "fido2/Fido2Broker.h"
#include "fido2/Fido2UnlockFile.h"

#include <QTest>

QTEST_GUILESS_MAIN(TestFido2Broker)

namespace
{
    QByteArray hex(const char* value)
    {
        return QByteArray::fromHex(value);
    }

    // Frozen cross-language broker vectors. Keep these bytes independent of production framing.
    QByteArray frozenAssertRequestFrame()
    {
        return hex(
            "4b5059510001000200000089000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252"
            "62728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f001c6669646f322d656e76656c6f70652e6b65657061737378"
            "632e6f7267020010a0a1a2a3a4a5a6a7a8a9aaabacadaeaf0010b0b1b2b3b4b5b6b7b8b9babbbcbdbebf000431323334");
    }

    QByteArray frozenAssertResponseFrame()
    {
        return hex("4b5059520001000200000000000000a10010b0b1b2b3b4b5b6b7b8b9babbbcbdbebf0025c0c1c2c3c4c5c6c7c8c9cacbc"
                   "ccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e40046101112131415161718191a1b1c1d1e1f202122232425"
                   "262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455e"
                   "0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    }

    QByteArray frozenHmacSecret()
    {
        return hex("e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    }
} // namespace

void TestFido2Broker::testAssertRequestVector()
{
    Fido2Broker::AssertRequest request;
    request.clientDataHash = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    request.hmacSalt = hex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
    request.credentialIds = {hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"), hex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf")};
    request.pin = QByteArrayLiteral("1234");

    QString error;
    QCOMPARE(Fido2Broker::encodeAssertRequest(request, error), frozenAssertRequestFrame());
}

void TestFido2Broker::testAssertResponseVector()
{
    Fido2Broker::AssertResponse response;
    QString error;
    QVERIFY2(Fido2Broker::decodeAssertResponse(frozenAssertResponseFrame(), response, error), qPrintable(error));
    QCOMPARE(response.selectedCredentialId, hex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"));
    QCOMPARE(response.hmacSecret, frozenHmacSecret());
    Fido2UnlockFile::clearSecret(response.hmacSecret);
}

void TestFido2Broker::testMalformedFrames()
{
    Fido2Broker::AssertResponse response;
    response.selectedCredentialId = QByteArrayLiteral("stale-id");
    response.authenticatorData = QByteArrayLiteral("stale-data");
    response.signature = QByteArrayLiteral("stale-signature");
    response.hmacSecret = QByteArrayLiteral("stale-secret");
    QString error;
    QVERIFY(!Fido2Broker::decodeAssertResponse(QByteArrayLiteral("KPYR"), response, error));
    QVERIFY(response.selectedCredentialId.isEmpty());
    QVERIFY(response.authenticatorData.isEmpty());
    QVERIFY(response.signature.isEmpty());
    QVERIFY(response.hmacSecret.isEmpty());
    Fido2Broker::AssertRequest request;
    request.clientDataHash = QByteArray(32, '\x01');
    request.hmacSalt = QByteArray(32, '\x02');
    request.credentialIds = {QByteArray(16, '\x03'), QByteArray(16, '\x03')};
    request.pin = QByteArrayLiteral("1234");
    QVERIFY(Fido2Broker::encodeAssertRequest(request, error).isEmpty());

    request.credentialIds = {QByteArray(16, '\x03')};
    request.pin = QByteArrayLiteral("1234");
    request.pin[0] = static_cast<char>(0xc3);
    request.pin[1] = static_cast<char>(0x28);
    QVERIFY(Fido2Broker::encodeAssertRequest(request, error).isEmpty());
}
