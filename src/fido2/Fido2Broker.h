/*
 *  Copyright (C) 2026 KeePassXC Team <team@keepassxc.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 */

#ifndef KEEPASSXC_FIDO2BROKER_H
#define KEEPASSXC_FIDO2BROKER_H

#include <QByteArray>
#include <QObject>
#include <QPointer>
#include <QProcess>

#include <functional>

class Fido2Broker : public QObject
{
public:
    struct AssertRequest
    {
        QByteArray clientDataHash;
        QByteArray hmacSalt;
        QList<QByteArray> credentialIds;
        QByteArray pin;
    };

    struct AssertResponse
    {
        QByteArray selectedCredentialId;
        QByteArray authenticatorData;
        QByteArray signature;
        QByteArray hmacSecret;
    };

    using AssertCallback = std::function<void(const AssertResponse&, const QString&)>;

    explicit Fido2Broker(QObject* parent = nullptr);
    ~Fido2Broker() override;

    /// Start one asynchronous assertion. Exactly one callback runs unless cancel() is called.
    bool getAssertion(const AssertRequest& request, AssertCallback callback, QString& error);

    /// Return whether a broker child is currently owned by this client.
    bool isBusy() const;

    /// Terminate the active child and discard its callback and secret buffers.
    void cancel();

    /// Encode a versioned broker get-assertion request frame.
    static QByteArray encodeAssertRequest(const AssertRequest& request, QString& error);

    /// Decode a broker response frame, including bounded UTF-8 error payloads.
    static bool decodeAssertResponse(const QByteArray& frame, AssertResponse& response, QString& error);

private:
    void processStarted();
    void processReadyRead();
    void processFinished(int exitCode, QProcess::ExitStatus exitStatus);
    bool readOutput();
    void finish(const QString& error);
    void cleanup();
    void watchCancelledProcess(QProcess* process);
    void cancelledProcessFinished(QProcess* process);
    static void clearProcessOutput(QProcess* process);

    QPointer<QProcess> m_process;
    QByteArray m_request;
    QByteArray m_output;
    AssertCallback m_callback;
};

#endif // KEEPASSXC_FIDO2BROKER_H
