/*
 *  Copyright (C) 2026 KeePassXC Team <team@keepassxc.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 */

#include "Fido2Broker.h"

#include "config-keepassx.h"
#include "fido2/Fido2UnlockFile.h"

#include <QFileInfo>
#include <QProcess>
#include <QSet>

#ifdef Q_OS_UNIX
#include <signal.h>
#include <sys/types.h>
#endif

namespace
{
    constexpr int requestHeaderSize = 12;
    constexpr int responseHeaderSize = 16;
    constexpr int maximumPayloadSize = 64 * 1024;
    constexpr int hashSize = 32;
    constexpr int maximumCredentialCount = 8;
    constexpr int maximumCredentialIdSize = 1024;
    constexpr int minimumPinSize = 4;
    constexpr int maximumPinSize = 63;
#ifdef Q_OS_UNIX
    // Allow the broker to complete a CTAP cancellation exchange without blocking the UI indefinitely.
    constexpr int cancellationTimeoutMs = 2000;
#endif
    constexpr int killTimeoutMs = 1000;
    constexpr quint16 protocolVersion = 1;
    constexpr quint16 getAssertionOperation = 2;
    constexpr quint16 reservedHeaderValue = 0;

    enum class ResponseStatus : quint16
    {
        Success = 0,
        FirstDefinedError = 1,
        LastDefinedError = 11,
        InternalError = 255,
    };

    const QByteArray requestMagic("KPYQ", 4);
    const QByteArray responseMagic("KPYR", 4);
    const QByteArray rpId("fido2-envelope.keepassxc.org", 28);

    // Frame integers and length prefixes are unsigned, big-endian values.
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

    bool appendLengthPrefixed(QByteArray& output, const QByteArray& value, int minimum, int maximum)
    {
        if (value.size() < minimum || value.size() > maximum) {
            return false;
        }
        appendUint16(output, static_cast<quint16>(value.size()));
        output.append(value);
        return true;
    }

    bool takeLengthPrefixed(const QByteArray& input, int& offset, QByteArray& value, int minimum, int maximum)
    {
        if (offset > input.size() - 2) {
            return false;
        }
        const auto size = readUint16(input, offset);
        offset += 2;
        if (size < minimum || size > maximum || size > input.size() - offset) {
            return false;
        }
        value = QByteArray(input.constData() + offset, size);
        offset += size;
        return true;
    }

    bool isDefinedErrorStatus(quint16 status)
    {
        return (status >= static_cast<quint16>(ResponseStatus::FirstDefinedError)
                && status <= static_cast<quint16>(ResponseStatus::LastDefinedError))
               || status == static_cast<quint16>(ResponseStatus::InternalError);
    }
} // namespace

Fido2Broker::Fido2Broker(QObject* parent)
    : QObject(parent)
{
}

Fido2Broker::~Fido2Broker()
{
    cancel();

    auto* process = m_process.data();
    if (!process) {
        return;
    }

    disconnect(process, nullptr, this, nullptr);
    clearProcessOutput(process);
    process->setParent(nullptr);
    connect(process, &QProcess::readyReadStandardOutput, process, [process] { clearProcessOutput(process); });
    connect(process,
            qOverload<int, QProcess::ExitStatus>(&QProcess::finished),
            process,
            [process](int, QProcess::ExitStatus) {
                clearProcessOutput(process);
                process->deleteLater();
            });
    m_process = nullptr;
}

bool Fido2Broker::getAssertion(const AssertRequest& request, AssertCallback callback, QString& error)
{
    if (isBusy()) {
        error = tr("A FIDO2 operation is already running.");
        return false;
    }
    auto frame = encodeAssertRequest(request, error);
    if (frame.isEmpty()) {
        return false;
    }

    const auto path = QString::fromUtf8(KPXC_FIDO2_BROKER_PATH);
    const QFileInfo executable(path);
    if (path.isEmpty() || !executable.isAbsolute() || !executable.isExecutable()) {
        Fido2UnlockFile::clearSecret(frame);
        error = tr("The packaged FIDO2 broker is unavailable.");
        return false;
    }

    m_request = std::move(frame);
    m_callback = std::move(callback);
    m_process = new QProcess(this);
    m_process->setProgram(path);
    m_process->setProcessChannelMode(QProcess::SeparateChannels);
    m_process->setStandardErrorFile(QProcess::nullDevice());
#ifdef Q_OS_UNIX
    m_process->setChildProcessModifier([] {
        // An early cancellation must remain pending until the broker installs
        // its handler and gives libfido2 the temporary unblocked I/O mask.
        sigset_t signalMask;
        ::sigemptyset(&signalMask);
        ::sigaddset(&signalMask, SIGUSR1);
        ::sigprocmask(SIG_BLOCK, &signalMask, nullptr);
    });
#endif
    connect(m_process, &QProcess::started, this, &Fido2Broker::processStarted);
    connect(m_process, &QProcess::readyReadStandardOutput, this, &Fido2Broker::processReadyRead);
    connect(m_process,
            qOverload<int, QProcess::ExitStatus>(&QProcess::finished),
            this,
            [this](int exitCode, QProcess::ExitStatus exitStatus) { processFinished(exitCode, exitStatus); });
    connect(m_process, &QProcess::errorOccurred, this, [this](QProcess::ProcessError) {
        if (m_process && m_process->error() == QProcess::FailedToStart) {
            finish(tr("Failed to start the packaged FIDO2 broker."));
        }
    });
    m_process->start(QIODevice::ReadWrite);
    return true;
}

bool Fido2Broker::isBusy() const
{
    return !m_process.isNull();
}

void Fido2Broker::cancel()
{
    m_callback = {};

    auto* process = m_process.data();
    if (process) {
        disconnect(process, nullptr, this, nullptr);
    }

    Fido2UnlockFile::clearSecret(m_request);
    Fido2UnlockFile::clearSecret(m_output);

    if (!process) {
        return;
    }

#ifdef Q_OS_UNIX
    if (process->state() != QProcess::NotRunning) {
        const auto processId = process->processId();
        if (processId > 0 && ::kill(static_cast<pid_t>(processId), SIGUSR1) == 0) {
            process->waitForFinished(cancellationTimeoutMs);
            clearProcessOutput(process);
        }
    }
#endif

    if (process->state() != QProcess::NotRunning) {
        process->kill();
        process->waitForFinished(killTimeoutMs);
        clearProcessOutput(process);
    }

    if (process->state() == QProcess::NotRunning) {
        clearProcessOutput(process);
        m_process = nullptr;
        delete process;
        return;
    }

    watchCancelledProcess(process);
}

QByteArray Fido2Broker::encodeAssertRequest(const AssertRequest& request, QString& error)
{
    if (request.clientDataHash.size() != hashSize || request.hmacSalt.size() != hashSize
        || request.credentialIds.isEmpty() || request.credentialIds.size() > maximumCredentialCount
        || request.pin.size() < minimumPinSize || request.pin.size() > maximumPinSize || request.pin.contains('\0')
        || QString::fromUtf8(request.pin).toUtf8() != request.pin) {
        error = QObject::tr("Invalid FIDO2 assertion request.");
        return {};
    }

    QByteArray payload = request.clientDataHash + request.hmacSalt;
    appendUint16(payload, static_cast<quint16>(rpId.size()));
    payload.append(rpId);
    payload.append(static_cast<char>(request.credentialIds.size()));

    QSet<QByteArray> uniqueCredentials;
    for (const auto& credentialId : request.credentialIds) {
        if (!appendLengthPrefixed(payload, credentialId, 1, maximumCredentialIdSize)
            || uniqueCredentials.contains(credentialId)) {
            Fido2UnlockFile::clearSecret(payload);
            error = QObject::tr("Invalid FIDO2 assertion credentials.");
            return {};
        }
        uniqueCredentials.insert(credentialId);
    }

    if (!appendLengthPrefixed(payload, request.pin, minimumPinSize, maximumPinSize)) {
        Fido2UnlockFile::clearSecret(payload);
        error = QObject::tr("Invalid FIDO2 assertion PIN.");
        return {};
    }

    QByteArray frame;
    frame.reserve(requestHeaderSize + payload.size());
    frame.append(requestMagic);
    appendUint16(frame, protocolVersion);
    appendUint16(frame, getAssertionOperation);
    appendUint32(frame, static_cast<quint32>(payload.size()));
    frame.append(payload);

    Fido2UnlockFile::clearSecret(payload);
    return frame;
}

bool Fido2Broker::decodeAssertResponse(const QByteArray& frame, AssertResponse& response, QString& error)
{
    Fido2UnlockFile::clearSecret(response.hmacSecret);
    response = {};

    if (frame.size() < responseHeaderSize || frame.left(4) != responseMagic || readUint16(frame, 4) != protocolVersion
        || readUint16(frame, 6) != getAssertionOperation || readUint16(frame, 10) != reservedHeaderValue
        || readUint32(frame, 12) > maximumPayloadSize
        || frame.size() != responseHeaderSize + static_cast<int>(readUint32(frame, 12))) {
        error = QObject::tr("Malformed FIDO2 broker response.");
        return false;
    }

    const auto status = readUint16(frame, 8);
    // Success payloads contain binary assertion fields; error payloads contain bounded UTF-8 text.
    if (status != static_cast<quint16>(ResponseStatus::Success)) {
        const auto payload = QByteArray(frame.constData() + responseHeaderSize, frame.size() - responseHeaderSize);
        if (!isDefinedErrorStatus(status) || payload.size() > 256) {
            error = QObject::tr("Malformed FIDO2 broker error response.");
            return false;
        }

        error = QString::fromUtf8(payload);
        if (error.toUtf8() != payload) {
            error = QObject::tr("Malformed FIDO2 broker error response.");
            return false;
        }
        if (error.isEmpty()) {
            error = QObject::tr("FIDO2 broker operation failed.");
        }
        return false;
    }

    AssertResponse parsed;
    int offset = responseHeaderSize;
    if (!takeLengthPrefixed(frame, offset, parsed.selectedCredentialId, 1, maximumCredentialIdSize)
        || !takeLengthPrefixed(frame, offset, parsed.authenticatorData, 1, 2048)
        || !takeLengthPrefixed(frame, offset, parsed.signature, 1, 256)
        || frame.size() - offset != Fido2UnlockFile::HMAC_SECRET_SIZE) {
        error = QObject::tr("Malformed FIDO2 assertion response.");
        return false;
    }

    parsed.hmacSecret = QByteArray(frame.constData() + offset, Fido2UnlockFile::HMAC_SECRET_SIZE);
    response = std::move(parsed);
    return true;
}

void Fido2Broker::processStarted()
{
    if (!m_process) {
        return;
    }
    if (m_process->write(m_request) != m_request.size()) {
        finish(tr("Failed to send the FIDO2 broker request."));
        return;
    }
    m_process->closeWriteChannel();
    Fido2UnlockFile::clearSecret(m_request);
}

void Fido2Broker::processReadyRead()
{
    if (!m_process) {
        return;
    }
    if (!readOutput()) {
        finish(tr("FIDO2 broker response is too large."));
    }
}

void Fido2Broker::processFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
    if (!m_process) {
        return;
    }

    if (!readOutput()) {
        finish(tr("FIDO2 broker response is too large."));
        return;
    }

    const auto responseIsOk = m_output.size() >= responseHeaderSize && m_output.left(4) == responseMagic
                              && readUint16(m_output, 4) == protocolVersion
                              && readUint16(m_output, 6) == getAssertionOperation
                              && readUint16(m_output, 8) == static_cast<quint16>(ResponseStatus::Success);
    // A success frame is trustworthy only when the broker also reports a clean process exit.
    if (responseIsOk && (exitStatus != QProcess::NormalExit || exitCode != 0)) {
        finish(tr("FIDO2 broker exited unexpectedly."));
        return;
    }

    AssertResponse response;
    QString error;
    if (!decodeAssertResponse(m_output, response, error)) {
        finish(error);
        return;
    }

    auto callback = std::move(m_callback);
    cleanup();

    if (callback) {
        callback(response, {});
    }

    Fido2UnlockFile::clearSecret(response.hmacSecret);
}

bool Fido2Broker::readOutput()
{
    constexpr int maximumOutputSize = responseHeaderSize + maximumPayloadSize;
    const auto remaining = maximumOutputSize - m_output.size();
    if (remaining < 0) {
        return false;
    }
    auto output = m_process->read(static_cast<qint64>(remaining) + 1);
    m_output.append(output);
    Fido2UnlockFile::clearSecret(output);
    return m_output.size() <= maximumOutputSize;
}

void Fido2Broker::finish(const QString& error)
{
    auto callback = std::move(m_callback);
    cleanup();
    if (callback) {
        callback({}, error);
    }
}

void Fido2Broker::cleanup()
{
    Fido2UnlockFile::clearSecret(m_request);
    Fido2UnlockFile::clearSecret(m_output);
    if (m_process) {
        disconnect(m_process, nullptr, this, nullptr);
        if (m_process->state() != QProcess::NotRunning) {
            m_process->kill();
        }
        m_process->deleteLater();
        m_process = nullptr;
    }
    m_callback = {};
}

void Fido2Broker::watchCancelledProcess(QProcess* process)
{
    connect(process, &QProcess::readyReadStandardOutput, this, [process] { clearProcessOutput(process); });
    connect(process,
            qOverload<int, QProcess::ExitStatus>(&QProcess::finished),
            this,
            [this, process](int, QProcess::ExitStatus) { cancelledProcessFinished(process); });
}

void Fido2Broker::cancelledProcessFinished(QProcess* process)
{
    clearProcessOutput(process);
    if (m_process == process) {
        m_process = nullptr;
    }
    process->deleteLater();
}

void Fido2Broker::clearProcessOutput(QProcess* process)
{
    auto output = process->readAllStandardOutput();
    Fido2UnlockFile::clearSecret(output);
}
