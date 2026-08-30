/*
 *  Copyright (C) 2026 KeePassXC Team <team@keepassxc.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "TestSSHAgent.h"
#include "config-keepassx-tests.h"
#include "core/Config.h"
#include "core/Database.h"
#include "core/Entry.h"
#include "core/Group.h"
#include "crypto/Crypto.h"
#include "sshagent/KeeAgentSettings.h"
#include "sshagent/OpenSSHKeyGen.h"
#include "sshagent/SSHAgent.h"

#include <QElapsedTimer>
#include <QScopeGuard>
#include <QTest>

QTEST_GUILESS_MAIN(TestSSHAgent)

void TestSSHAgent::initTestCase()
{
    QVERIFY(Crypto::init());
    QLocale::setDefault(QLocale::c());

    // Create temporary config file
    const auto configFile = TemporaryFile::createTempConfigFile();
    Config::createConfigFromFile(configFile, configFile);

    // default config must not enable agent
    SSHAgent agent;
    QVERIFY(!agent.isEnabled());

    m_agentSocketFile.reset(new TemporaryFile(this));

    m_agentSocketFileName = m_agentSocketFile->fileName();
    QVERIFY(!m_agentSocketFileName.isEmpty());

    QStringList arguments;
    arguments << "-D" << "-a" << m_agentSocketFileName;

    QElapsedTimer timer;
    timer.start();

    qDebug() << "ssh-agent starting with arguments" << arguments;
    m_agentProcess.setProcessChannelMode(QProcess::ForwardedChannels);
    m_agentProcess.start("ssh-agent", arguments);
    m_agentProcess.closeWriteChannel();

    if (!m_agentProcess.waitForStarted()) {
        QSKIP("ssh-agent could not be started");
    }

    qDebug() << "ssh-agent started as pid" << m_agentProcess.processId();

    // we need to wait for the agent to open the socket before going into real tests
    QFileInfo socketFileInfo(m_agentSocketFileName);
    while (!timer.hasExpired(2000)) {
        if (socketFileInfo.exists()) {
            break;
        }
        QTest::qWait(10);
    }

    QVERIFY(socketFileInfo.exists());
    qDebug() << "ssh-agent initialized in" << timer.elapsed() << "ms";

    // initialize test key
    const QString keyString = QString("-----BEGIN OPENSSH PRIVATE KEY-----\n"
                                      "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
                                      "QyNTUxOQAAACDdlO5F2kF2WzedrBAHBi9wBHeISzXZ0IuIqrp0EzeazAAAAKjgCfj94An4\n"
                                      "/QAAAAtzc2gtZWQyNTUxOQAAACDdlO5F2kF2WzedrBAHBi9wBHeISzXZ0IuIqrp0EzeazA\n"
                                      "AAAEBe1iilZFho8ZGAliiSj5URvFtGrgvmnEKdiLZow5hOR92U7kXaQXZbN52sEAcGL3AE\n"
                                      "d4hLNdnQi4iqunQTN5rMAAAAH29wZW5zc2hrZXktdGVzdC1wYXJzZUBrZWVwYXNzeGMBAg\n"
                                      "MEBQY=\n"
                                      "-----END OPENSSH PRIVATE KEY-----\n");

    const QByteArray keyData = keyString.toLatin1();

    QVERIFY(m_key.parsePKCS1PEM(keyData));
}

void TestSSHAgent::init()
{
    // Reset the config state
    SSHAgent agent;
    agent.setEnabled(false);
    QString empty;
    agent.setAuthSockOverride(empty);
    config()->remove(Config::SSHAgent_AutoLoadAllowlists);
}

void TestSSHAgent::testConfiguration()
{
    SSHAgent agent;
    agent.setEnabled(true);
    QVERIFY(agent.isEnabled());

    // this will either be an empty string or the real ssh-agent socket path, doesn't matter
    QString defaultSocketPath = agent.socketPath(false);

    // overridden path must match default before setting an override
    QCOMPARE(agent.socketPath(true), defaultSocketPath);

    agent.setAuthSockOverride(m_agentSocketFileName);

    // overridden path must match what we set
    QCOMPARE(agent.socketPath(true), m_agentSocketFileName);

    // non-overridden path must match the default
    QCOMPARE(agent.socketPath(false), defaultSocketPath);
}

void TestSSHAgent::testIdentity()
{
    SSHAgent agent;
    agent.setEnabled(true);
    agent.setAuthSockOverride(m_agentSocketFileName);

    QVERIFY(agent.isAgentRunning());

    KeeAgentSettings settings;
    bool keyInAgent;

    QVariantHash autoLoadAllowlists;
    autoLoadAllowlists.insert(QStringLiteral("database"), QStringList{});
    config()->set(Config::SSHAgent_AutoLoadAllowlists, autoLoadAllowlists);

    // test adding a key works
    QVERIFY(agent.addIdentity(m_key, settings, m_uuid));
    QVERIFY(agent.checkIdentity(m_key, keyInAgent) && keyInAgent);

    // test non-conflicting key ownership doesn't throw an error
    QVERIFY(agent.addIdentity(m_key, settings, m_uuid));

    // test conflicting key ownership throws an error
    QUuid secondUuid("{11111111-1111-1111-1111-111111111111}");
    QVERIFY(!agent.addIdentity(m_key, settings, secondUuid));

    // test removing a key works
    QVERIFY(agent.removeIdentity(m_key));
    QVERIFY(agent.checkIdentity(m_key, keyInAgent) && !keyInAgent);
}

void TestSSHAgent::testAutoLoadAllowlists()
{
    SSHAgent agent;
    agent.setEnabled(true);
    agent.setAuthSockOverride(m_agentSocketFileName);

    QVERIFY(agent.isAgentRunning());
    QVERIFY(agent.clearAllAgentIdentities());
    const auto cleanupAgent = qScopeGuard([&agent] {
        agent.clearAllAgentIdentities();
        agent.setEnabled(false);
    });

    auto database = QSharedPointer<Database>::create();
    OpenSSHKey allowedKey = m_key;
    OpenSSHKey deniedKey;
    OpenSSHKey manualOnlyKey;
    QVERIFY(OpenSSHKeyGen::generateEd25519(deniedKey));
    QVERIFY(OpenSSHKeyGen::generateEd25519(manualOnlyKey));

    const auto addEntry = [&database](OpenSSHKey& key, bool addAtDatabaseOpen) {
        auto entry = new Entry();
        entry->setUuid(QUuid::createUuid());
        entry->setGroup(database->rootGroup());
        entry->attachments()->set(QStringLiteral("id_ed25519"), key.privateKey().toUtf8());

        KeeAgentSettings settings;
        settings.setAllowUseOfSshKey(true);
        settings.setAddAtDatabaseOpen(addAtDatabaseOpen);
        settings.setSelectedType(QStringLiteral("attachment"));
        settings.setAttachmentName(QStringLiteral("id_ed25519"));
        settings.toEntry(entry);
        return entry;
    };

    const auto allowedEntry = addEntry(allowedKey, true);
    addEntry(deniedKey, true);
    const auto manualOnlyEntry = addEntry(manualOnlyKey, false);

    const auto verifyLoaded = [&agent](const OpenSSHKey& key, bool expected) {
        bool loaded = false;
        QVERIFY(agent.checkIdentity(key, loaded));
        QCOMPARE(loaded, expected);
    };

    // A missing database member preserves the existing AddAtDatabaseOpen behavior.
    agent.databaseUnlocked(database);
    verifyLoaded(allowedKey, true);
    verifyLoaded(deniedKey, true);
    verifyLoaded(manualOnlyKey, false);
    QVERIFY(agent.clearAllAgentIdentities());

    const auto databaseId = database->rootGroup()->uuid().toString();
    QVERIFY(database->rootGroup()->uuid() != database->uuid());

    // A present empty allowlist suppresses all automatic loading.
    QVariantHash autoLoadAllowlists;
    autoLoadAllowlists.insert(databaseId, QStringList{});
    config()->set(Config::SSHAgent_AutoLoadAllowlists, autoLoadAllowlists);
    agent.databaseUnlocked(database);
    verifyLoaded(allowedKey, false);
    verifyLoaded(deniedKey, false);
    verifyLoaded(manualOnlyKey, false);

    // The stable root group UUID selects the database allowlist. Entries still need AddAtDatabaseOpen.
    autoLoadAllowlists.insert(databaseId,
                              QStringList{allowedEntry->uuid().toString(), manualOnlyEntry->uuid().toString()});
    config()->set(Config::SSHAgent_AutoLoadAllowlists, autoLoadAllowlists);
    agent.databaseUnlocked(database);
    verifyLoaded(allowedKey, true);
    verifyLoaded(deniedKey, false);
    verifyLoaded(manualOnlyKey, false);
}

void TestSSHAgent::testRemoveOnClose()
{
    SSHAgent agent;
    agent.setEnabled(true);
    agent.setAuthSockOverride(m_agentSocketFileName);

    QVERIFY(agent.isAgentRunning());

    KeeAgentSettings settings;
    bool keyInAgent;

    settings.setRemoveAtDatabaseClose(true);
    QVERIFY(agent.addIdentity(m_key, settings, m_uuid));
    QVERIFY(agent.checkIdentity(m_key, keyInAgent) && keyInAgent);
    agent.setEnabled(false);
    QVERIFY(agent.checkIdentity(m_key, keyInAgent) && !keyInAgent);
}

void TestSSHAgent::testLifetimeConstraint()
{
    SSHAgent agent;
    agent.setEnabled(true);
    agent.setAuthSockOverride(m_agentSocketFileName);

    QVERIFY(agent.isAgentRunning());

    KeeAgentSettings settings;
    bool keyInAgent;

    settings.setUseLifetimeConstraintWhenAdding(true);
    settings.setLifetimeConstraintDuration(2); // two seconds

    // identity should be in agent immediately after adding
    QVERIFY(agent.addIdentity(m_key, settings, m_uuid));
    QVERIFY(agent.checkIdentity(m_key, keyInAgent) && keyInAgent);

    QElapsedTimer timer;
    timer.start();

    // wait for the identity to time out
    while (!timer.hasExpired(5000)) {
        QVERIFY(agent.checkIdentity(m_key, keyInAgent));

        if (!keyInAgent) {
            break;
        }

        QTest::qWait(100);
    }

    QVERIFY(!keyInAgent);
}

void TestSSHAgent::testConfirmConstraint()
{
    SSHAgent agent;
    agent.setEnabled(true);
    agent.setAuthSockOverride(m_agentSocketFileName);

    QVERIFY(agent.isAgentRunning());

    KeeAgentSettings settings;
    bool keyInAgent;

    settings.setUseConfirmConstraintWhenAdding(true);

    QVERIFY(agent.addIdentity(m_key, settings, m_uuid));

    // we can't test confirmation itself is working but we can test the agent accepts the key
    QVERIFY(agent.checkIdentity(m_key, keyInAgent) && keyInAgent);

    QVERIFY(agent.removeIdentity(m_key));
    QVERIFY(agent.checkIdentity(m_key, keyInAgent) && !keyInAgent);
}

void TestSSHAgent::testToOpenSSHKey()
{
    KeeAgentSettings settings;
    settings.setSelectedType("file");
    settings.setFileName(QString("%1/id_rsa-encrypted-asn1").arg(QString(KEEPASSX_TEST_DATA_DIR)));

    OpenSSHKey key;
    settings.toOpenSSHKey("username", "correctpassphrase", QString(), nullptr, key, false);

    QVERIFY(!key.publicKey().isEmpty());
}

void TestSSHAgent::testKeyGenRSA()
{
    SSHAgent agent;
    agent.setEnabled(true);
    agent.setAuthSockOverride(m_agentSocketFileName);

    QVERIFY(agent.isAgentRunning());

    OpenSSHKey key;
    KeeAgentSettings settings;
    bool keyInAgent;

    QVERIFY(OpenSSHKeyGen::generateRSA(key, 2048));

    QVERIFY(agent.addIdentity(key, settings, m_uuid));
    QVERIFY(agent.checkIdentity(key, keyInAgent) && keyInAgent);
    QVERIFY(agent.removeIdentity(key));
    QVERIFY(agent.checkIdentity(key, keyInAgent) && !keyInAgent);
}

void TestSSHAgent::testKeyGenECDSA()
{
    SSHAgent agent;
    agent.setEnabled(true);
    agent.setAuthSockOverride(m_agentSocketFileName);

    QVERIFY(agent.isAgentRunning());

    OpenSSHKey key;
    KeeAgentSettings settings;
    bool keyInAgent;

    QVERIFY(OpenSSHKeyGen::generateECDSA(key, 256));

    QVERIFY(agent.addIdentity(key, settings, m_uuid));
    QVERIFY(agent.checkIdentity(key, keyInAgent) && keyInAgent);
    QVERIFY(agent.removeIdentity(key));
    QVERIFY(agent.checkIdentity(key, keyInAgent) && !keyInAgent);
}

void TestSSHAgent::testKeyGenEd25519()
{
    SSHAgent agent;
    agent.setEnabled(true);
    agent.setAuthSockOverride(m_agentSocketFileName);

    QVERIFY(agent.isAgentRunning());

    OpenSSHKey key;
    KeeAgentSettings settings;
    bool keyInAgent;

    QVERIFY(OpenSSHKeyGen::generateEd25519(key));

    QVERIFY(agent.addIdentity(key, settings, m_uuid));
    QVERIFY(agent.checkIdentity(key, keyInAgent) && keyInAgent);
    QVERIFY(agent.removeIdentity(key));
    QVERIFY(agent.checkIdentity(key, keyInAgent) && !keyInAgent);
}

void TestSSHAgent::cleanupTestCase()
{
    if (m_agentProcess.state() != QProcess::NotRunning) {
        qDebug() << "Killing ssh-agent pid" << m_agentProcess.processId();
        m_agentProcess.terminate();
        m_agentProcess.waitForFinished();
    }
}
