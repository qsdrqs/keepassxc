/*
 *  Copyright (C) 2011 Felix Geyer <debfx@fobos.de>
 *  Copyright (C) 2017 KeePassXC Team <team@keepassxc.org>
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

#ifndef KEEPASSX_DATABASEOPENWIDGET_H
#define KEEPASSX_DATABASEOPENWIDGET_H

#include <QPointer>
#include <QScopedPointer>
#include <QTimer>

#include "fido2/Fido2Broker.h"
#include "fido2/Fido2UnlockFile.h"
#include "gui/DialogyWidget.h"
#include "gui/MessageWidget.h"
#include "osutils/DeviceListener.h"

class CompositeKey;
class Database;
class FileKey;
class QFile;
class PasswordKey;
class QPushButton;
class PasswordWidget;
class QWidget;

namespace Ui
{
    class DatabaseOpenWidget;
}

class DatabaseOpenWidget : public DialogyWidget
{
    Q_OBJECT

public:
    explicit DatabaseOpenWidget(QWidget* parent = nullptr);
    ~DatabaseOpenWidget() override;
    void load(const QString& filename);
    QString filename();
    void clearForms();
    void enterKey(const QString& pw, const QString& keyFile);
    QSharedPointer<Database> database();
    bool unlockingDatabase();
    void showMessage(const QString& text, MessageWidget::MessageType type, int autoHideTimeout);

    // Quick Unlock helper functions
    bool canPerformQuickUnlock() const;
    bool isOnQuickUnlockScreen() const;
    void toggleQuickUnlockScreen();
    void triggerQuickUnlock();
    void resetQuickUnlock();

signals:
    void dialogFinished(bool accepted);

protected:
    bool event(QEvent* event) override;
    void keyPressEvent(QKeyEvent* event) override;
    QSharedPointer<CompositeKey> buildDatabaseKey(const QSharedPointer<PasswordKey>& fido2PasswordKey = {},
                                                  const QSharedPointer<FileKey>& fido2FileKey = {});
    void setUserInteractionLock(bool state);

    const QScopedPointer<Ui::DatabaseOpenWidget> m_ui;
    QSharedPointer<Database> m_db;
    QString m_filename;
    bool m_retryUnlockWithEmptyPassword = false;

protected slots:
    virtual void openDatabase();
    void reject();

private slots:
    bool browseKeyFile();
    bool browseFido2UnlockFile();
    void toggleHardwareKeyComponent(bool state);
    void closeDatabase();
    void pollHardwareKey(bool manualTrigger = false, int delay = 0);
    void hardwareKeyResponse(bool found);

private:
    enum class UnlockMode
    {
        Password = 0,
        Fido2 = 1,
    };

    void setUnlockMode(UnlockMode mode, bool remember);
    void updateUnlockModeLink();
    void focusUnlockInput();
    void openDatabaseWithKey(bool blockQuickUnlock,
                             const QSharedPointer<PasswordKey>& fido2PasswordKey = {},
                             const QSharedPointer<FileKey>& fido2FileKey = {});
    void startFido2Unlock(bool blockQuickUnlock);
    void finishFido2Unlock(const Fido2Broker::AssertResponse& response,
                           const QString& error,
                           const Fido2UnlockFile::Envelope& envelope,
                           const QByteArray& clientDataHash,
                           bool blockQuickUnlock);
    void handleFido2UnlockError(const QString& error);

    QPointer<DeviceListener> m_deviceListener;
    QPointer<QWidget> m_fido2UnlockFileComponent;
    QPointer<PasswordWidget> m_fido2UnlockFilePath;
    QPointer<QPushButton> m_fido2UnlockFileBrowseButton;
    QPointer<PasswordWidget> m_fido2PinWidget;
    QPointer<Fido2Broker> m_fido2Broker;
    UnlockMode m_unlockMode = UnlockMode::Password;
    bool m_pollingHardwareKey = false;
    bool m_manualHardwareKeyRefresh = false;
    bool m_blockQuickUnlock = false;
    bool m_unlockingDatabase = false;
    bool m_triedToQuit = false;
    QTimer m_hideTimer;
    QTimer m_hideNoHardwareKeysFoundTimer;

    Q_DISABLE_COPY(DatabaseOpenWidget)
};

#endif // KEEPASSX_DATABASEOPENWIDGET_H
