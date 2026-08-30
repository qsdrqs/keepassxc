/*
 *  Copyright (C) 2026 KeePassXC Team <team@keepassxc.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 */

#ifndef KEEPASSXC_TESTFIDO2UNLOCKFILE_H
#define KEEPASSXC_TESTFIDO2UNLOCKFILE_H

#include <QObject>

class TestFido2UnlockFile : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void testVector();
    void testCanonicalRejection();
    void testUnwrapFailureClearsOutput();
    void testPasswordOnlyRejectsNonZeroFileKey();
    void testAssertionVerification();
    void testCompositeKeyEquivalence();
    void testLocalUnlockFilePathMemory();
    void testLocalUnlockModeMemory();
    void testUnlockFileLastDirectoryPreference();
};

#endif // KEEPASSXC_TESTFIDO2UNLOCKFILE_H
