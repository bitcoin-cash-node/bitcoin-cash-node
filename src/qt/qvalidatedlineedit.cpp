// Copyright (c) 2011-2016 The Bitcoin Core developers
// Copyright (c) 2021 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/qvalidatedlineedit.h>

#include <qt/bitcoinaddressvalidator.h>
#include <qt/guiconstants.h>

QValidatedLineEdit::QValidatedLineEdit(QWidget *parent)
    : QLineEdit(parent), valid(true), checkValidator(nullptr) {
    connect(this, &QValidatedLineEdit::textChanged, this,
            &QValidatedLineEdit::markValid);
}

void QValidatedLineEdit::setValid(bool _valid) {
    if (_valid == this->valid) {
        return;
    }

    if (_valid) {
        setStyleSheet("");
    } else {
        setStyleSheet(STYLE_INVALID);
    }
    this->valid = _valid;
}

void QValidatedLineEdit::focusInEvent(QFocusEvent *evt) {
    // Clear invalid flag on focus
    setValid(true);

    QLineEdit::focusInEvent(evt);
}

void QValidatedLineEdit::focusOutEvent(QFocusEvent *evt) {
    validate();

    QLineEdit::focusOutEvent(evt);
}

void QValidatedLineEdit::markValid() {
    // As long as a user is typing ensure we display state as valid
    setValid(true);
}

void QValidatedLineEdit::clear() {
    setValid(true);
    QLineEdit::clear();
}

void QValidatedLineEdit::setEnabled(bool enabled) {
    if (!enabled) {
        // A disabled QValidatedLineEdit should be marked valid
        setValid(true);
    } else {
        // Recheck validity when QValidatedLineEdit gets enabled
        validate();
    }

    QLineEdit::setEnabled(enabled);
}

bool QValidatedLineEdit::validate() {
    if (text().isEmpty()) {
        setValid(true);
    } else if (hasAcceptableInput()) {
        setValid(true);

        // Check contents on focus out
        if (checkValidator) {
            QString input = text();
            int pos = 0;
            setValid(checkValidator->validate(input, pos) == QValidator::Acceptable);
            // note: checkValidator may have modified the text, so update the text
            setText(input);
        }
    } else {
        setValid(false);
    }

    Q_EMIT validationDidChange(this);

    return valid;
}

void QValidatedLineEdit::setCheckValidator(const QValidator *v) {
    checkValidator = v;
}

bool QValidatedLineEdit::isValid() {
    // use checkValidator in case the QValidatedLineEdit is disabled
    if (checkValidator) {
        QString input = text();
        int pos = 0;
        if (checkValidator->validate(input, pos) == QValidator::Acceptable) {
            return true;
        }
    }

    return valid;
}
