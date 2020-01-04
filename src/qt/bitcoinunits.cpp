// Copyright (c) 2011-2016 The Bitcoin Core developers
// Copyright (c) 2021 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/bitcoinunits.h>

#include <primitives/transaction.h>

#include <QLocale>
#include <QStringList>

#include <cassert>

BitcoinUnits::BitcoinUnits(QObject *parent)
    : QAbstractListModel(parent), unitlist(availableUnits()) {}

QList<BitcoinUnits::Unit> BitcoinUnits::availableUnits() {
    QList<BitcoinUnits::Unit> unitlist;
    unitlist.append(BCH);
    unitlist.append(mBCH);
    unitlist.append(uBCH);
    unitlist.append(SAT);
    return unitlist;
}

bool BitcoinUnits::valid(int unit) {
    switch (unit) {
        case BCH:
        case mBCH:
        case uBCH:
        case SAT:
            return true;
        default:
            return false;
    }
}

QString BitcoinUnits::ticker(int unit) {
    switch (unit) {
        case BCH:
            return QString("BCH");
        case mBCH:
            return QString("mBCH");
        case uBCH:
            return QString::fromUtf8("μBCH");
        case SAT:
            return QString("sat");
        default:
            return QString("???");
    }
}

QString BitcoinUnits::description(int unit) {
    constexpr auto thinUtf8 = BitcoinSpaces::thinUtf8;
    switch (unit) {
        case BCH:
            return QObject::tr("bitcoins");
        case mBCH:
            return QObject::tr("millibitcoins") + " (1 / 1" + thinUtf8 + "000)";
        case uBCH:
            return QObject::tr("microbitcoins/bits") + " (1 / 1" + thinUtf8 + "000" + thinUtf8 + "000)";
        case SAT:
            return QObject::tr("satoshis") + " (1 / 100" + thinUtf8 + "000" + thinUtf8 + "000)";
        default:
            return QString("???");
    }
}

qint64 BitcoinUnits::factor(int unit) {
    switch (unit) {
        case BCH:
            return 100000000;
        case mBCH:
            return 100000;
        case uBCH:
            return 100;
        case SAT:
            return 1;
        default:
            return 100000000;
    }
}

int BitcoinUnits::decimals(int unit) {
    switch (unit) {
        case BCH:
            return 8;
        case mBCH:
            return 5;
        case uBCH:
            return 2;
        case SAT:
            return 0;
        default:
            return 0;
    }
}

bool BitcoinUnits::decimalSeparatorIsComma() {
    // Considering that:
    // * bitcoin is an international currency;
    // * Bitcoin-Qt uses only spaces as group separator, as recommended by SI;
    // * Bitcoin-Qt traditionally displays amounts with the dot as decimal separator;
    // * Bitcoin-Qt traditionally accepts both dots and commas as decimal separators in input amounts;
    // * some locales use dots as group separator rather than decimal separator;
    // * some locales have different decimal separators for currency amounts and other numbers;
    // * one cannot retrieve the decimal separator for currency amounts from QLocale;
    // * decimal separators other than dot and comma are rare, especially on computers;
    // this function suggests the dot as decimal separator for displaying amounts,
    // with comma as the fallback if a reader could mistake the dot for a group separator.
    return QString(QLocale().groupSeparator()) == ".";
}

QString BitcoinUnits::format(int unit, const Amount nIn, bool fPlus,
                             SeparatorStyle separators, bool justify) {
    // Note: not using straight sprintf here because we do NOT want
    // standard localized number formatting.
    if (!valid(unit)) {
        // Refuse to format invalid unit
        return QString();
    }
    qint64 n = qint64(nIn / SATOSHI);
    qint64 coin = factor(unit);
    int num_decimals = decimals(unit);
    qint64 n_abs = (n > 0 ? n : -n);
    qint64 quotient = n_abs / coin;
    QString quotient_str = QString::number(quotient);
    if (justify) {
        quotient_str = quotient_str.rightJustified(16 - num_decimals, ' ');
    }

    // Use SI-style thin space separators as these are locale independent and
    // can't be confused with the decimal marker.
    int q_size = quotient_str.size();
    if (separators == separatorAlways ||
        (separators == separatorStandard && q_size > 4)) {
        for (int i = 3; i < q_size; i += 3) {
            quotient_str.insert(q_size - i, BitcoinSpaces::thin);
        }
    }

    if (n < 0) {
        quotient_str.insert(0, '-');
    } else if (fPlus && n > 0) {
        quotient_str.insert(0, '+');
    }

    if (num_decimals > 0) {
        qint64 remainder = n_abs % coin;
        QString remainder_str =
            QString::number(remainder).rightJustified(num_decimals, '0');
        return quotient_str + (decimalSeparatorIsComma() ? ',' : '.') + remainder_str;
    } else {
        return quotient_str;
    }
}

// NOTE: Using formatWithUnit in an HTML context risks wrapping
// quantities at the thousands separator. More subtly, it also results
// in a standard space rather than a thin space, due to a bug in Qt's
// XML whitespace canonicalisation
//
// Please take care to use formatHtmlWithUnit instead, when
// appropriate.

QString BitcoinUnits::formatWithUnit(int unit, const Amount amount,
                                     bool plussign, SeparatorStyle separators) {
    return format(unit, amount, plussign, separators) + " " + ticker(unit);
}

QString BitcoinUnits::formatHtmlWithUnit(int unit, const Amount amount,
                                         bool plussign,
                                         SeparatorStyle separators) {
    QString str(formatWithUnit(unit, amount, plussign, separators));
    str.replace(BitcoinSpaces::thin, QString(BitcoinSpaces::thinHtml));
    return QString("<span style='white-space: nowrap;'>%1</span>").arg(str);
}

QString BitcoinUnits::formatWithPrivacy(int unit, const Amount &amount,
                                        SeparatorStyle separators,
                                        bool privacy) {
    assert(amount >= Amount::zero());
    QString value;
    if (privacy) {
        value = format(unit, Amount::zero(), false, separators, true)
                    .replace('0', '#');
    } else {
        value = format(unit, amount, false, separators, true);
    }
    return value + QString(" ") + ticker(unit);
}

std::optional<Amount> BitcoinUnits::parse(int unit, bool allowComma, const QString& value) {
    if (!valid(unit) || value.isEmpty()) {
        // Refuse to parse invalid unit or empty string
        return std::nullopt;
    }
    const int num_decimals = decimals(unit);

    // Ignore spaces and thin spaces when parsing
    QString trimmed = removeSpaces(value);
    // If comma is allowed, accept both comma and dot as decimal separators
    if (allowComma) {
        trimmed.replace(',', '.');
    }
    const QStringList parts = trimmed.split('.');

    if (parts.size() > 2) {
        // More than one decimal separator
        return std::nullopt;
    }
    const QString& whole = parts[0];
    QString decimals;

    if (parts.size() > 1) {
        decimals = parts[1];
    }
    if (decimals.size() > num_decimals) {
        // Exceeds max precision
        return std::nullopt;
    }

    const QString str = whole + decimals.leftJustified(num_decimals, '0');
    if (str.size() > 18) {
        // Longer numbers will exceed 63 bits
        return std::nullopt;
    }
    bool ok = false;
    const int64_t sats = int64_t(str.toLongLong(&ok));
    if (!ok) {
        // String-to-integer conversion failed
        return std::nullopt;
    }
    return sats * SATOSHI;
}

QString BitcoinUnits::getAmountColumnTitle(int unit) {
    QString amountTitle = QObject::tr("Amount");
    if (BitcoinUnits::valid(unit)) {
        amountTitle += " (" + BitcoinUnits::ticker(unit) + ")";
    }
    return amountTitle;
}

int BitcoinUnits::rowCount(const QModelIndex &parent) const {
    Q_UNUSED(parent);
    return unitlist.size();
}

QVariant BitcoinUnits::data(const QModelIndex &index, int role) const {
    int row = index.row();
    if (row >= 0 && row < unitlist.size()) {
        Unit unit = unitlist.at(row);
        switch (role) {
            case Qt::EditRole:
            case Qt::DisplayRole:
                return QVariant(ticker(unit));
            case Qt::ToolTipRole:
                return QVariant(description(unit));
            case UnitRole:
                return QVariant(static_cast<int>(unit));
        }
    }
    return QVariant();
}
