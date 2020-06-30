/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
*
* Copyright 2013 - 2020, nymea GmbH
* Contact: contact@nymea.io
*
* This file is part of nymea.
* This project including source code and documentation is protected by
* copyright law, and remains the property of nymea GmbH. All rights, including
* reproduction, publication, editing and translation, are reserved. The use of
* this project is subject to the terms of a license agreement to be concluded
* with nymea GmbH in accordance with the terms of use of nymea GmbH, available
* under https://nymea.io/license
*
* GNU Lesser General Public License Usage
* Alternatively, this project may be redistributed and/or modified under the
* terms of the GNU Lesser General Public License as published by the Free
* Software Foundation; version 3. This project is distributed in the hope that
* it will be useful, but WITHOUT ANY WARRANTY; without even the implied
* warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
* Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public License
* along with this project. If not, see <https://www.gnu.org/licenses/>.
*
* For any further details and any questions please contact us under
* contact@nymea.io or see our FAQ/Licensing Information on
* https://nymea.io/license/faq
*
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#ifndef ZEROCONFSERVICEBROWSERNSDK_H
#define ZEROCONFSERVICEBROWSERNSDK_H

#include <QObject>
#include <QSocketNotifier>
#include <QHostAddress>
#include <QHostInfo>

#include "network/zeroconf/zeroconfserviceentry.h"
#include "network/zeroconf/zeroconfservicebrowser.h"
#include "network/zeroconf/zeroconfserviceentry.h"

#include <dns_sd.h>

class ZeroConfServiceBrowserDnssd: public ZeroConfServiceBrowser
{
    Q_OBJECT

public:
    explicit ZeroConfServiceBrowserDnssd(const QString &serviceType, QObject *parent = nullptr);
    ~ZeroConfServiceBrowserDnssd() override;

    QList<ZeroConfServiceEntry> serviceEntries() const override;

    static void DNSSD_API enumerateCallback(DNSServiceRef sdRef, DNSServiceFlags flags, uint32_t interfaceIndex, DNSServiceErrorType errorCode, const char *replyDomain, void *context);

    static void DNSSD_API browseCallback(DNSServiceRef sdRef, DNSServiceFlags flags, uint32_t interfaceIndex, DNSServiceErrorType errorCode, const char *serviceName, const char *regtype, const char *replyDomain, void *context);

    static void DNSSD_API resolveCallback(DNSServiceRef sdRef, DNSServiceFlags flags, uint32_t interfaceIndex, DNSServiceErrorType errorCode, const char *fullname, const char *hosttarget, uint16_t port, uint16_t txtLen, const unsigned char *txtRecord, void *context);


#ifdef AVAHI_COMPAT
private slots:
    void lookupFinished(const QHostInfo &info);
#else
    static void DNSSD_API addressCallback(DNSServiceRef sdRef, DNSServiceFlags flags, uint32_t interfaceIndex, DNSServiceErrorType errorCode, const char *hostname, const sockaddr *address, uint32_t ttl, void *context);
#endif

private:
    class Context {
    public:
        QString serviceType;
        QString name;
        QHostAddress address;
        QString domain;
        QString hostName;
        int port = 0;
        uint interfaceIndex = 0;
        QStringList txt;
        DNSServiceRef ref;
        QSocketNotifier *socketNotifier = nullptr;
        ZeroConfServiceBrowserDnssd *self = nullptr;
    };
    DNSServiceRef m_browser;
    QSocketNotifier *m_socketNotifier = nullptr;

    QHash<QString, ZeroConfServiceEntry> m_serviceEntries;
    QStringList m_serviceTypes;

    QHash<int, Context*> m_pendingLookups;

};

#endif // ZEROCONFSERVICEBROWSERNSDK_H
