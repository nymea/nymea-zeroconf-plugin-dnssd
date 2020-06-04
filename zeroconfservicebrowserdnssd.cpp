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

#include "zeroconfservicebrowserdnssd.h"
#include "loggingcategories.h"

#include <QHostAddress>
#include <QtEndian>
#include <QHostInfo>

#include <netdb.h>

ZeroConfServiceBrowserDnssd::ZeroConfServiceBrowserDnssd(const QString &serviceType, QObject *parent) :
    ZeroConfServiceBrowser(QString(), parent)
{
    if (serviceType.isEmpty()) {
        qCWarning(dcPlatformZeroConf) << "The Bonjour plugin does not support browsing all services. You must specify a serviceType.";
        return;
    }

    DNSServiceErrorType err = DNSServiceBrowse(&m_browser, 0, 0, serviceType.toUtf8(), 0, (DNSServiceBrowseReply) ZeroConfServiceBrowserDnssd::browseCallback, this);
    if (err != kDNSServiceErr_NoError) {
        qCWarning(dcPlatformZeroConf) << "Failed to create service browser:" << err;
        return;
    }

    int sockFd = DNSServiceRefSockFD(m_browser);
    if (sockFd == -1) {
        DNSServiceRefDeallocate(m_browser);
        return;
    }

    m_socketNotifier = new QSocketNotifier(sockFd, QSocketNotifier::Read, this);
    connect(m_socketNotifier, &QSocketNotifier::activated, this, [this]{
        DNSServiceErrorType err = DNSServiceProcessResult(m_browser);
        if (err != kDNSServiceErr_NoError) {
            DNSServiceRefDeallocate(m_browser);
            m_socketNotifier->deleteLater();
        }
    });

    qCDebug(dcPlatformZeroConf) << "Service browser created.";
}

ZeroConfServiceBrowserDnssd::~ZeroConfServiceBrowserDnssd()
{
}

QList<ZeroConfServiceEntry> ZeroConfServiceBrowserDnssd::serviceEntries() const
{
    return m_serviceEntries;
}

void DNSSD_API ZeroConfServiceBrowserDnssd::browseCallback(DNSServiceRef sdRef, DNSServiceFlags flags, uint32_t interfaceIndex, DNSServiceErrorType errorCode, const char *serviceName, const char *regtype, const char *replyDomain, void *context)
{
    Q_UNUSED(sdRef)
    Q_UNUSED(flags)
    Q_UNUSED(errorCode)
    qCDebug(dcPlatformZeroConf) << "Browsing result:" << serviceName << regtype << replyDomain << context;
    ZeroConfServiceBrowserDnssd *self = static_cast<ZeroConfServiceBrowserDnssd*>(context);

    Context *resolverContext = new Context();
    resolverContext->self = self;
    resolverContext->name = QString::fromUtf8(serviceName);
    resolverContext->serviceType = QString::fromUtf8(regtype);
    resolverContext->serviceType.remove(QRegExp(".$"));
    resolverContext->domain = QString::fromUtf8(replyDomain);

    DNSServiceErrorType err = DNSServiceResolve(&resolverContext->ref, 0, interfaceIndex, serviceName, regtype, replyDomain, (DNSServiceResolveReply) ZeroConfServiceBrowserDnssd::resolveCallback, resolverContext);
    if (err != kDNSServiceErr_NoError) {
        qCWarning(dcPlatformZeroConf) << "Failed to create service resolver:" << err;
        delete resolverContext;
        return;
    }

    int sockFd = DNSServiceRefSockFD(resolverContext->ref);
    if (sockFd == -1) {
        DNSServiceRefDeallocate(resolverContext->ref);
        delete resolverContext;
        return;
    }

    resolverContext->socketNotifier = new QSocketNotifier(sockFd, QSocketNotifier::Read, self);
    connect(resolverContext->socketNotifier, &QSocketNotifier::activated, self, [resolverContext]{
        DNSServiceErrorType err = DNSServiceProcessResult(resolverContext->ref);
        if (err != kDNSServiceErr_NoError) {
            DNSServiceRefDeallocate(resolverContext->ref);
            resolverContext->socketNotifier->deleteLater();
            delete resolverContext;
        }
    });

}

void ZeroConfServiceBrowserDnssd::resolveCallback(DNSServiceRef sdRef, DNSServiceFlags flags, uint32_t interfaceIndex, DNSServiceErrorType errorCode, const char *fullname, const char *hosttarget, uint16_t port, uint16_t txtLen, const unsigned char *txtRecord, void *context)
{
    Q_UNUSED(sdRef)
    qCDebug(dcPlatformZeroConf) << "Resolve callback" << flags << interfaceIndex << errorCode << fullname << hosttarget << port << txtLen << txtRecord << context;

    Context *resolverContext = static_cast<Context*>(context);
    ZeroConfServiceBrowserDnssd *self = resolverContext->self;
    DNSServiceRefDeallocate(resolverContext->ref);
    delete resolverContext->socketNotifier;

    if (errorCode != kDNSServiceErr_NoError) {
        qCWarning(dcPlatformZeroConf) << "Failed to resolve service" << errorCode;
        delete resolverContext;
        return;
    }

    Context *addrContext = new Context();
    addrContext->self = self;
    addrContext->name = resolverContext->name;
    addrContext->serviceType = resolverContext->serviceType;
    addrContext->domain = resolverContext->domain;
    addrContext->hostName = QString::fromUtf8(hosttarget);
    addrContext->port = qFromBigEndian<quint16>(port);
    QStringList txt;
    qint16 recLen;
    while (txtLen > 0) {
        recLen = txtRecord[0];
        txtRecord++;
        QByteArray t((const char *)txtRecord, recLen);
        QList<QByteArray> pair = t.split('=');
        if (pair.size() == 2) {
            txt.append(pair.at(0) + "=" + pair.at(1));
        } else {
            txt.append(pair.at(0));
        }
        txtLen-= recLen + 1;
        txtRecord+= recLen;
    }
    addrContext->txt = txt;
    delete resolverContext;


    int jobId = QHostInfo::lookupHost(hosttarget, self, SLOT(lookupFinished(QHostInfo)));
    self->m_pendingLookups.insert(jobId, addrContext);
}

void ZeroConfServiceBrowserDnssd::lookupFinished(const QHostInfo &info)
{
    if (!m_pendingLookups.contains(info.lookupId())) {
        qCWarning(dcPlatformZeroConf()) << "Lookup finished but we don't have a request for it";
        return;
    }
    Context *addrContext = m_pendingLookups.take(info.lookupId());

    foreach (const QHostAddress &addr, info.addresses()) {
        if (addr.protocol() == QAbstractSocket::IPv4Protocol) {
            qCDebug(dcPlatformZeroConf()) << "Entry added" << addrContext->serviceType << addr;
            ZeroConfServiceEntry entry = ZeroConfServiceEntry(addrContext->name, addrContext->serviceType, info.addresses().first(), addrContext->domain, addrContext->hostName, addrContext->port, QAbstractSocket::IPv4Protocol, addrContext->txt, false, false, false, false, false);
            m_serviceEntries.append(entry);
            emit serviceEntryAdded(entry);
        }
    }
    delete addrContext;
}
