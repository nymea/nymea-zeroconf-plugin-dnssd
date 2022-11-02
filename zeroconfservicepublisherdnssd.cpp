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

#include "zeroconfservicepublisherdnssd.h"

#include <loggingcategories.h>
#include <QNetworkInterface>
#include <QtEndian>

ZeroConfServicePublisherDnssd::ZeroConfServicePublisherDnssd(QObject *parent) : ZeroConfServicePublisher(parent)
{
}

bool ZeroConfServicePublisherDnssd::registerService(const QString &name, const QHostAddress &hostAddress, const quint16 &port, const QString &serviceType, const QHash<QString, QString> &txtRecords)
{
    if (m_services.contains(name)) {
        qCDebug(dcPlatformZeroConf) << "Service" << name << "already registered. Cannot reregister.";
        return false;
    }


    Context *ctx = new Context();
    ctx->self = this;
    ctx->name = name;

    return registerServiceInternal(ctx, hostAddress, port, serviceType, txtRecords);
}

bool ZeroConfServicePublisherDnssd::registerServiceInternal(ZeroConfServicePublisherDnssd::Context *ctx, const QHostAddress &hostAddress, const quint16 &port, const QString &serviceType, const QHash<QString, QString> &txtRecords)
{

    uint32_t ifIndex = 0;
    if (hostAddress != QHostAddress("0.0.0.0")) {
        foreach (const QNetworkInterface &interface, QNetworkInterface::allInterfaces()) {
            foreach (const QNetworkAddressEntry &addressEntry, interface.addressEntries()) {
                QPair<QHostAddress, int> subnet = QHostAddress::parseSubnet(addressEntry.ip().toString() + "/" + addressEntry.netmask().toString());
                if (hostAddress.isInSubnet(subnet.first, subnet.second)) {
                    ifIndex = static_cast<uint32_t>(interface.index());
                    break;
                }
            }
        }
    }

    QByteArray txt;
    foreach (const QString &key, txtRecords.keys()) {
        QString record = key;
        record.append("=");
        record.append(txtRecords.value(key));
        txt.append(static_cast<quint8>(record.size()));
        txt.append(record.toUtf8());
    }

    ctx->effectiveName = ctx->name + ((ctx->collisionIndex > 0) ? " #" + QString::number(ctx->collisionIndex) : "");

    DNSServiceErrorType err = DNSServiceRegister(&ctx->ref, 0, ifIndex, ctx->effectiveName.toUtf8().data(), serviceType.toUtf8().data(), 0, 0, qFromBigEndian<quint16>(port), txt.length(), txt, (DNSServiceRegisterReply) registerCallback, ctx);
    if (err != kDNSServiceErr_NoError) {
        qCWarning(dcPlatformZeroConf) << "Failed to register ZeroConf service" << ctx->name << "with dns_sd. Error:" << err;
        if (err == kDNSServiceErr_NameConflict) {
            qCDebug(dcPlatformZeroConf()) << "Handling service collision";
            ctx->collisionIndex++;
            return registerServiceInternal(ctx, hostAddress, port, serviceType, txtRecords);
        }
        delete ctx;
        return false;
    }

    int sockFd = DNSServiceRefSockFD(ctx->ref);
    if (sockFd == -1) {
        qCWarning(dcPlatformZeroConf) << "Error obtaining ZeroConf socket descriptor.";
        DNSServiceRefDeallocate(ctx->ref);
        delete ctx;
        return false;
    }

    ctx->socketNotifier = new QSocketNotifier(sockFd, QSocketNotifier::Read, this);
    connect(ctx->socketNotifier, &QSocketNotifier::activated, this, [this, ctx]{
        DNSServiceErrorType err = DNSServiceProcessResult(ctx->ref);
        if (err != kDNSServiceErr_NoError) {
            qCWarning(dcPlatformZeroConf) << "Error processing ZeroConf Socket data.";
            DNSServiceRefDeallocate(ctx->ref);
            m_services.remove(ctx->name);
            ctx->socketNotifier->deleteLater();
            delete ctx;
        }
    });

    m_services.insert(ctx->name, ctx);
    qCDebug(dcPlatformZeroConf) << "ZeroConf service" << ctx->name << serviceType << port << "registerd at dns_sd as" << ctx->effectiveName;
    return true;

}

void ZeroConfServicePublisherDnssd::unregisterService(const QString &name)
{
    if (!m_services.contains(name)) {
        qCDebug(dcPlatformZeroConf) << "Service" << name << "unknown. Cannot unregister.";
        return;
    }

    qCDebug(dcPlatformZeroConf) << "ZeroConf service" << name << "unregistered";
    Context *ctx = m_services.take(name);
    ctx->socketNotifier->deleteLater();
    DNSServiceRefDeallocate(ctx->ref);
    delete ctx;
}

void DNSSD_API ZeroConfServicePublisherDnssd::registerCallback(DNSServiceRef, DNSServiceFlags, DNSServiceErrorType errorCode, const char *, const char *, const char *, void *userdata)
{
    if (errorCode != kDNSServiceErr_NoError) {
        Context *ctx = static_cast<Context*>(userdata);
        qCWarning(dcPlatformZeroConf) << "Zeroconf registration failed with error code" << errorCode << ctx->name;
        DNSServiceRefDeallocate(ctx->ref);
        ctx->self->m_services.remove(ctx->name);
        ctx->socketNotifier->deleteLater();
        delete ctx;
    }
}

