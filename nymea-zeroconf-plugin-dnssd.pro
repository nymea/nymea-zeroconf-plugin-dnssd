TEMPLATE = lib
TARGET = $$qtLibraryTarget(nymea_zeroconfplugindnssd)

QT -= gui
QT += network dbus

QMAKE_CXXFLAGS += -Werror

CONFIG += plugin link_pkgconfig c++11
PKGCONFIG += nymea

LIBS += -ldns_sd

SOURCES += platformzeroconfcontrollerdnssd.cpp \
    zeroconfservicebrowserdnssd.cpp \
    zeroconfservicepublisherdnssd.cpp


HEADERS += platformzeroconfcontrollerdnssd.h \
    zeroconfservicebrowserdnssd.h \
    zeroconfservicepublisherdnssd.h


target.path = $$[QT_INSTALL_LIBS]/nymea/platform/
INSTALLS += target
