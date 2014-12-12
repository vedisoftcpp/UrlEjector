TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle

SOURCES += main.cpp

win32 {
INCLUDEPATH += $$PWD/../../Local/Include
LIBS += -L$$PWD/../../Local/Lib/ -lwpcap
}


