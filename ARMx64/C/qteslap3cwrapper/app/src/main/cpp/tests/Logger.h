//
// Created by tuxed on 12.08.2019.
//

#ifndef QTESLAP3C_LOGGER_H
#define QTESLAP3C_LOGGER_H

#include <vector>
#include <cstring>
#include <string>
#include <iostream>
#include "../config.h"


using namespace std;


class Logger {
public:
    static Logger& instance()
    {
        static Logger _instance;
        return _instance;
    }
    ~Logger() {}
    string popMessage();
    void pushMessage(string m);
    bool hasMessages();
    void clear();
private:
    vector<string> _messages;
    bool read_mode;

    Logger() {
        read_mode=false;
    }           // verhindert, dass ein Objekt von außerhalb von N erzeugt wird.
    // protected, wenn man von der Klasse noch erben möchte
    Logger( const Logger& ); /* verhindert, dass eine weitere Instanz via
 Kopier-Konstruktor erstellt werden kann */
    Logger & operator = (const Logger &); //Verhindert weitere Instanz durch Kopie
};


#endif //QTESLAP3C_LOGGER_H
