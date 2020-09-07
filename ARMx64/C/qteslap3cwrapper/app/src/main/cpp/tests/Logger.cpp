//
// Created by tuxed on 12.08.2019.
//

#include "Logger.h"
#include <iostream>

using namespace std;

void Logger::clear() {
    this->read_mode = false;
    this->_messages.clear();
}

string Logger::popMessage() {
    if(!this->read_mode) {
        this->read_mode = true;
        std::reverse(_messages.begin(),_messages.end());
    }


    if (this->_messages.size() > 0) {
        string tmp = _messages[_messages.size()-1];
        _messages.pop_back();
        return tmp;
    } else
        return "";
}

void Logger::pushMessage(string m) {
    this->_messages.push_back(m);
    cout << m << "\n";
}

bool Logger::hasMessages() {
    if(this->_messages.size() > 0) {
        return true;
    }
    else {
        return false;
    }
}
