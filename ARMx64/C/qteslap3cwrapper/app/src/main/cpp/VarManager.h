//
// Created by MichaelB on 27.08.2019.
//

#ifndef QTESLAP3CWRAPPER_VARMANAGER_H
#define QTESLAP3CWRAPPER_VARMANAGER_H

class VarManager
{
public:
    static VarManager& instance()
    {
        static VarManager _instance;
        return _instance;
    }
    ~VarManager() {}

    void setThreadNum(int n) {
        this->_thread_num = n;
    }

    int getThreadNum() {
        return this->_thread_num;
    }
private:

    VarManager() {
        _thread_num=1;
    }           // verhindert, dass ein Objekt von außerhalb von N erzeugt wird.
    // protected, wenn man von der Klasse noch erben möchte
    VarManager( const VarManager& ); /* verhindert, dass eine weitere Instanz via
 Kopier-Konstruktor erstellt werden kann */
    VarManager & operator = (const VarManager &); //Verhindert weitere Instanz durch Kopie

    int _thread_num;
};

#endif //QTESLAP3CWRAPPER_VARMANAGER_H
