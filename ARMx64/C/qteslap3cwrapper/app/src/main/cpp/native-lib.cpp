#include <jni.h>
#include <string>     // std::string, std::to_string
#include <omp.h>

#include "tests/test_qtesla.h"
#include "tests/Logger.h"
#include "VarManager.h"

using namespace std;

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_qteslap3c_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject, /* this */
        int runs,
        int signsperrun,
        int threadstouse,
        int bitflag,
        int rsabitlen
        ) {
    std::string hello = "Hello from C++";

    VarManager::instance().setThreadNum(threadstouse);

    string s = "";


    double tstart = omp_get_wtime();
    int ret = mainTest(runs, signsperrun, s, bitflag, rsabitlen);
    double tend = omp_get_wtime();

    s = "";
    s = "Total time: " + to_string(tend-tstart) + " s.\n";

    while(Logger::instance().hasMessages()) {
        s += Logger::instance().popMessage();
    }

    return env->NewStringUTF(s.c_str());
}
