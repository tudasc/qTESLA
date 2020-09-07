# qTESLA
This repository includes all software versions which where created for the publication: "qTESLA: Practical Implementations of a Quantum Attack Resistant Signature Scheme"

## Introduction
All our C codes are based qTESLA's on the reference code from https://github.com/qtesla/qTesla which was presebted in [ALK20].

## Acknoledgements
We thank the authors of [ALK20] for their help with their code. In particular, N. Bindel for providing us the special qTesla version with adaptable parameters and her support.

## Software
### x64 Projects
All files required are provided in `qtesla-piii-jni`.
Clang (10.0 or higher) or GCC (8.3 or higher) are required as well as static library files of the OpenSSL library.

#### Windows
There, you can find the Visual Studio 2017 Solution `qtesla-piii-jni.sln` which contains three projects. Only the Release/x64 built configurations are properly maintained!

If you want to compile the plain C version you need the projects `qtesla-win-lib` and `qtesla-win`. The first one compiles qTESLA as a static library. The second compiles the benchmark application which calls the library.

If you want to use C behind JNI/JCA, then first compile the Visual Studio project `qtesla-piii-jni` and copy the produced `qTeslaTest.dll` to the main directory `qtesla-piii-jni`. Afterward, execute the `build.sh` script which compiles the Java files.

#### Linux
To build everything run the `build.sh`. The C executable is generated in `qteslap3ccode` where you can also find the C Makefile called by by `build.sh`. Java bytecode is written in the `java`subfolder.

#### Execution
##### Plain C
Call the executable with four command line parameter which are parsed the folliwing way:

    NRUNS = atoi(argv[1]); // No. of keys and random messages
    signsperrun = atoi(argv[2]); // Signs/Verifies per key/messages

    // Which tests to execute
    int test = atoi(argv[3]);
    check_qtesla = CHECK_BIT(test, 0);
    check_ecdsa = CHECK_BIT(test, 1);
    check_rsa = CHECK_BIT(test, 2);

    // Degree of parallelism
    int num = atoi(argv[4]);
    omp_set_num_threads(num);

##### Java version
The qTESLA Java version is included in the package `\sctudarmstadt\qtesla\java`. Its functionality can be tested with the `JAVABasicTester.java` from `\sctudarmstadt\qtesla\test`. Paramter 1 sets the number of keys/messages to test, Parameter 2 the number of signs/verifies per key/message, Parameter 3 has no effect at the moment and Parameter for chooses the signature scheme as an integer. If the first bit is set, qTESLA is tested. If the second do_ecdsa and if the third do_rsa, respectively.

##### Java JCA version
The two Cryptographic Server Providers for C and Java version are located in `\sctudarmstadt\qtesla\jca` and `\sctudarmstadt\qtesla\javajca`. Have a look at the `JavaSecureBenchmark.java` test in `\sctudarmstadt\qtesla\test` for an example how to use the providers.


##### Scripts and Results
The mesaurement data which is the base for the diagrams in [BUR20] are avaiable in `qtesla-piii-jni-vs20119\logs` and `qtesla-piii-jni-vs20119\qteslap3ccode\logs`.
Scripts employed for the results in both OSs are:
* JCABenchLinux.sh
* JCABenchWindows.bat
* terri.sh
* scripts/paperBenchWin.bat
* LinuxPaperBench.sh


### ARMx64 Projects
#### C version
In `ARMx64/C` you find the C version which is wrapped behind JNI to run on an Android ARMx64 device.
The folder `precompiled-libs` contains the binary files of the OpenSSL library which we employed for our tests.
The folder `qteslap3cwrapper` contains the Android Studio 4.0 project which employs NDK/Gradle/CMAKE to compile the C-code as a library and to access it via JNI on the Android device. The C source code is located in `\ARMx64\C\qteslap3cwrapper\app\src\main\cpp` where `native-lib.cpp` contains the JNI interface.
A graphical interface is added by JAVA. There, you can choose which signature scheme to use (qTESLA, RSA or ECDSA) as well as the number of threads for qTESLA or the bitlength of RSA.

#### Java version
In `ARMx64/JAVA` you find the C version which is wrapped behind JNI to run on an Android ARMx64 device.
The folder `qteslap3android` contains the Android Studio 4.0 project which employs Gradle to compile the Java code for the Android device.
A graphical interface is added by JAVA. There, you can choose which signature scheme to use (qTESLA, RSA or ECDSA) as well as the number of threads for qTESLA or the bitlength of RSA.

## References
<table style="border:0px">
<tr>
    <td valign="top"><a name="ref-ALK[20]"></a>[ALK20]</td>
    <td> E. Alkim, P. S. L. M. Barreto, N. Bindel, J. Krämer, P. Longa,
and J. E. Ricardini:
The lattice-based digital signature
scheme qtesla.</a></td>
</tr>
<tr>
    <td valign="top"><a name="ref-MACH20"></a>[BUR20]</td>
    <td>Burger, M. ; Krämer, J. ; Bischof, Christian  :
       qTESLA: Practical Implementations of a Quantum Attack Resistant Signature Scheme.</td>
</tr>
</table>

## Contact
michael.burger@tu-darmstadt.de
