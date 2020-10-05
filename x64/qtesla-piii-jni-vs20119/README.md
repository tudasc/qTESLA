# qTESLA-PIII(-p-III)-JNI
The qTESLA implementation ready for integration into CogniCrypt employing JNI to access the C-code and supporting the Java Security provider.
It also includes the Java qTESLA version which was error corrected and adapted to the recent parameter set.
Only the proven-III (meeting NIST security category III) is ready-to-use and automatically chosen.

# Compilation and Execution#
## Linux ###
### Prerequisites ###
Java SDK must be installed. The tests were performed with Oracle Java 9 (version of java/javac 14.0.2 2020-07-14)<sup>[1](#myfootnote1)</sup>.
The installation was done following this [Guide](https://phoenixnap.com/kb/install-java-on-centos).
In short, you have to download the *.rpm package from oracle manually. Then, you install it with `sudo yum localinstall *-VERSION-linux-x64.rpm`.
The appropriate java can be set via `sudo alternatives --config java`.
Finally, you should set the path of the chosen java in the *.bash_profile* as `export JAVA_HOME=”/your/installation/path/”` which is in our case */usr/java/jdk-14.0.2/bin/java*.
Make also sure that your java install directory contains an *include* folder (*/usr/java/jdk-14.0.2/include* in our case).
This folder must contain the *jni.h* file and the subfolder *linux* within the actual *include* directory.

To promote the location to the JNI-headers to our compilation process you have two options:
1. You can add the two paths to the `CPATH` environment variable.
2. You can set the `JNIINC_HARD` variable at the beginning of the *Makefile* to the include path. It will automatically add the second path to the subfolder *linux*. For example, for Oracle Java the path is */usr/lib/jvm/java/include* and for OpenJDK8 it is */usr/lib/jvm/java-openjdk/include* on our CentOS7 machine.

To compile qTESLA you need OpenSSL to be installed so that you can link `-lssl` and `-lcrypto` which is done automatically by the modified *Makefile*.
We tested with the `openssl-devel` package retrieved by `yum` on our Linux system.

A third (optional) prerequisite is [SageMath](https://www.sagemath.org/) which must be installed on the system.
It is implicitly used by the make procedure if you want to play around with the parameters L<sub>S</sub> and E<sub>S</sub>.
In order to configure it, you have to set the path to the main sage script at the top of the file *list_omegas.py*.
In the our case this line is *#!/home/mburger/SageMath/sage -python*.

The tests were performed with **gcc/10.1** on **CentOS 7** (5.2.11-1.el7.elrepo.x86_64).
Additionally, the following compilers where checked on that linux: gcc/5.5, gcc/8.4, clang/10.
Since SageMath on the test system was compiled with gcc/5.5 a lower version could no be tested.
qTESLA itsef can also be compiled with gcc/4.9.4.
Feel free to test other configurations and notify us in the case of success.

### Compilation process ###
The process is realized for Linux in the script *build.sh* and is internally split in two steps.
To compile the default configuration call `./build.sh` (make *build.sh* executable with `chmod +x build.sh` if it is not executable yet).

The first step is to generate the shared C-library which is called by Java afterward.
This should generated the library file *libqTeslaTest.so* and automatically copies it to the main directory.

Even in the case of errors in the C-part, the second step compiled the Java code.
This assumes that `javac` is configured correctly, i.e. `javac --version` works and the path to the *JNI*-headers is promoted correctly.

#### OPTIONAL: Compile with a different parameter set ####
Optionally, you can also test to vary the two rejection parameters L<sub>S</sub> and E<sub>S</sub>.
See [qTESLA Documentation](https://eprint.iacr.org/2019/085.pdf) on page 14 for details.
Call, e.g., `./build.sh 950 950` to set L<sub>S</sub> and E<sub>S</sub> to 950.
A different number of parameters automatically calls the default parameter set 901/901.


### Execution ###
In order to resolve the dependency of the shared C-library there are two possibilities.
The first one is to pass the search path during the call of the Java executable via
`java -cp ./java/src -Djava.library.path=. sctudarmstadt/qtesla/tests/JavaSecureBenchmark 1 1 1 1`.

The second way is to add the path to LD_LIBRARY_PATH for example via `export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:YOURPATH`. To identify *YOURPATH* use `pwd` command.

In both cases, the code will run one iteration of qTESLA with one signing and one verification of a random message.
By passing different parameters you can adept the behavior.
For example, if you want to run 4 iterations with 11 signings each employing two threads within the C-part use `java -cp ./java/src -Djava.library.path=. sctudarmstadt/qtesla/tests/JavaSecureBenchmark 4 11 1 2`.
The third  parameter is interpreted as a three bit array.
 If the last bit is set (odd numbers) qTESLA is tested.
 If the second bit is set then ECDSA is (additionally) tested.
 If the third bit is set then RSA-6144 is (additionally) tested.

## Other operating systems ###
At the moment, we successfully performed tests under Windows which will be added to this documentation.
Even if qTESLA can be compiled, there is the problem that JNI works differently on MaCOSX and Windows. Feel free to remove that limitation.


# Documentation of the process so far#
Since the [video about CogniCrypt](https://youtu.be/vOZKN8yQcAY) only handles MaCOSX (without explicitly stating this...), the process is based on other online tutorials.
* [Tutorial 1](https://medium.com/@bschlining/a-simple-java-native-interface-jni-example-in-java-and-scala-68fdafe76f5f)
* [Tutorial 2](https://www.baeldung.com/jni)

  The general order to employ JNI is:
  * You have your C-code methods required for the interface in a C-file.
  * You generate a new java-file. There, you have to choose a unique name for the library you want to call from java and within a static block you need `System.loadLibrary("YOURLIBRARYNAME");`. Also `private native` methods with the same signature as you want to use in your C-file must be implemented.
  * Compile the java code and generate a header file automatically via `javac YOURFILENAME.java -h`
  * Include the generated h-file in the C-file and copy the signature of the methods generated to it. Add names to the parameter and a function body.
  * Compile your C-code to a shared library with the name you have chosen in the java-file.
  * Call the java class already compiled.

The following section describes the procedure as it was employed so far.

## The C-interface ##
For a quick test and proof of concept, we limit the interface to one single function which is given in *qTeslaTest.h* and which is `int checkQTesla (int runs, int signs, const char* in_message);`. Thus, we can only determine how many iterations of keygen-signing-verification are perfomed via `runs`, how many signings-verifications are performed per iteration via `signs` and the message we want to sign-verify via `in_message`.

## The java-equivalent ##
As mentioned above, we require a library name and `private native` functions for the interface. Everything is integrated in the `qTeslaTestJNI.java`file. The JNI part is:

    import java.lang.String;
    public class qTeslaTestJNI {
        static {
		      System.loadLibrary("qTeslaTest");
	    }

    	private native int checkQTesla (int runs, int signs, String in_message);

	    public static void main(String[] args) {
          ...
        }
    }

Afterward, the java code is compiled and the required header file is generated with
`javac qTeslaTestJNI.java -h .`. Do not miss the "." at the end of the command!

This generates the header *qTeslaTestJNI.h*

    /* DO NOT EDIT THIS FILE - it is machine generated */
    #include <jni.h>
    /* Header for class qTeslaTestJNI */

    #ifndef _Included_qTeslaTestJNI
    #define _Included_qTeslaTestJNI
    #ifdef __cplusplus
    extern "C" {
    #endif
    /*
     * Class:     qTeslaTestJNI
     * Method:    checkQTesla
      * Signature: (IILjava/lang/String;)I
      */
     JNIEXPORT jint JNICALL Java_qTeslaTestJNI_checkQTesla
       (JNIEnv *, jobject, jint, jint, jstring);

     #ifdef __cplusplus
     }
     #endif
     #endif

The lines with the function declaration must be copied to our "connecting" C-file.

## The connecting C-file ##
The *qTeslaTestJNI.c* implements our function `int checkQTesla (int runs, int signs, const char* c_message)` to actually employ the qTesla-library in the background. In principle, it contains the main functionality test of *tests/test_qtesla.c*, extended by a variable number of iterations and signings as well as a custom message with a variable length.
Below the actual test function we have the generated JNI-interface code:

    JNIEXPORT jint JNICALL Java_qTeslaTestJNI_checkQTesla
      (JNIEnv * jnienv, jobject thisobj, jint runs, jint signs, jstring in_message) {

	    const char *c_message = (*jnienv)->GetStringUTFChars(jnienv, in_message, 0);
	    checkQTesla (runs, signs, c_message);
	    return 0;
    }

Within the code, we have to manually convert the `java-String` to the `char*` pointer. The way employed comes from [rukspot](https://www.rukspot.com/blog/pass_and_return_string_value_to_jni_method). It also shows an example which can input an output strings which may be very helpfull for us in the future.

Java:

    class Greeting {

    	public static native String sayHello(String name);

    	static
    	{
    		System.loadLibrary("Greeting");
    	}
    }

C:

    JNIEXPORT jstring JNICALL Java_Greeting_sayHello (JNIEnv *env, jclass cl, jstring name)
    {
	    jstring jstr;
	    char greeting[] = "Hello, ";

	    char* cname;
	    cname = (*env)->GetStringUTFChars(env, name, NULL);

    	strcat(greeting,cname);

    	jstr = (*env)->NewStringUTF(env, greeting);

    	return jstr;
    }


## Compiling the C-code ##
This is a rather complicated task and at the moment, the Makefile of qTESLA is modified to reach the goal to generate a dynamically linkable library.
The first part is identical to the original file:

    consts: list_omegas.py
    	./list_omegas.py $(Q) $(N) 0 > consts.c
    	./list_omegas.py $(Q) $(N) 1 > reduce.h

    objs_p_III/%.o: %.c
    	@mkdir -p $(@D)
	    $(CC) -c $(CFLAGS) $(DFLAG) -D _qTESLA_p_III_ $< -o $@

    objs/random.o: random/random.c
	    @mkdir -p $(@D)
    	$(CC) -c $(CFLAGS) random/random.c -o objs/random.o

    objs/fips202.o: sha3/fips202.c
	    @mkdir -p $(@D)

And builds the object files of the standard C-files of qTESLA.
What is changes are the C-compile flags:

    CFLAGS = -std=gnu11 -fPIC -O3 -g3 -D $(ARCHITECTURE) -D __LINUX__ -fomit-frame-pointer -fopenmp

  We have to employ the `-fPIC` to generate position independent code for the use in a shared library.
  Additionally, a new built target `JNI_p_III: $(OBJECTS_p_III)` is defined which does two things.
  First, it compiles the new connecting C-file inlcuding the JNI headers into an object file:

    $(CC) $(CFLAGS) -c -I/usr/java/jdk-14.0.2/include -I/usr/java/jdk-14.0.2/include/linux qTeslaTestJNI.c -o libqTeslaTest.o

  and second, it combines all object-files created so far to a shared library:

    	$(CC) -shared -fopenmp -fPIC -o libqTeslaTest.so libqTeslaTest.o $^

which is indicated by the `-shared` and the `fPIC` is also required here.

# Footnotes
<a name="myfootnote1">1</a>: We also performed successful compilation and running tests with OpenJDK8 (version 1.8.0_262). Hence, you can employ other implementations by adapting the paths to JNI.
The installation for OpenJDK was directly done with `sudo yum install java-1.8.0-openjdk-devel`.
However, we had to set the path to `javac`and `java` manually to the environment *PATH* variable.




# Open issues #
* Using *OpenMP*-pragmas in the qTESLA C-code results in access violations
* In order to use qTESLA with full functionality the three methods in the *api.h* of qTesla need to be interfaced via JNI where input variables are changed within the functions:

      int crypto_sign_keypair(
       unsigned char *,
       unsigned char *
       );

      int crypto_sign(
       unsigned char *,unsigned long long *,
       const unsigned char *,unsigned long long,
       const unsigned char *
       );

      int crypto_sign_open(
       unsigned char *,unsigned long long *,
       const unsigned char *,unsigned long long,
       const unsigned char *
       );
