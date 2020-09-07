# qtesla-PIII-JNI
A sandbox for playing around with qTesla and JNI to prepare integration into CogniCrypt

# Compilation and Execution#
## Linux ###
### Prerequisites ###
Java SDK must be installed. The tests were performed with Oracle Java 9 (version of java/javac 14.0.2 2020-07-14).
The installation was done following this [Guide](https://phoenixnap.com/kb/install-java-on-centos).
In short, you have to download the *.rpm package from oracle manually. Then, you install it with `sudo yum localinstall *-VERSION-linux-x64.rpm`.
The appropriate java can be set via `sudo alternatives --config java`.
Finally, you should set the path of the choosen java in the *.bash_profile* as `export JAVA_HOME=”/your/installation/path/”` which is in our case */usr/java/jdk-14.0.2/bin/java*.
Make also sure that your java directory contains an *include* folder (*/usr/java/jdk-14.0.2/include* in our case). This folder must conaint the *jni.h* file and a subfolder *linux*.

To compile qTesla you need OpenSSL to be installed so that you can link `-lssl` and `-lcrypto` which is done automatically by the modified *Makefile*.

A third prerequisite is [SageMath](https://www.sagemath.org/) which must be installed on the system and which is implicitly used by the make procedure. In order to configure it, you have to set the path to the sage script at the top of the file *list_omegas.py*. In the test-case this line is *#!/home/mburger/SageMath/sage -python*.

The tests were performed with **gcc/10.1** on **CentOS 7** (5.2.11-1.el7.elrepo.x86_64).
Additionally, the following compilers where checked on that linux: gcc/5.5, gcc/8.4, clang/10. Since SageMath on the test system was compiled with gcc/5.5 a lower version could no be tested. qTesla itsef can also be compiled with gcc/4.9.4.
Feel free to test other configurations and add the information.

### Compilation process ###
The process is split in two steps. The first one is to compile the java code.
Assuming that javac is configured correctly, i.e. `javac --version` works, a simple `javac qTeslaTestJNI.java` should generate the *qTeslaTestJNI* class file.

The second step is to generate the shared C-library which is called by java afterward. Call `./build.sh 1500 1500` (make *build.sh* executable with `chmod +x build.sh` if it is not executable yet). The two 1500 set the values for the rejection parameter **E** and **S** in the qTesla code. See [qTesla Documentation](https://eprint.iacr.org/2019/085.pdf) on page 14 for details.
This should generated the library file *libqTeslaTest.so*.

### Execution ###
In order to resolve the dependency of the shared C-library there are two possibility.
The first one is to pass the search path during the call of the Java executable via
`java -cp . -Djava.library.path=. qTeslaTestJNI`.

The second way is to add the path to LD_LIBRARY_PATH for example via `export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:YOURPATH`. To identify *YOURPATH* use `pwd` command. Then, the call is a simply `java qTeslaTestJNI`.

In both cases, the code will run one iteration with one signing and one verification of the message "Hallo" by default. You can pass a three-tuple of arguments to change the behavior. For example, if you want to run 4 iterations with 11 signings each of the message "We love JNI" the call is `java -cp . -Djava.library.path=. qTeslaTestJNI 4 11 "We love JNI"` and `java  qTeslaTestJNI 4 11 "We love JNI"`.

## Other operating systems ###
At the moment, no other systems are possible. Even if qTesla can be compiled, there is the problem that JNI works differently on MaCOSX and Windows. Feel free to remove that limitation.


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
This is a rather complicated task and at the moment, the Makefile of qTesla is modified to reach the goal to generate a dynamically linkable library.
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

And builds the object files of the standard C-files of qTesla.
What is changes are the C-compile flags:

    CFLAGS = -std=gnu11 -fPIC -O3 -g3 -D $(ARCHITECTURE) -D __LINUX__ -fomit-frame-pointer -fopenmp

  We have to employ the `-fPIC` to generate position independent code for the use in a shared library.
  Additionally, a new built target `JNI_p_III: $(OBJECTS_p_III)` is defined which does two things.
  First, it compiles the new connecting C-file inlcuding the JNI headers into an object file:

    $(CC) $(CFLAGS) -c -I/usr/java/jdk-14.0.2/include -I/usr/java/jdk-14.0.2/include/linux qTeslaTestJNI.c -o libqTeslaTest.o

  and second, it combines all object-files created so far to a shared library:

    	$(CC) -shared -fopenmp -fPIC -o libqTeslaTest.so libqTeslaTest.o $^

which is indicated by the `-shared` and the `fPIC` is also required here.





# Open issues #
* Using *OpenMP*-pragmas in the qTesla C-code results in access violations
* In order to use qTesla with full functionality the three methods in the *api.h* of qTesla need to be interfaced via JNI where input variables are changed within the functions:

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

