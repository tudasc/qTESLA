#CC = scorep --nocompiler --user gcc
#CC=gcc

ifeq "$(CC)" "clang"
    COMPILER=clang
else ifeq "$(CC)" "gcc"
    COMPILER=gcc
endif

ARCHITECTURE=_AMD64_
ifeq "$(ARCH)" "x64"
    ARCHITECTURE=_AMD64_
else ifeq "$(ARCH)" "x86"
    ARCHITECTURE=_X86_
else ifeq "$(ARCH)" "ARM"
    ARCHITECTURE=_ARM_
    ARM_SETTING=-lrt
else ifeq "$(ARCH)" "ARM64"
    ARCHITECTURE=_ARM64_
    ARM_SETTING=-lrt
endif

AR=ar rcs
RANLIB=ranlib
LD=ld

CFLAGS = -std=gnu11 -fPIC -Ofast -g0 -D $(ARCHITECTURE) -D __LINUX__ -fopenmp #-lpthread #-DSCOREP  -fomit-frame-pointer
LDFLAGS=-lm -L/usr/lib/ -lssl -lcrypto -fopenmp #=libiomp5

ifeq "$(CC)" "gcc"
    CFLAGS+= -march=native
endif

DFLAG=
ifeq "$(DEBUG)" "TRUE"
    DFLAG=-DDEBUG
endif

#DFLAG+=-DPARAM_KEYGEN_BOUND_E=901 -DPARAM_KEYGEN_BOUND_S=901

N ?= $$(/usr/bin/gcc -dM -E params.h | grep "PARAM_N " |awk '{ print $$3}') 
Q ?= $$(/usr/bin/gcc -dM -E params.h | grep "PARAM_Q " |awk '{ print $$3}')

OBJECTS_p_III = objs_p_III/sign.o objs_p_III/pack.o objs_p_III/sample.o objs_p_III/gauss.o objs_p_III/poly.o objs_p_III/consts.o objs/fips202.o objs/random.o
SOURCE_TEST = tests/cpucycles.c tests/test_qtesla.c
SOURCE_KATS_GEN  = tests/rng.c tests/PQCgenKAT_sign.c
SOURCE_KATS_TEST = tests/rng.c tests/PQCtestKAT_sign.c

#all: JNI_p_III consts 

all:  JNI_p_III lib_p_III tests

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
	$(CC) -c $(CFLAGS) sha3/fips202.c -o objs/fips202.o

lib_p_III_shared: $(OBJECTS_p_III)
	$(LD) -shared $^ -o qtesla.so

obj_pack: $(OBJECTS_p_III)
	$(LD) -r -o lib_p_III/qTESLA_p_III.o $^

lib_p_III: $(OBJECTS_p_III)
	rm -rf lib_p_III
	mkdir lib_p_III
	$(AR) lib_p_III/libqtesla.a $^ 
	$(RANLIB) lib_p_III/libqtesla.a

JNI_p_III: $(OBJECTS_p_III)
	$(CC) $(CFLAGS) -c -I/usr/java/jdk-14.0.2/include -I/usr/java/jdk-14.0.2/include/linux -I./sctudarmstadt/qtesla/cwrapper qTeslaTestJNI.c -o libqTeslaTest.o
	$(CC) -shared $(CFLAGS) -fPIC -o libqTeslaTest.so libqTeslaTest.o $^

tests: lib_p_III
	$(CC) $(CFLAGS) -c -I/usr/java/jdk-14.0.2/include -I/usr/java/jdk-14.0.2/include/linux -I./sctudarmstadt/qtesla/cwrapper qTeslaTestJNI.c -o libqTeslaTest2.o
	$(CC) $(CFLAGS) -L./lib_p_III -D _qTESLA_p_III_ $(SOURCE_TEST) libqTeslaTest2.o $(DFLAG) -lqtesla $(LDFLAGS) -I/usr/java/jdk-14.0.2/include -I/usr/java/jdk-14.0.2/include/linux -o test_qtesla-p-III $(ARM_SETTING)


.PHONY: clean

clean:
	rm -rf objs* lib_p_III/*.a test_qtesla-* PQCgenKAT_sign-* PQCtestKAT_sign-* PQCsignKAT_qTesla* *.input.c *.input.prep.c *.prep.c.opari.inc *.input.prep.opari.c


