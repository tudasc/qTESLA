#!/bin/bash

E=901
S=901

if [ $# -eq 0 ]
then
	E=901
	S=901
fi

if [ $# -eq 2 ]
then
	E=$1
	S=$2
fi

SRCROOT="java/src"

echo -e "Compiling C code of qtesla with: KEYGEN_BOUND_E=$E, KEYGEN_BOUND_S=$S"
cd qteslap3ccode 
make clean
make DFLAG="-DPARAM_KEYGEN_BOUND_E=$E -DPARAM_KEYGEN_BOUND_S=$S" CC=gcc

FILE=libqTeslaTest.so
if test -f "$FILE"; then
    mv libqTeslaTest.so ../
	echo -e "Success"	
fi
cd ..

#!/bin/bash
echo -e "Compiling sctudarmstadt.qtesla.java"	
javac -cp $SRCROOT $SRCROOT/sctudarmstadt/qtesla/java/*java

echo -e "Compiling sctudarmstadt.qtesla.cwrapper"	
javac -cp $SRCROOT $SRCROOT/sctudarmstadt/qtesla/cwrapper/*java

echo -e "Compiling sctudarmstadt.qtesla.jca"	
javac -cp $SRCROOT -Xlint:deprecation $SRCROOT/sctudarmstadt/qtesla/jca/*java

echo -e "Compiling sctudarmstadt.qtesla.javajca"	
javac -cp $SRCROOT $SRCROOT/sctudarmstadt/qtesla/javajca/*java

echo -e "Compiling sctudarmstadt.qtesla.tests"	
javac -cp $SRCROOT $SRCROOT/sctudarmstadt/qtesla/tests/*java

$SHELL


