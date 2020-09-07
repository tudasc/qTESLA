#!/bin/bash

REPS=1
KEYS=1
SIGNPR=1
THREADS=1

EXE=test_qtesla-p-III

#clang-Suite
module purge
module load clang

LOGFILEBASE=logs/logJCAWin-C-09-01-
FILEIM=$LOGFILEBASE.clang-

FILE=$FILEIM.1T.txt
export OMP_NUM_THREADS=1
for ((i=0; i<REPS; i=i+1))	
do
	java -cp ./java/src -Djava.library.path=. sctudarmstadt/qtesla/tests/JavaSecureBenchmark $KEYS $SIGNPR 7 1 QTESLAProvider >> $FILE
done

FILE=$FILEIM.2T.txt
export OMP_NUM_THREADS=2
for ((i=0; i<REPS; i=i+1))	
do
	java -cp ./java/src -Djava.library.path=. sctudarmstadt/qtesla/tests/JavaSecureBenchmark $KEYS $SIGNPR 1 2 QTESLAProvider >> $FILE
done

FILE=$FILEIM.3T.txt
export OMP_NUM_THREADS=3
for ((i=0; i<REPS; i=i+1))	
do
	java -cp ./java/src -Djava.library.path=. sctudarmstadt/qtesla/tests/JavaSecureBenchmark $KEYS $SIGNPR 1 3 QTESLAProvider >> $FILE
done

FILE=$FILEIM.4T.txt
export OMP_NUM_THREADS=4
for ((i=0; i<REPS; i=i+1))	
do
	java -cp ./java/src -Djava.library.path=. sctudarmstadt/qtesla/tests/JavaSecureBenchmark $KEYS $SIGNPR 1 4 QTESLAProvider >> $FILE
done

#JAVAPart
LOGFILEBASE=logs/logJCAWin-JAVA-09-01-
FILEIM=$LOGFILEBASE.clang-

FILE=$FILEIM.1T.txt
export OMP_NUM_THREADS=1
for ((i=0; i<REPS; i=i+1))	
do
	java -cp ./java/src -Djava.library.path=. sctudarmstadt/qtesla/tests/JavaSecureBenchmark $KEYS $SIGNPR 1 1 QTESLAJavaProvider >> $FILE
done

$SHELL