#!/bin/bash

REPS=15
KEYS=50
SIGNPR=50
EXE=test_qtesla-p-III

LOGFILEBASE=logs/log-09-01-

module purge
module load gcc/10.1

#gcc-Suite
make clean
make CC=gcc

FILEIM=$LOGFILEBASE.gcc-

FILE=$FILEIM.1T.txt
export OMP_NUM_THREADS=1
for ((i=0; i<REPS; i=i+1))	
do
	./$EXE $KEYS $SIGNPR 7 >> $FILE
done

FILE=$FILEIM.2T.txt
export OMP_NUM_THREADS=2
for ((i=0; i<REPS; i=i+1))	
do
	./$EXE $KEYS $SIGNPR 1 >> $FILE
done

FILE=$FILEIM.3T.txt
export OMP_NUM_THREADS=3
for ((i=0; i<REPS; i=i+1))	
do
	./$EXE $KEYS $SIGNPR 1 >> $FILE
done

FILE=$FILEIM.4T.txt
export OMP_NUM_THREADS=3
for ((i=0; i<REPS; i=i+1))	
do
	./$EXE $KEYS $SIGNPR 1 >> $FILE
done

#clang-Suite
module purge
module load clang

make clean
make CC=clang

FILEIM=$LOGFILEBASE.clang-

FILE=$FILEIM.1T.txt
export OMP_NUM_THREADS=1
for ((i=0; i<REPS; i=i+1))	
do
	./$EXE $KEYS $SIGNPR 7 >> $FILE
done

FILE=$FILEIM.2T.txt
export OMP_NUM_THREADS=2
for ((i=0; i<REPS; i=i+1))	
do
	./$EXE $KEYS $SIGNPR 1 >> $FILE
done

FILE=$FILEIM.3T.txt
export OMP_NUM_THREADS=3
for ((i=0; i<REPS; i=i+1))	
do
	./$EXE $KEYS $SIGNPR 1 >> $FILE
done

FILE=$FILEIM.4T.txt
export OMP_NUM_THREADS=3
for ((i=0; i<REPS; i=i+1))	
do
	./$EXE $KEYS $SIGNPR 1 >> $FILE
done
