set REPS=15
set KEYS=50
set SIGNPR=50
set THREADS=1

set LOGFILEBASE=logs/logJCAWin-C-09-03-
set FILEIM=%LOGFILEBASE%.mvsc-


rem C behind java
set FILE=%FILEIM%-1T.txt
echo %FILE%
FOR /L %%A IN (1,1,%REPS%) DO (
	java -cp ./java/src -Djava.library.path=. sctudarmstadt/qtesla/tests/JavaSecureBenchmark %KEYS% %SIGNPR% 1 1 QTESLAProvider >> %FILE%
)

set FILE=%FILEIM%-2T.txt
echo %FILE%
FOR /L %%A IN (1,1,%REPS%) DO (
	java -cp ./java/src -Djava.library.path=. sctudarmstadt/qtesla/tests/JavaSecureBenchmark %KEYS% %SIGNPR% 1 2 QTESLAProvider >> %FILE%
)

set FILE=%FILEIM%-3T.txt
echo %FILE%
FOR /L %%A IN (1,1,%REPS%) DO (
	java -cp ./java/src -Djava.library.path=. sctudarmstadt/qtesla/tests/JavaSecureBenchmark %KEYS% %SIGNPR% 1 3 QTESLAProvider >> %FILE%
)
set FILE=%FILEIM%-4T.txt
echo %FILE%
FOR /L %%A IN (1,1,%REPS%) DO (
	java -cp ./java/src -Djava.library.path=. sctudarmstadt/qtesla/tests/JavaSecureBenchmark %KEYS% %SIGNPR% 1 4 QTESLAProvider >> %FILE%
)

rem JAVA behind JAVA
rem set LOGFILEBASE=logs/logJCAWin-JAVA-09-01-
rem set FILEIM=%LOGFILEBASE%.mvsc-
rem set FILE=%FILEIM%-1T.txt
rem echo %FILE%
rem FOR /L %%A IN (1,1,%REPS%) DO (
rem 	java -cp ./java/src -Djava.library.path=. sctudarmstadt/qtesla/tests/JavaSecureBenchmark %KEYS% %SIGNPR% 1 1 QTESLAJavaProvider >> %FILE%
rem )