SET REPS=15
SET KEYS=50
SET SIGNPR=50
SET EXE=test_qtesla-p-III

FOR /L %%A IN (1,1,%REPS%) DO (
	start "Der Fick" /wait /B ../qtesla-win/x64/Release/qtesla-win.exe %KEYS% %SIGNPR% 1 1 >> ../logs/mvsc-03-09-1T.txt
)

FOR /L %%A IN (1,1,%REPS%) DO (
	start "Der Fick" /wait /B ../qtesla-win/x64/Release/qtesla-win.exe %KEYS% %SIGNPR% 1 2 >> ../logs/mvsc-03-09-2T.txt
)

FOR /L %%A IN (1,1,%REPS%) DO (
	start "Der Fick" /wait /B ../qtesla-win/x64/Release/qtesla-win.exe %KEYS% %SIGNPR% 1 3 >> ../logs/mvsc-03-09-3T.txt
)

FOR /L %%A IN (1,1,%REPS%) DO (
	start "Der Fick" /wait /B ../qtesla-win/x64/Release/qtesla-win.exe %KEYS% %SIGNPR% 1 4 >> ../logs/mvsc-03-09-4T.txt
)