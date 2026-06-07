@echo off
setlocal

set SCRIPT_DIR=%~dp0
set CLASSPATH_FILE=%SCRIPT_DIR%target\classpath.txt

mvn -f "%SCRIPT_DIR%pom.xml" -DskipTests compile dependency:build-classpath -Dmdep.outputFile="%CLASSPATH_FILE%" -Dmdep.includeScope=runtime >NUL
if errorlevel 1 exit /b %errorlevel%

set /p DEPS=<"%CLASSPATH_FILE%"
java -cp "%SCRIPT_DIR%target\classes;%DEPS%" de.kaikreuzer.teslatoken.TeslaToken %*
