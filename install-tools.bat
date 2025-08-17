@echo off
echo Installing SolShield security analysis tools...

echo.
echo Installing Slither...
pip install slither-analyzer

echo.
echo Installing Mythril...
pip install mythril

echo.
echo Installing Solhint...
npm install -g solhint

echo.
echo Checking installations...
echo.
echo Slither version:
slither --version

echo.
echo Mythril version:
myth version

echo.
echo Solhint version:
solhint --version

echo.
echo All tools installed successfully!
pause