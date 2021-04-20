pyinstaller.exe --onefile --hidden-import win32timezone ..\src\service.py ..\src\bridge.py
move .\dist\service.exe ..\dist\