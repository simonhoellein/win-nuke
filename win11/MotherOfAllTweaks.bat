@echo off

REM mother of all tweak scripts found on http://reboot.pro/topic/20622-windows-10-enterprise-ltsb-mother-of-all-tweak-scripts/ by ericgl
REM version 1.0
REM version 2.0 from 2015/10/27
REM version 3.0 from 2016/03/09
REM version 4.0 from 2016/03/22
REM version 5.0 from 2017/01/27
REM version 6.0 from 2017/12/18
REM version 7.0 from 2018/05/03
REM version 8.0 for win10 build1809 from 2019/02/27
REM version 9.0 from 2019/08/19 -> disabled fast startup crap
REM version 10.0 from 2020/01/08 -> re-enabled registry backups
REM version 11.0 from 2020/10/06 -> fix for winver2004 to disable bing in windows search
REM version 12.0 from 2021/11/15 -> added support for win11 21h2

color 2

echo ***MOTHER OF ALL TWEAK SCRIPTS with additions and modifications by jk ***
echo.
echo.



REM set ANSWER=y 
REM set /p ANSWER= Change all Temp directories to C:\TEMP (environment variables)? (y/n) [%ANSWER%]:
REM echo. 

REM if %answer%==n goto skiptempdirs

REM cd\
REM if NOT exist %SYSTEMDRIVE%\TEMP (md %SYSTEMDRIVE%\TEMP)
REM reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "TEMP" /t REG_EXPAND_SZ /d %%SYSTEMDRIVE%%\TEMP /f
REM reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "TMP" /t REG_EXPAND_SZ /d %%SYSTEMDRIVE%%\TEMP /f
REM reg add "HKEY_USERS\.DEFAULT\Environment" /v "TEMP" /t REG_EXPAND_SZ /d %%SYSTEMDRIVE%%\TEMP /f
REM reg add "HKEY_USERS\.DEFAULT\Environment" /v "TMP" /t REG_EXPAND_SZ /d %%SYSTEMDRIVE%%\TEMP /f
REM reg add "HKCU\Environment" /v "TEMP" /t REG_EXPAND_SZ /d %%SYSTEMDRIVE%%\TEMP /f
REM reg add "HKCU\Environment" /v "TMP" /t REG_EXPAND_SZ /d %%SYSTEMDRIVE%%\TEMP /f
REM takeown /f %USERPROFILE%\AppData\Local\Temp /a /r /d y
REM icacls %USERPROFILE%\AppData\Local\Temp /grant Administrators:F /T
REM rd /s /q %USERPROFILE%\AppData\Local\Temp
REM takeown /f %SystemRoot%\Temp /a /r /d y
REM icacls %SystemRoot%\Temp /grant Administrators:F /T
REM rd /s /q %SystemRoot%\Temp

REM :skiptempdirs

copy  /Y /V %~dp0SetACL\x64\SetACLx64.exe %windir%\system32

REM checking if it's win 10 or 11...
ver
REM ver | find "6.1." >nul && goto ver_win7
REM ver | find "6.2." >nul && goto ver_win8
REM ver | find "6.3." >nul && goto ver_win81
REM ver | find "10.0." >nul && goto ver_win10
ver | find "10.0.22000" >nul && goto ver_win21h1






set ANSWER=y
set /p ANSWER= Tweak everything automatically? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto manual
REM hier gehts automatisch los! :D

REM choice /c yn /t 5 /d y /m "Weitermachen (jetzt setze ich die Berechtigungen)"
REM if /I "%c%" EQU "n" goto :manuell
REM if /I "%c%" NEQ "n" goto :auto



choice /c yn /t 3 /d y /m "Disable creation of an Advertising ID"
if ERRORLEVEL 2 goto skipadid
if ERRORLEVEL 1 goto adid

:adid
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f
:skipadid



REM set ANSWER=y
REM set /p ANSWER= Remove Telemetry and Data Collection? (y/n) [%ANSWER%]:
REM echo. 
REM if %answer%==n goto skiptelemetry

REM Changes in registry do not reflect back to GPEDIT.MSC. Better to do it directly through GPEDIT.MSC UI.
REM reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d 1 /f
REM reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
REM reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v DontOfferThroughWUAU /t REG_DWORD /d 1 /f
REM reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f
REM reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f
REM reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f
REM reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
REM reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f
REM reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d 0 /f
REM reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Telemetry" /v "Enabled" /t REG_DWORD /d 0 /f
REM reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\TCPIPLOGGER" /v "Start" /t REG_DWORD /d 0 /f REM *** NOT SURE ABOUT THIS ONE YET
REM reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\ReadyBoot" /v "Start" /t REG_DWORD /d 0 /f REM *** NOT SURE ABOUT THIS ONE YET

REM :skiptelemetry
echo.
choice /c yn /t 3 /d y /m "Change some IE settings (like download path, sending browsing history and so on)"
if ERRORLEVEL 2 goto skipie11
if ERRORLEVEL 1 goto ie11


:ie11
echo.
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Default Download Directory" /t REG_SZ /d "D:\DOWNLOADS"
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DoNotTrack" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Search Page" /t REG_SZ /d "http://www.google.de" /f
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Start Page Redirect Cache" /t REG_SZ /d "http://www.google.de" /f
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "PlaySounds" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Isolation" /t REG_SZ /d PMEM /f
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Isolation64Bit" /t REG_DWORD /d 1 /f

reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Default Download Directory" /t REG_SZ /d "D:\DOWNLOADS"
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DoNotTrack" /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Search Page" /t REG_SZ /d "http://www.google.de" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Start Page Redirect Cache" /t REG_SZ /d "http://www.google.de" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Internet Explorer\Main" /v "PlaySounds" /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Isolation" /t REG_SZ /d PMEM /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Isolation64Bit" /t REG_DWORD /d 1 /f

REM *** Add Google as search provider for IE11, and make it the default ***
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /f
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "DisplayName" /t REG_SZ /d "Google" /f
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "FaviconURL" /t REG_SZ /d "http://www.google.de/favicon.ico" /f
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "FaviconURLFallback" /t REG_SZ /d "http://www.google.de/favicon.ico" /f
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "OSDFileURL" /t REG_SZ /d "http://www.iegallery.com/en-us/AddOns/DownloadAddOn?resourceId=813" /f
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "ShowSearchSuggestions" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "SuggestionsURL" /t REG_SZ /d "http://clients5.google.de/complete/search?q={searchTerms}&client=ie8&mw={ie:maxWidth}&sh={ie:sectionHeight}&rh={ie:rowHeight}&inputencoding={inputEncoding}&outputencoding={outputEncoding}" /f
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "SuggestionsURLFallback" /t REG_SZ /d "http://clients5.google.com/complete/search?hl={language}&q={searchTerms}&client=ie8&inputencoding={inputEncoding}&outputencoding={outputEncoding}" /f
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "TopResultURLFallback" /t REG_SZ /d "" /f
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "URL" /t REG_SZ /d "http://www.google.de/search?q={searchTerms}&sourceid=ie7&rls=com.microsoft:{language}:{referrer:source}&ie={inputEncoding?}&oe={outputEncoding?}" /f
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes" /v "DefaultScope" /t REG_SZ /d "{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /f

reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "DisplayName" /t REG_SZ /d "Google" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "FaviconURL" /t REG_SZ /d "http://www.google.de/favicon.ico" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "FaviconURLFallback" /t REG_SZ /d "http://www.google.de/favicon.ico" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "OSDFileURL" /t REG_SZ /d "http://www.iegallery.com/en-us/AddOns/DownloadAddOn?resourceId=813" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "ShowSearchSuggestions" /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "SuggestionsURL" /t REG_SZ /d "http://clients5.google.de/complete/search?q={searchTerms}&client=ie8&mw={ie:maxWidth}&sh={ie:sectionHeight}&rh={ie:rowHeight}&inputencoding={inputEncoding}&outputencoding={outputEncoding}" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "SuggestionsURLFallback" /t REG_SZ /d "http://clients5.google.com/complete/search?hl={language}&q={searchTerms}&client=ie8&inputencoding={inputEncoding}&outputencoding={outputEncoding}" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "TopResultURLFallback" /t REG_SZ /d "" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "URL" /t REG_SZ /d "http://www.google.de/search?q={searchTerms}&sourceid=ie7&rls=com.microsoft:{language}:{referrer:source}&ie={inputEncoding?}&oe={outputEncoding?}" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Internet Explorer\SearchScopes" /v "DefaultScope" /t REG_SZ /d "{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /f


REM *** Disable IE Suggested Sites & Flip ahead (page prediction which sends browsing history to Microsoft) ***
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Suggested Sites" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Suggested Sites" /v "DataStreamEnabledState" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\FlipAhead" /v "FPEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d 0 /f
:skipie11


echo.
choice /c yn /t 3 /d y /m "Disable synchronisation of user settings"
if ERRORLEVEL 2 goto skipusersets
if ERRORLEVEL 1 goto usersets

:usersets

reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d 5 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d 0 /f

reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d 5 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d 0 /f

:skipusersets


echo.
choice /c yn /t 3 /d y /m "Don't allow Windows Defender to submit samples to MAPS (formerly SpyNet)"
if ERRORLEVEL 2 goto skipwindef
if ERRORLEVEL 1 goto windef


:windef
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet" /v "SpyNetReporting" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d 1 /f

:skipwindef



echo.
choice /c yn /t 3 /d y /m "Add Reboot to Recovery to right-click menu of This PC"
if ERRORLEVEL 2 goto skipreboottorecovery
if ERRORLEVEL 1 goto reboottorecovery


:reboottorecovery
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg add "HKEY_CLASSES_ROOT\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell\Reboot to Recovery" /v "Icon" /t REG_SZ /d %SystemRoot%\System32\imageres.dll,-110" /f
reg add "HKEY_CLASSES_ROOT\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell\Reboot to Recovery\command" /ve /d "shutdown.exe -r -o -f -t 00" /f

:skipreboottorecovery



echo.
choice /c yn /t 3 /d y /m "Disable Cortana"
if ERRORLEVEL 2 goto skipcortana
if ERRORLEVEL 1 goto cortana


:cortana
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f


REM HIER GUCKEN
REM reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!dss-winrt-telemetry.js" /t REG_DWORD /d 0 /f
REM reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry.js" /t REG_DWORD /d 0 /f
REM reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry-event_8ac43a41e5030538" /t REG_DWORD /d 0 /f
REM reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry-inter_58073761d33f144b" /t REG_DWORD /d 0 /f

reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f 
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f 
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f 
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f 
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f 
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f 
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f 
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f 

:skipcortana


echo.
choice /c yn /t 3 /d y /m "Hide the search box from taskbar"
if ERRORLEVEL 2 goto skipsearch
if ERRORLEVEL 1 goto search


:search
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f
:skipsearch

echo.
choice /c yn /t 3 /d y /m "Remove telemetry from search"
if ERRORLEVEL 2 goto skipsearchtel
if ERRORLEVEL 1 goto searchtel

:searchtel
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d 1 /f

:skipsearchtel


echo.
choice /c yn /t 3 /d y /m "Remove more telemetry"
if ERRORLEVEL 2 goto skiptel
if ERRORLEVEL 1 goto tel

:tel

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f

:skiptel


echo.
choice /c yn /t 3 /d y /m "Remove even more telemetry"
if ERRORLEVEL 2 goto skipmoretel
if ERRORLEVEL 1 goto moretel

:moretel
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d 0 /f

:skipmoretel

echo.
choice /c yn /t 3 /d y /m "Disable location"
if ERRORLEVEL 2 goto skiploc
if ERRORLEVEL 1 goto loc

:loc
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d 1 /f
:skiploc
				
			
echo.
choice /c yn /t 3 /d y /m "Remove sharing of handwriting"
if ERRORLEVEL 2 goto skiphand
if ERRORLEVEL 1 goto hand	

:hand		
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v  "PreventHandwritingErrorReports" /t REG_DWORD /d 1 /f			
:skiphand

echo.
choice /c yn /t 3 /d y /m "Disable MRU (jump lists) lists"
if ERRORLEVEL 2 goto skipmru
if ERRORLEVEL 1 goto mru


:mru
REM TESTEN*** Disable MRU lists (jump lists) of XAML apps in Start Menu ***
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d 0 /f

:skipmru


echo.
choice /c yn /t 3 /d y /m "Exchange Windows Explorer to start on This PC instead of Quick Access"
if ERRORLEVEL 2 goto skipexp
if ERRORLEVEL 1 goto exp


:exp
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d 1 /f
:skipexp


echo.
choice /c yn /t 3 /d y /m "Create Desktop Shortcuts"
if ERRORLEVEL 2 goto skipshorts
if ERRORLEVEL 1 goto shorts


:shorts
REM Computer
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0 /f 
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0 /f 
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0 /f 
REM Network 
REM reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" /t REG_DWORD /d 0 /f 
REM User's folder
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{450D8FBA-AD25-11D0-98A8-0800361B1103}" /t REG_DWORD /d 0 /f 
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{450D8FBA-AD25-11D0-98A8-0800361B1103}" /t REG_DWORD /d 0 /f 
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{450D8FBA-AD25-11D0-98A8-0800361B1103}" /t REG_DWORD /d 0 /f 
:skipshorts


echo.
choice /c yn /t 3 /d n /m "Add Take Ownership on right-click menu of files and folders"
if ERRORLEVEL 2 goto skipownership
if ERRORLEVEL 1 goto ownership


:ownership
reg add "HKEY_CLASSES_ROOT\*\shell\runas" /ve /t REG_SZ /d "Take ownership" /f
reg add "HKEY_CLASSES_ROOT\*\shell\runas" /v "HasLUAShield" /t REG_SZ /d "" /f
reg add "HKEY_CLASSES_ROOT\*\shell\runas" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
reg add "HKEY_CLASSES_ROOT\*\shell\runas\command" /ve /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" /a && icacls \"%%1\" /grant Administrators:F" /f
reg add "HKEY_CLASSES_ROOT\*\shell\runas\command" /v "IsolatedCommand" /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" /a && icacls \"%%1\" /grant Administrators:F" /f
reg add "HKEY_CLASSES_ROOT\Directory\shell\runas" /ve /t REG_SZ /d "Take ownership" /f
reg add "HKEY_CLASSES_ROOT\Directory\shell\runas" /v "HasLUAShield" /t REG_SZ /d "" /f
reg add "HKEY_CLASSES_ROOT\Directory\shell\runas" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
reg add "HKEY_CLASSES_ROOT\Directory\shell\runas\command" /ve /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" /a /r /d y && icacls \"%%1\" /grant Administrators:F /t" /f
reg add "HKEY_CLASSES_ROOT\Directory\shell\runas\command" /v "IsolatedCommand" /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" /a /r /d y && icacls \"%%1\" /grant Administrators:F /t" /f

:skipownership


echo.
choice /c yn /t 3 /d y /m "Turn OFF Sticky Keys when caps is pressed 5 times"
if ERRORLEVEL 2 goto skipstickykeys
if ERRORLEVEL 1 goto stickykeys

:stickykeys
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "506" /f
reg add "HKEY_USERS\.DEFAULT\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "506" /f
:skipstickykeys



echo.
choice /c yn /t 3 /d y /m "Underline keyboard shortcuts and access keys"
if ERRORLEVEL 2 goto skipunderline
if ERRORLEVEL 1 goto underline


:underline
REM *** Underline keyboard shortcuts and access keys ***
reg add "HKCU\Control Panel\Accessibility\Keyboard Preference" /v "On" /t REG_SZ /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Control Panel\Accessibility\Keyboard Preference" /v "On" /t REG_SZ /d 1 /f
:skipunderline



echo.
choice /c yn /t 3 /d y /m "Use Windows Photo Viewer to open TIF-files instead of Paint"
if ERRORLEVEL 2 goto skippaint
if ERRORLEVEL 1 goto paint


:paint
reg add "HKCU\Software\Classes\.jpg" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKCU\Software\Classes\.jpeg" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKCU\Software\Classes\.gif" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKCU\Software\Classes\.png" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKCU\Software\Classes\.bmp" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKCU\Software\Classes\.tiff" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKCU\Software\Classes\.ico" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKEY_USERS\.DEFAULT\Software\Classes\.jpg" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKEY_USERS\.DEFAULT\Software\Classes\.jpeg" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKEY_USERS\.DEFAULT\Software\Classes\.gif" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKEY_USERS\.DEFAULT\Software\Classes\.png" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKEY_USERS\.DEFAULT\Software\Classes\.bmp" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKEY_USERS\.DEFAULT\Software\Classes\.tiff" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKEY_USERS\.DEFAULT\Software\Classes\.ico" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKCR\Applications\photoviewer.dll\shell\open" /v "MuiVerb" /t REG_SZ /d "@photoviewer.dll,-3043" /f
reg add "HKCR\Applications\photoviewer.dll\shell\open\command" /ve /t REG_EXPAND_SZ /d "%%SystemRoot%%\System32\rundll32.exe \"%%ProgramFiles%%\Windows Photo Viewer\PhotoViewer.dll\", ImageView_Fullscreen %%1" /f
reg add "HKCR\Applications\photoviewer.dll\shell\open\DropTarget" /v "Clsid" /t REG_SZ /d "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" /f
reg add "HKCR\Applications\photoviewer.dll\shell\print\command" /ve /t REG_EXPAND_SZ /d "%%SystemRoot%%\System32\rundll32.exe \"%%ProgramFiles%%\Windows Photo Viewer\PhotoViewer.dll\", ImageView_Fullscreen %%1" /f
reg add "HKCR\Applications\photoviewer.dll\shell\print\DropTarget" /v "Clsid" /t REG_SZ /d "{60fd46de-f830-4894-a628-6fa81bc0190d}" /f

:skippaint



echo.
choice /c yn /t 3 /d y /m "Remove Music, Pictures and Videos from Start Menu places (remove links only)"
if ERRORLEVEL 2 goto skipstartmenuplaces
if ERRORLEVEL 1 goto startmenuplaces


:startmenuplaces
del "C:\ProgramData\Microsoft\Windows\Start Menu Places\05 - Music.lnk"
del "C:\ProgramData\Microsoft\Windows\Start Menu Places\06 - Pictures.lnk"
del "C:\ProgramData\Microsoft\Windows\Start Menu Places\07 - Videos.lnk"

:skipstartmenuplaces



echo.
choice /c yn /t 3 /d n /m "Remove Libraries"
if ERRORLEVEL 2 goto skiplibraries
if ERRORLEVEL 1 goto libraries


:libraries
del "%userprofile%\AppData\Roaming\Microsoft\Windows\Libraries\Music.library-ms"
del "%userprofile%\AppData\Roaming\Microsoft\Windows\Libraries\Pictures.library-ms"
del "%userprofile%\AppData\Roaming\Microsoft\Windows\Libraries\Videos.library-ms"
 

reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UsersLibraries" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{59BD6DD1-5CEC-4d7e-9AD2-ECC64154418D}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{C4D98F09-6124-4fe0-9942-826416082DA9}" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{59BD6DD1-5CEC-4d7e-9AD2-ECC64154418D}" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{C4D98F09-6124-4fe0-9942-826416082DA9}" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\UsersLibraries" /f
reg delete "HKCU\SOFTWARE\Classes\Local Settings\MuiCache\1\52C64B7E" /v "@C:\Windows\system32\windows.storage.dll,-50691" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\SettingSync\WindowsSettingHandlers\UserLibraries" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\SettingSync\WindowsSettingHandlers\UserLibraries" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\SettingSync\WindowsSettingHandlers\UserLibraries" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\SettingSync\Namespace\Windows\UserLibraries" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\SettingSync\Namespace\Windows\UserLibraries" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\SettingSync\Namespace\Windows\UserLibraries" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.NavPaneShowLibraries" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.NavPaneShowLibraries" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.NavPaneShowLibraries" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Namespace\Windows\UserLibraries" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Namespace\Windows\UserLibraries" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Namespace\Windows\UserLibraries" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\WindowsSettingHandlers\UserLibraries" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\WindowsSettingHandlers\UserLibraries" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\WindowsSettingHandlers\UserLibraries" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.NavPaneShowLibraries" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.NavPaneShowLibraries" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.NavPaneShowLibraries" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{c51b83e5-9edd-4250-b45a-da672ee3c70e}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{c51b83e5-9edd-4250-b45a-da672ee3c70e}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{c51b83e5-9edd-4250-b45a-da672ee3c70e}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{c51b83e5-9edd-4250-b45a-da672ee3c70e}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{c51b83e5-9edd-4250-b45a-da672ee3c70e}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{c51b83e5-9edd-4250-b45a-da672ee3c70e}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{e9711a2f-350f-4ec1-8ebd-21245a8b9376}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{e9711a2f-350f-4ec1-8ebd-21245a8b9376}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{e9711a2f-350f-4ec1-8ebd-21245a8b9376}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{1CF324EC-F905-4c69-851A-DDC8795F71F2}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{1CF324EC-F905-4c69-851A-DDC8795F71F2}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{1CF324EC-F905-4c69-851A-DDC8795F71F2}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{1CF324EC-F905-4c69-851A-DDC8795F71F2}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{1CF324EC-F905-4c69-851A-DDC8795F71F2}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{1CF324EC-F905-4c69-851A-DDC8795F71F2}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{51F649D3-4BFF-42f6-A253-6D878BE1651D}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{51F649D3-4BFF-42f6-A253-6D878BE1651D}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{51F649D3-4BFF-42f6-A253-6D878BE1651D}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{51F649D3-4BFF-42f6-A253-6D878BE1651D}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{51F649D3-4BFF-42f6-A253-6D878BE1651D}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{51F649D3-4BFF-42f6-A253-6D878BE1651D}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{896664F7-12E1-490f-8782-C0835AFD98FC}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{896664F7-12E1-490f-8782-C0835AFD98FC}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{896664F7-12E1-490f-8782-C0835AFD98FC}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{896664F7-12E1-490f-8782-C0835AFD98FC}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{896664F7-12E1-490f-8782-C0835AFD98FC}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{896664F7-12E1-490f-8782-C0835AFD98FC}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" /f


reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\NavPane\ShowLibraries" /f

reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Music" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Music" /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Music" /f
reg delete "HKEY_CLASSES_ROOT\SystemFileAssociations\MyMusic" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "CommonMusic" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Music" /f
reg delete "HKEY_USERS\S-1-5-19\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Music" /f
reg delete "HKEY_USERS\S-1-5-20\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Music" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "CommonMusic" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "CommonMusic" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "CommonMusic" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{3f2a72a7-99fa-4ddb-a5a8-c604edf61d6b}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" /f
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f


%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" /f


%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" /f


%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f


%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f

 
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Pictures" /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Pictures" /f
reg delete "HKEY_CLASSES_ROOT\SystemFileAssociations\MyPictures" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Pictures" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Pictures" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Classes\Local Settings\MuiCache\1\52C64B7E" /v "@C:\Windows\System32\Windows.UI.Immersive.dll,-38304" /f
reg delete "HKEY_USERS\S-1-5-19\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Pictures" /f
reg delete "HKEY_USERS\S-1-5-20\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Pictures" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "CommonPictures" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{0b2baaeb-0042-4dca-aa4d-3ee8648d03e5}" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\StartMenu\StartPanel\PinnedItems\Pictures" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "CommonPictures" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{b3690e58-e961-423b-b687-386ebfd83239}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{b3690e58-e961-423b-b687-386ebfd83239}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{b3690e58-e961-423b-b687-386ebfd83239}" /f

reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{c1f8339f-f312-4c97-b1c6-ecdf5910c5c0}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{0b2baaeb-0042-4dca-aa4d-3ee8648d03e5}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{4dcafe13-e6a7-4c28-be02-ca8c2126280d}" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{b3690e58-e961-423b-b687-386ebfd83239}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{b3690e58-e961-423b-b687-386ebfd83239}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{b3690e58-e961-423b-b687-386ebfd83239}" /f

reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{c1f8339f-f312-4c97-b1c6-ecdf5910c5c0}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "CommonPictures" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "CommonPictures" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Classes\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Classes\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Wow6432Node\Classes\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Classes\CLSID\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Classes\CLSID\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Wow6432Node\Classes\CLSID\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA" /f


%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA" /f


%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" /f


%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" /f


 

reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Video" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "CommonVideo" /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Video" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Video" /f
reg delete "HKEY_CLASSES_ROOT\SystemFileAssociations\MyVideo" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "CommonVideo" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Video" /f
reg delete "HKEY_USERS\S-1-5-19\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Video" /f
reg delete "HKEY_USERS\S-1-5-20\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Video" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "CommonVideo" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{51294DA1-D7B1-485b-9E9A-17CFFE33E187}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{ea25fbd7-3bf7-409e-b97f-3352240903f4}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{292108be-88ab-4f33-9a26-7748e62e37ad}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{5fa96407-7e77-483c-ac93-691d05850de8}" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "CommonVideo" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{51294DA1-D7B1-485b-9E9A-17CFFE33E187}" /f



%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" /f


%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" /f


%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" /f


%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" /f

reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Accents\0\Theme0" /v "Color" /t REG_DWORD /d "9538419" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Accents\0\Theme1" /v "Color" /t REG_DWORD /d "10915422" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Accents\1\Theme0" /v "Color" /t REG_DWORD /d "10766359" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Accents\1\Theme1" /v "Color" /t REG_DWORD /d "10766359" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Accents\2\Theme0" /v "Color" /t REG_DWORD /d "6392360" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Accents\2\Theme1" /v "Color" /t REG_DWORD /d "12235947" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Accents\3\Theme0" /v "Color" /t REG_DWORD /d "8764727" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Accents\3\Theme1" /v "Color" /t REG_DWORD /d "8764727" /f

reg delete "HKLM\SOFTWARE\Microsoft\DiskSnapshot\v2\0\.?users?*?music*" /f
reg delete "HKLM\SOFTWARE\Microsoft\DiskSnapshot\v2\0\.?users?*?onedrive*" /f
reg delete "HKLM\SOFTWARE\Microsoft\DiskSnapshot\v2\0\.?users?*?pictures*" /f
reg delete "HKLM\SOFTWARE\Microsoft\DiskSnapshot\v2\0\.?users?*?videos*" /f

reg delete "HKCU\SOFTWARE\Classes\Local Settings\MuiCache\1\52C64B7E" /v "@windows.storage.dll,-21790" /f
reg delete "HKCU\SOFTWARE\Classes\Local Settings\MuiCache\1\52C64B7E" /v "@windows.storage.dll,-34584" /f
reg delete "HKCU\SOFTWARE\Classes\Local Settings\MuiCache\1\52C64B7E" /v "@windows.storage.dll,-34595" /f
reg delete "HKCU\SOFTWARE\Classes\Local Settings\MuiCache\1\52C64B7E" /v "@windows.storage.dll,-34620" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Classes\Local Settings\MuiCache\1\52C64B7E" /v "@windows.storage.dll,-21790" /f

:skiplibraries



echo.
choice /c yn /t 3 /d y /m "Enable verbose status messages when you sign out of Windows"
if ERRORLEVEL 2 goto skipverbose
if ERRORLEVEL 1 goto verbose


:verbose
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "VerboseStatus" /t REG_DWORD /d 1 /f

:skipverbose



echo.
choice /c yn /t 3 /d y /m "Re-enable automatic registry backups"
if ERRORLEVEL 2 goto skipregback
if ERRORLEVEL 1 goto regback


:regback
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager" /v "EnablePeriodicBackup" /t REG_DWORD /d 1 /f

:skipregback



echo.
choice /c yn /t 3 /d y /m "Disable fast startup for fewer errors while signing in"
if ERRORLEVEL 2 goto skipfstartup
if ERRORLEVEL 1 goto fstartup


:fstartup
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d 0 /f

:skipfstartup




echo.
choice /c yn /t 3 /d n /m "Remove OneDrive"
if ERRORLEVEL 2 goto skiponedrive
if ERRORLEVEL 1 goto onedrive


:onedrive
reg delete "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
reg delete "HKCU\SOFTWARE\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
reg delete "HKCU\SOFTWARE\Classes\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
reg delete "HKEY_USERS\.DEFAULT\SOFTWARE\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
reg delete "HKEY_USERS\.DEFAULT\SOFTWARE\Classes\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d 1 /f

:skiponedrive





REM *** Remove Logon screen wallpaper/background. Will use solid color instead (Accent color) ***
REM Changes in registry do not reflect back to GPEDIT.MSC. Better to do it directly through GPEDIT.MSC UI.
REM reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableLogonBackgroundImage" /t REG_DWORD /d 1 /f

REM *** Always show all icons on the taskbar (next to clock) ***
REM 0 = Show all icons
REM 1 = Hide icons on the taskbar
REM reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "EnableAutoTray" /t REG_DWORD /d 0 /f


echo.
choice /c yn /t 3 /d y /m "Show Hidden files with Explorer"
if ERRORLEVEL 2 goto skiphidden
if ERRORLEVEL 1 goto hidden


:hidden
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f

:skiphidden



echo.
choice /c yn /t 3 /d n /m "Show Super Hidden System files with Explorer"
if ERRORLEVEL 2 goto skipsuperhidden
if ERRORLEVEL 1 goto superhidden


:superhidden
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d 1 /f

:skipsuperhidden



echo.
choice /c yn /t 3 /d y /m "Show known file extensions with Explorer"
if ERRORLEVEL 2 goto skipfileext
if ERRORLEVEL 1 goto fileext


:fileext
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t  REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t  REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t  REG_DWORD /d 0 /f
 
:skipfileext



echo.
choice /c yn /t 3 /d n /m "Show super hidden file extensions with Explorer"
if ERRORLEVEL 2 goto skipsuperfileext
if ERRORLEVEL 1 goto superfileext


:superfileext
reg delete "HKEY_CLASSES_ROOT\lnkfile" /v "NeverShowExt" /f
reg delete "HKEY_CLASSES_ROOT\IE.AssocFile.URL" /v "NeverShowExt" /f
reg delete "HKEY_CLASSES_ROOT\IE.AssocFile.WEBSITE" /v "NeverShowExt" /f
reg delete "HKEY_CLASSES_ROOT\InternetShortcut" /v "NeverShowExt" /f
reg delete "HKEY_CLASSES_ROOT\Microsoft.Website" /v "NeverShowExt" /f
reg delete "HKEY_CLASSES_ROOT\piffile" /v "NeverShowExt" /f
reg delete "HKEY_CLASSES_ROOT\SHCmdFile" /v "NeverShowExt" /f
reg delete "HKEY_CLASSES_ROOT\LibraryFolder" /v "NeverShowExt" /f

:skipsuperfileext


echo.
choice /c yn /t 3 /d y /m "Make the Explorer a bit more colourful (compressed files)"
if ERRORLEVEL 2 goto skipcompressed
if ERRORLEVEL 1 goto compressed


:compressed
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCompColor" /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCompColor" /t REG_DWORD /d 1 /f
:skipcompressed



REM set ANSWER=y 
REM set /p ANSWER= Expand to current folder in the left panel in Explorer? (y/n) [%ANSWER%]:
REM echo. 
REM if %answer%==n goto skipexplorerexpand

REM 0 = Don't expand
REM 1 = Expand
REM reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "NavPaneExpandToCurrentFolder" /t REG_DWORD /d 1 /f

REM :skipexplorerexpand


echo.
choice /c yn /t 3 /d y /m "Disable WiFi Sense"
if ERRORLEVEL 2 goto skipwifisense
if ERRORLEVEL 1 goto wifisense


:wifisense
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v "value" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v "value" /t REG_DWORD /d 0 /f

:skipwifisense



echo. 
choice /c yn /t 3 /d y /m "Turn off those annoying Windows Firewall notifications"
if ERRORLEVEL 2 goto skipfw
if ERRORLEVEL 1 goto fw


:fw
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableEnhancedNotifications" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableNotifications" /t REG_DWORD /d 1 /f

:skipfw



echo.
choice /c yn /t 3 /d y /m "Disable some tracking services"
if ERRORLEVEL 2 goto skipsc
if ERRORLEVEL 1 goto sc


:sc
sc stop diagtrack
echo DiagTrack stopped.
sc config DiagTrack start= disabled
echo DiagTrack disabled.

sc stop diagnosticshub.standardcollector.service
echo standardcollectorstopped.
sc config diagnosticshub.standardcollector.service start= disabled
echo standardcollector disabled.

sc stop dmwappushservice
echo dmwappushservice stopped.
sc config dmwappushservice start= disabled
echo dmwappushservice disabled.

REM sc stop RemoteRegistry
REM echo RemoteRegistry stopped.
REM sc config RemoteRegistry start= disabled

sc stop TrkWks
echo TrkWks stopped.
sc config TrkWks start= disabled
echo TrkWks disabled.

sc stop WMPNetworkSvc
echo WMPNetworkSvc stopped.
sc config WMPNetworkSvc start= disabled
echo WMPNetworkSvc disabled.

sc stop WSearch
echo WSearch stopped.
sc config WSearch start= demand
echo WSearch on demand.

sc stop XblAuthManager
echo XblAuthManager stopped.
sc config XblAuthManager start= disabled
echo XblAuthManager disabled.

sc stop XblGameSave
echo XblGameSave stopped.
sc config XblGameSave start= disabled
echo XblGameSave disabled.

sc stop XboxNetApiSvc
echo XboxNetApiSvc stopped.
sc config XboxNetApiSvc start= disabled
echo XboxNetApiSvc disabled.

sc stop XboxGipSvc
echo XboxGipSvc stopped.
sc config XboxGipSvc start= disabled
echo XboxGipSvc disabled.

sc stop xbgm
echo xbgm stopped.
sc config xbgm start= disabled
echo xbgm disabled.
:skipsc



echo.
choice /c yn /t 3 /d y /m "Disable Superfetch"
if ERRORLEVEL 2 goto skipsuperfetch
if ERRORLEVEL 1 goto superfetch


:superfetch
sc config SysMain start= disabled
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d 0 /f

:skipsuperfetch



echo.
choice /c yn /t 3 /d y /m "Disable some scheduled tasks tracking"
if ERRORLEVEL 2 goto skipschedtasks
if ERRORLEVEL 1 goto schedtasks


:schedtasks
schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /Disable
echo AppID\SmartScreenSpecific disabled.
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
echo Microsoft Compatibility Appraiser disabled.
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
echo Application Experience\ProgramDataUpdater disabled.
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable
echo Application Experience\StartupAppTask" disabled.
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable
echo Autochk\Proxy disabled.
REM schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
echo Customer Experience Improvement Program\Consolidator disabled.
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable
echo Customer Experience Improvement Program\KernelCeipTask disabled.
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
echo Customer Experience Improvement Program\UsbCeip disabled.
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
echo Microsoft-Windows-DiskDiagnosticDataCollector disabled.
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable
echo File History (maintenance mode) disabled.
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Disable
echo WinSAT disabled.
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable
echo GatherNetworkInfo disabled.
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable
echo PI\Sqm-Tasks disabled.
schtasks /Change /TN "Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /Disable
echo ForceSynchronizeTime disabled.
REM schtasks /Change /TN "Microsoft\Windows\Time Synchronization\SynchronizeTime" /Disable
REM echo SynchronizeTime disabled.
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable
echo QueueReporting disabled.
REM schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Automatic App Update" /Disable
REM echo Automatic App Update disabled.
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /Disable
echo Siuf disabled.
:skipschedtasks




REM *** Disable the stubborn scheduled tasks "BackgroundUploadTask" & "Metadata Refresh" ***
REM "BackgroundUploadTask" is located in "Task Scheduler Library\Microsoft\Windows\SettingSync".
REM "Metadata Refresh" is located in "Task Scheduler Library\Microsoft\Windows\Device Setup".
REM These tasks are enabled by default (status Ready), and cannot be disabled by any regular means.
REM A single bit in the registry keys is responsible for enabling/disabling these tasks.
REM Go to: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks
REM Search for "BackgroundUploadTask" in this location, and note the task's ID.
REM 1st we need to take ownership. In the following commands, replace XXX with the task's ID, and run them in CMD:
REM %SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{XXXXXXXX-XXX-XXXX-XXXX-XXXXXXXXXXXX}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
REM %SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{XXXXXXXX-XXX-XXXX-XXXX-XXXXXXXXXXXX}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
REM Now we can edit the contents of the key.
REM Within this key, there is a binary value named "Triggers", which contains a series of bits.
REM Open it and make sure the format is set to "byte".
REM Go to the 6th row, 3rd column, and change (double-click on) it from "C0" to "00". Press OK and you're done.
REM Do all the steps above for the "Metadata Refresh" task.



echo.
choice /c yn /t 3 /d y /m "Add the option Processor performance core parking min cores"
if ERRORLEVEL 2 goto skipprocessor
if ERRORLEVEL 1 goto processor


:processor
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "Attributes" /t REG_DWORD /d 0 /f

:skipprocessor



echo.
choice /c yn /t 3 /d n /m "Disable CPU Core Parking"
if ERRORLEVEL 2 goto skipparking
if ERRORLEVEL 1 goto parking


:parking
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d 0 /f

:skipparking



echo.
choice /c yn /t 3 /d y /m "Remove the DiagTrack package using DISM"
if ERRORLEVEL 2 goto skipdiagtrack
if ERRORLEVEL 1 goto diagtrack


:diagtrack
REM dism /online /remove-package /packagename:Microsoft-Windows-DiagTrack-Internal-Package~31bf3856ad364e35~amd64~~10.0.10240.16384 /NoRestart
call C:\Windows\Temp\KillDiagTrack.exe Microsoft-Windows-DiagTrack
:skipdiagtrack



echo.
choice /c yn /t 3 /d y /m "Remove already installed Apps"
if ERRORLEVEL 2 goto skipapps
if ERRORLEVEL 1 goto apps


:apps
call C:\Windows\Temp\AppUninstaller.exe

echo.
echo Waiting for some background services to stop...
echo.
timeout 100 /nobreak
echo.
echo.
:skipapps




echo.
choice /c yn /t 3 /d y /m "Disable preinstalled Apps"
if ERRORLEVEL 2 goto skipdisableapps
if ERRORLEVEL 1 goto disableapps


:disableapps
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f
REM reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f
:skipdisableapps



goto ending













:manual
set ANSWER=y
set /p ANSWER= Disable creation of an Advertising ID? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipadid

reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f

:skipadid



REM set ANSWER=y
REM set /p ANSWER= Remove Telemetry and Data Collection? (y/n) [%ANSWER%]:
REM echo. 
REM if %answer%==n goto skiptelemetry

REM Changes in registry do not reflect back to GPEDIT.MSC. Better to do it directly through GPEDIT.MSC UI.
REM reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d 1 /f
REM reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
REM reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v DontOfferThroughWUAU /t REG_DWORD /d 1 /f
REM reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f
REM reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f
REM reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f
REM reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
REM reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f
REM reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d 0 /f
REM reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Telemetry" /v "Enabled" /t REG_DWORD /d 0 /f
REM reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\TCPIPLOGGER" /v "Start" /t REG_DWORD /d 0 /f REM *** NOT SURE ABOUT THIS ONE YET
REM reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\ReadyBoot" /v "Start" /t REG_DWORD /d 0 /f REM *** NOT SURE ABOUT THIS ONE YET

REM :skiptelemetry


set ANSWER=y
set /p ANSWER= Change some IE settings (like download path, sending browsing history and so on)? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipie11

echo.
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Default Download Directory" /t REG_SZ /d "D:\DOWNLOADS"
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DoNotTrack" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Search Page" /t REG_SZ /d "http://www.google.de" /f
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Start Page Redirect Cache" /t REG_SZ /d "http://www.google.de" /f
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "PlaySounds" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Isolation" /t REG_SZ /d PMEM /f
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Isolation64Bit" /t REG_DWORD /d 1 /f

reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Default Download Directory" /t REG_SZ /d "D:\DOWNLOADS"
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DoNotTrack" /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Search Page" /t REG_SZ /d "http://www.google.de" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Start Page Redirect Cache" /t REG_SZ /d "http://www.google.de" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Internet Explorer\Main" /v "PlaySounds" /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Isolation" /t REG_SZ /d PMEM /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Isolation64Bit" /t REG_DWORD /d 1 /f

REM *** Add Google as search provider for IE11, and make it the default ***
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /f
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "DisplayName" /t REG_SZ /d "Google" /f
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "FaviconURL" /t REG_SZ /d "http://www.google.de/favicon.ico" /f
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "FaviconURLFallback" /t REG_SZ /d "http://www.google.de/favicon.ico" /f
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "OSDFileURL" /t REG_SZ /d "http://www.iegallery.com/en-us/AddOns/DownloadAddOn?resourceId=813" /f
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "ShowSearchSuggestions" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "SuggestionsURL" /t REG_SZ /d "http://clients5.google.de/complete/search?q={searchTerms}&client=ie8&mw={ie:maxWidth}&sh={ie:sectionHeight}&rh={ie:rowHeight}&inputencoding={inputEncoding}&outputencoding={outputEncoding}" /f
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "SuggestionsURLFallback" /t REG_SZ /d "http://clients5.google.com/complete/search?hl={language}&q={searchTerms}&client=ie8&inputencoding={inputEncoding}&outputencoding={outputEncoding}" /f
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "TopResultURLFallback" /t REG_SZ /d "" /f
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "URL" /t REG_SZ /d "http://www.google.de/search?q={searchTerms}&sourceid=ie7&rls=com.microsoft:{language}:{referrer:source}&ie={inputEncoding?}&oe={outputEncoding?}" /f
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes" /v "DefaultScope" /t REG_SZ /d "{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /f

reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /f
reg add "HKEY_USERS\.DEFAULT\\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "DisplayName" /t REG_SZ /d "Google" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "FaviconURL" /t REG_SZ /d "http://www.google.de/favicon.ico" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "FaviconURLFallback" /t REG_SZ /d "http://www.google.de/favicon.ico" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "OSDFileURL" /t REG_SZ /d "http://www.iegallery.com/en-us/AddOns/DownloadAddOn?resourceId=813" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "ShowSearchSuggestions" /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "SuggestionsURL" /t REG_SZ /d "http://clients5.google.de/complete/search?q={searchTerms}&client=ie8&mw={ie:maxWidth}&sh={ie:sectionHeight}&rh={ie:rowHeight}&inputencoding={inputEncoding}&outputencoding={outputEncoding}" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "SuggestionsURLFallback" /t REG_SZ /d "http://clients5.google.com/complete/search?hl={language}&q={searchTerms}&client=ie8&inputencoding={inputEncoding}&outputencoding={outputEncoding}" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "TopResultURLFallback" /t REG_SZ /d "" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "URL" /t REG_SZ /d "http://www.google.de/search?q={searchTerms}&sourceid=ie7&rls=com.microsoft:{language}:{referrer:source}&ie={inputEncoding?}&oe={outputEncoding?}" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Internet Explorer\SearchScopes" /v "DefaultScope" /t REG_SZ /d "{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /f


REM *** Disable IE Suggested Sites & Flip ahead (page prediction which sends browsing history to Microsoft) ***
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Suggested Sites" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Suggested Sites" /v "DataStreamEnabledState" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\FlipAhead" /v "FPEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d 0 /f

:skipie11


echo.
set ANSWER=y
set /p ANSWER= Disable synchronisation of user settings? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipusersets

reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d 5 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d 0 /f

reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d 5 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d 0 /f

:skipusersets


echo.
set ANSWER=y
set /p ANSWER= Don't allow Windows Defender to submit samples to MAPS (formerly SpyNet)? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipwindef

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet" /v "SpyNetReporting" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d 1 /f

:skipwindef



echo.
set ANSWER=y
set /p ANSWER=  ***FOR SPECIAL USERS*** Add "Reboot to Recovery" to right-click menu of "This PC"? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipreboottorecovery

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg add "HKEY_CLASSES_ROOT\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell\Reboot to Recovery" /v "Icon" /t REG_SZ /d %SystemRoot%\System32\imageres.dll,-110" /f
reg add "HKEY_CLASSES_ROOT\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell\Reboot to Recovery\command" /ve /d "shutdown.exe -r -o -f -t 00" /f

:skipreboottorecovery



echo.
set ANSWER=y
set /p ANSWER=  Disable Cortana? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipcortana

REM HIER GUCKEN
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f


REM HIER GUCKEN
REM reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!dss-winrt-telemetry.js" /t REG_DWORD /d 0 /f
REM reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry.js" /t REG_DWORD /d 0 /f
REM reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry-event_8ac43a41e5030538" /t REG_DWORD /d 0 /f
REM reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry-inter_58073761d33f144b" /t REG_DWORD /d 0 /f

reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f 
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f 
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f 
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f 
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f 
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f 
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f 
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f 

:skipcortana



echo.
set ANSWER=y
set /p ANSWER=  Hide the search box from taskbar? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipsearch

reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f

:skipsearch




echo.
set ANSWER=y
set /p ANSWER=  Remove telemetry from search? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipsearchtel


reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d 1 /f

:skipsearchtel




echo.
set ANSWER=y
set /p ANSWER=  Remove more telemetry? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skiptel

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f

:skiptel



echo.
set ANSWER=y
set /p ANSWER=  Remove even more telemetry? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipmoretel

reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d 0 /f

:skipmoretel




echo.
set ANSWER=y
set /p ANSWER=  Disable location? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skiploc

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d 1 /f
:skiploc



echo.
set ANSWER=y
set /p ANSWER=  Remove sharing of handwriting? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skiphand

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v  "PreventHandwritingErrorReports" /t REG_DWORD /d 1 /f			
:skiphand



echo.
set ANSWER=y
set /p ANSWER=  Disable MRU (jump lists) lists? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipmru

REM TESTEN*** Disable MRU lists (jump lists) of XAML apps in Start Menu ***
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d 0 /f

:skipmru



echo.
set ANSWER=y
set /p ANSWER= Set Windows Explorer to start on This PC instead of Quick Access? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipexp

reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d 1 /f

:skipexp



echo.
set ANSWER=y
set /p ANSWER= Create Desktop Shortcuts? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipshorts

REM Computer
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0 /f 
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0 /f 
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0 /f 
REM Network 
REM reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" /t REG_DWORD /d 0 /f 
REM User's folder
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{450D8FBA-AD25-11D0-98A8-0800361B1103}" /t REG_DWORD /d 0 /f 
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{450D8FBA-AD25-11D0-98A8-0800361B1103}" /t REG_DWORD /d 0 /f 
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{450D8FBA-AD25-11D0-98A8-0800361B1103}" /t REG_DWORD /d 0 /f 

:skipshorts



echo.
set ANSWER=n
set /p ANSWER= ***ADMIN ONLY*** Add "Take Ownership" on right-click menu of files and folders? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipownership

reg add "HKEY_CLASSES_ROOT\*\shell\runas" /ve /t REG_SZ /d "Take ownership" /f
reg add "HKEY_CLASSES_ROOT\*\shell\runas" /v "HasLUAShield" /t REG_SZ /d "" /f
reg add "HKEY_CLASSES_ROOT\*\shell\runas" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
reg add "HKEY_CLASSES_ROOT\*\shell\runas\command" /ve /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" /a && icacls \"%%1\" /grant Administrators:F" /f
reg add "HKEY_CLASSES_ROOT\*\shell\runas\command" /v "IsolatedCommand" /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" /a && icacls \"%%1\" /grant Administrators:F" /f
reg add "HKEY_CLASSES_ROOT\Directory\shell\runas" /ve /t REG_SZ /d "Take ownership" /f
reg add "HKEY_CLASSES_ROOT\Directory\shell\runas" /v "HasLUAShield" /t REG_SZ /d "" /f
reg add "HKEY_CLASSES_ROOT\Directory\shell\runas" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
reg add "HKEY_CLASSES_ROOT\Directory\shell\runas\command" /ve /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" /a /r /d y && icacls \"%%1\" /grant Administrators:F /t" /f
reg add "HKEY_CLASSES_ROOT\Directory\shell\runas\command" /v "IsolatedCommand" /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" /a /r /d y && icacls \"%%1\" /grant Administrators:F /t" /f

:skipownership



echo.
set ANSWER=y
set /p ANSWER= Turn OFF Sticky Keys when SHIFT is pressed 5 times? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipstickykeys

reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "506" /f
reg add "HKEY_USERS\.DEFAULT\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "506" /f

:skipstickykeys



echo.
set ANSWER=y
set /p ANSWER= Underline keyboard shortcuts and access keys? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipunderline

REM *** Underline keyboard shortcuts and access keys ***
reg add "HKCU\Control Panel\Accessibility\Keyboard Preference" /v "On" /t REG_SZ /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Control Panel\Accessibility\Keyboard Preference" /v "On" /t REG_SZ /d 1 /f

:skipunderline



echo.
set ANSWER=y
set /p ANSWER= Use Windows Photo Viewer to open *.tif files instead of Paint? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skippaint

reg add "HKCU\Software\Classes\.jpg" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKCU\Software\Classes\.jpeg" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKCU\Software\Classes\.gif" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKCU\Software\Classes\.png" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKCU\Software\Classes\.bmp" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKCU\Software\Classes\.tiff" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKCU\Software\Classes\.ico" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKEY_USERS\.DEFAULT\Software\Classes\.jpg" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKEY_USERS\.DEFAULT\Software\Classes\.jpeg" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKEY_USERS\.DEFAULT\Software\Classes\.gif" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKEY_USERS\.DEFAULT\Software\Classes\.png" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKEY_USERS\.DEFAULT\Software\Classes\.bmp" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKEY_USERS\.DEFAULT\Software\Classes\.tiff" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKEY_USERS\.DEFAULT\Software\Classes\.ico" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKCR\Applications\photoviewer.dll\shell\open" /v "MuiVerb" /t REG_SZ /d "@photoviewer.dll,-3043" /f
reg add "HKCR\Applications\photoviewer.dll\shell\open\command" /ve /t REG_EXPAND_SZ /d "%%SystemRoot%%\System32\rundll32.exe \"%%ProgramFiles%%\Windows Photo Viewer\PhotoViewer.dll\", ImageView_Fullscreen %%1" /f
reg add "HKCR\Applications\photoviewer.dll\shell\open\DropTarget" /v "Clsid" /t REG_SZ /d "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" /f
reg add "HKCR\Applications\photoviewer.dll\shell\print\command" /ve /t REG_EXPAND_SZ /d "%%SystemRoot%%\System32\rundll32.exe \"%%ProgramFiles%%\Windows Photo Viewer\PhotoViewer.dll\", ImageView_Fullscreen %%1" /f
reg add "HKCR\Applications\photoviewer.dll\shell\print\DropTarget" /v "Clsid" /t REG_SZ /d "{60fd46de-f830-4894-a628-6fa81bc0190d}" /f

:skippaint



echo.
set ANSWER=y
set /p ANSWER= Remove Music, Pictures and Videos from Start Menu places (remove liks only)? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipstartmenuplaces

del "C:\ProgramData\Microsoft\Windows\Start Menu Places\05 - Music.lnk"
del "C:\ProgramData\Microsoft\Windows\Start Menu Places\06 - Pictures.lnk"
del "C:\ProgramData\Microsoft\Windows\Start Menu Places\07 - Videos.lnk"

:skipstartmenuplaces



echo.
set ANSWER=n
set /p ANSWER= Remove Libraries and everything in there? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skiplibraries

del "%userprofile%\AppData\Roaming\Microsoft\Windows\Libraries\Music.library-ms"
del "%userprofile%\AppData\Roaming\Microsoft\Windows\Libraries\Pictures.library-ms"
del "%userprofile%\AppData\Roaming\Microsoft\Windows\Libraries\Videos.library-ms"
 

reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UsersLibraries" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{59BD6DD1-5CEC-4d7e-9AD2-ECC64154418D}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{C4D98F09-6124-4fe0-9942-826416082DA9}" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{59BD6DD1-5CEC-4d7e-9AD2-ECC64154418D}" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{C4D98F09-6124-4fe0-9942-826416082DA9}" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\UsersLibraries" /f
reg delete "HKCU\SOFTWARE\Classes\Local Settings\MuiCache\1\52C64B7E" /v "@C:\Windows\system32\windows.storage.dll,-50691" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\SettingSync\WindowsSettingHandlers\UserLibraries" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\SettingSync\WindowsSettingHandlers\UserLibraries" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\SettingSync\WindowsSettingHandlers\UserLibraries" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\SettingSync\Namespace\Windows\UserLibraries" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\SettingSync\Namespace\Windows\UserLibraries" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\SettingSync\Namespace\Windows\UserLibraries" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.NavPaneShowLibraries" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.NavPaneShowLibraries" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.NavPaneShowLibraries" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Namespace\Windows\UserLibraries" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Namespace\Windows\UserLibraries" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Namespace\Windows\UserLibraries" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\WindowsSettingHandlers\UserLibraries" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\WindowsSettingHandlers\UserLibraries" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\WindowsSettingHandlers\UserLibraries" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.NavPaneShowLibraries" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.NavPaneShowLibraries" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.NavPaneShowLibraries" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{c51b83e5-9edd-4250-b45a-da672ee3c70e}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{c51b83e5-9edd-4250-b45a-da672ee3c70e}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{c51b83e5-9edd-4250-b45a-da672ee3c70e}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{c51b83e5-9edd-4250-b45a-da672ee3c70e}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{c51b83e5-9edd-4250-b45a-da672ee3c70e}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{c51b83e5-9edd-4250-b45a-da672ee3c70e}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{e9711a2f-350f-4ec1-8ebd-21245a8b9376}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{e9711a2f-350f-4ec1-8ebd-21245a8b9376}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{e9711a2f-350f-4ec1-8ebd-21245a8b9376}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{1CF324EC-F905-4c69-851A-DDC8795F71F2}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{1CF324EC-F905-4c69-851A-DDC8795F71F2}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{1CF324EC-F905-4c69-851A-DDC8795F71F2}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{1CF324EC-F905-4c69-851A-DDC8795F71F2}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{1CF324EC-F905-4c69-851A-DDC8795F71F2}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{1CF324EC-F905-4c69-851A-DDC8795F71F2}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{51F649D3-4BFF-42f6-A253-6D878BE1651D}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{51F649D3-4BFF-42f6-A253-6D878BE1651D}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{51F649D3-4BFF-42f6-A253-6D878BE1651D}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{51F649D3-4BFF-42f6-A253-6D878BE1651D}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{51F649D3-4BFF-42f6-A253-6D878BE1651D}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{51F649D3-4BFF-42f6-A253-6D878BE1651D}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{896664F7-12E1-490f-8782-C0835AFD98FC}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{896664F7-12E1-490f-8782-C0835AFD98FC}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{896664F7-12E1-490f-8782-C0835AFD98FC}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{896664F7-12E1-490f-8782-C0835AFD98FC}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{896664F7-12E1-490f-8782-C0835AFD98FC}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{896664F7-12E1-490f-8782-C0835AFD98FC}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" /f


reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\NavPane\ShowLibraries" /f

reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Music" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Music" /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Music" /f
reg delete "HKEY_CLASSES_ROOT\SystemFileAssociations\MyMusic" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "CommonMusic" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Music" /f
reg delete "HKEY_USERS\S-1-5-19\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Music" /f
reg delete "HKEY_USERS\S-1-5-20\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Music" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "CommonMusic" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "CommonMusic" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "CommonMusic" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{3f2a72a7-99fa-4ddb-a5a8-c604edf61d6b}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" /f
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f

 
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Pictures" /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Pictures" /f
reg delete "HKEY_CLASSES_ROOT\SystemFileAssociations\MyPictures" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Pictures" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Pictures" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Classes\Local Settings\MuiCache\1\52C64B7E" /v "@C:\Windows\System32\Windows.UI.Immersive.dll,-38304" /f
reg delete "HKEY_USERS\S-1-5-19\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Pictures" /f
reg delete "HKEY_USERS\S-1-5-20\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Pictures" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "CommonPictures" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{0b2baaeb-0042-4dca-aa4d-3ee8648d03e5}" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\StartMenu\StartPanel\PinnedItems\Pictures" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "CommonPictures" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{b3690e58-e961-423b-b687-386ebfd83239}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{b3690e58-e961-423b-b687-386ebfd83239}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{b3690e58-e961-423b-b687-386ebfd83239}" /f

reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{c1f8339f-f312-4c97-b1c6-ecdf5910c5c0}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{0b2baaeb-0042-4dca-aa4d-3ee8648d03e5}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{4dcafe13-e6a7-4c28-be02-ca8c2126280d}" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{b3690e58-e961-423b-b687-386ebfd83239}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{b3690e58-e961-423b-b687-386ebfd83239}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{b3690e58-e961-423b-b687-386ebfd83239}" /f

reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{c1f8339f-f312-4c97-b1c6-ecdf5910c5c0}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "CommonPictures" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "CommonPictures" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Classes\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Classes\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Wow6432Node\Classes\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Classes\CLSID\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Classes\CLSID\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Wow6432Node\Classes\CLSID\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" /f
 

reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Video" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "CommonVideo" /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Video" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Video" /f
reg delete "HKEY_CLASSES_ROOT\SystemFileAssociations\MyVideo" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "CommonVideo" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Video" /f
reg delete "HKEY_USERS\S-1-5-19\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Video" /f
reg delete "HKEY_USERS\S-1-5-20\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Video" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "CommonVideo" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{51294DA1-D7B1-485b-9E9A-17CFFE33E187}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{ea25fbd7-3bf7-409e-b97f-3352240903f4}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{292108be-88ab-4f33-9a26-7748e62e37ad}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{5fa96407-7e77-483c-ac93-691d05850de8}" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "CommonVideo" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{51294DA1-D7B1-485b-9E9A-17CFFE33E187}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" /f


reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Accents\0\Theme0" /v "Color" /t REG_DWORD /d "9538419" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Accents\0\Theme1" /v "Color" /t REG_DWORD /d "10915422" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Accents\1\Theme0" /v "Color" /t REG_DWORD /d "10766359" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Accents\1\Theme1" /v "Color" /t REG_DWORD /d "10766359" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Accents\2\Theme0" /v "Color" /t REG_DWORD /d "6392360" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Accents\2\Theme1" /v "Color" /t REG_DWORD /d "12235947" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Accents\3\Theme0" /v "Color" /t REG_DWORD /d "8764727" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Accents\3\Theme1" /v "Color" /t REG_DWORD /d "8764727" /f

reg delete "HKLM\SOFTWARE\Microsoft\DiskSnapshot\v2\0\.?users?*?music*" /f
reg delete "HKLM\SOFTWARE\Microsoft\DiskSnapshot\v2\0\.?users?*?onedrive*" /f
reg delete "HKLM\SOFTWARE\Microsoft\DiskSnapshot\v2\0\.?users?*?pictures*" /f
reg delete "HKLM\SOFTWARE\Microsoft\DiskSnapshot\v2\0\.?users?*?videos*" /f

reg delete "HKCU\SOFTWARE\Classes\Local Settings\MuiCache\1\52C64B7E" /v "@windows.storage.dll,-21790" /f
reg delete "HKCU\SOFTWARE\Classes\Local Settings\MuiCache\1\52C64B7E" /v "@windows.storage.dll,-34584" /f
reg delete "HKCU\SOFTWARE\Classes\Local Settings\MuiCache\1\52C64B7E" /v "@windows.storage.dll,-34595" /f
reg delete "HKCU\SOFTWARE\Classes\Local Settings\MuiCache\1\52C64B7E" /v "@windows.storage.dll,-34620" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Classes\Local Settings\MuiCache\1\52C64B7E" /v "@windows.storage.dll,-21790" /f

:skiplibraries



echo.
set ANSWER=y
set /p ANSWER= Enable verbose status messages when you sign in/out of Windows? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipverbose

reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "VerboseStatus" /t REG_DWORD /d 1 /f

:skipverbose


echo.
set ANSWER=y
set /p ANSWER= Re-enable automatic registry backups? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipregback

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager" /v "EnablePeriodicBackup" /t REG_DWORD /d 1 /f

:skipregback



echo.
set ANSWER=y
set /p ANSWER= Disable fast startup for fewer errors while signing in? (y/n) [%ANSWER%]: 
echo. 
if %answer%==n goto skipfstartup

reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d 0 /f

:skipfstartup


echo.
set ANSWER=n
set /p ANSWER= Remove OneDrive? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skiponedrive

reg delete "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
reg delete "HKCU\SOFTWARE\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
reg delete "HKCU\SOFTWARE\Classes\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
reg delete "HKEY_USERS\.DEFAULT\SOFTWARE\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
reg delete "HKEY_USERS\.DEFAULT\SOFTWARE\Classes\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d 1 /f

:skiponedrive





REM *** Remove Logon screen wallpaper/background. Will use solid color instead (Accent color) ***
REM Changes in registry do not reflect back to GPEDIT.MSC. Better to do it directly through GPEDIT.MSC UI.
REM reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableLogonBackgroundImage" /t REG_DWORD /d 1 /f

REM *** Always show all icons on the taskbar (next to clock) ***
REM 0 = Show all icons
REM 1 = Hide icons on the taskbar
REM reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "EnableAutoTray" /t REG_DWORD /d 0 /f


echo.
set ANSWER=y
set /p ANSWER= ***FOR EXPERIENCED USERS*** Show Hidden files in Explorer? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skiphidden

reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f

:skiphidden



echo.
set ANSWER=n
set /p ANSWER= ***ADMIN ONLY*** Show Super Hidden System files in Explorer? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipsuperhidden

reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d 1 /f

:skipsuperhidden



echo.
set ANSWER=y
set /p ANSWER= Show known file extensions in Explorer (n is not an option!;)? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipfileext

reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t  REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t  REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t  REG_DWORD /d 0 /f
 
:skipfileext


echo.
set ANSWER=n
set /p ANSWER= ***ADMIN ONLY*** Show super-duper hidden extensions? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipsuperfileext

reg delete "HKEY_CLASSES_ROOT\lnkfile" /v "NeverShowExt" /f
reg delete "HKEY_CLASSES_ROOT\IE.AssocFile.URL" /v "NeverShowExt" /f
reg delete "HKEY_CLASSES_ROOT\IE.AssocFile.WEBSITE" /v "NeverShowExt" /f
reg delete "HKEY_CLASSES_ROOT\InternetShortcut" /v "NeverShowExt" /f
reg delete "HKEY_CLASSES_ROOT\Microsoft.Website" /v "NeverShowExt" /f
reg delete "HKEY_CLASSES_ROOT\piffile" /v "NeverShowExt" /f
reg delete "HKEY_CLASSES_ROOT\SHCmdFile" /v "NeverShowExt" /f
reg delete "HKEY_CLASSES_ROOT\LibraryFolder" /v "NeverShowExt" /f

:skipsuperfileext


echo.
set ANSWER=y
set /p ANSWER= Make the Explorer a bit more colourful (compressed files)? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipcompressed

reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCompColor" /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCompColor" /t REG_DWORD /d 1 /f

:skipcompressed



REM set ANSWER=y 
REM set /p ANSWER= Expand to current folder in the left panel in Explorer? (y/n) [%ANSWER%]:
REM echo. 
REM if %answer%==n goto skipexplorerexpand

REM 0 = Don't expand
REM 1 = Expand
REM reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "NavPaneExpandToCurrentFolder" /t REG_DWORD /d 1 /f

REM :skipexplorerexpand



echo.
set ANSWER=y
set /p ANSWER= Disable WiFi Sense? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipwifisense

reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v "value" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v "value" /t REG_DWORD /d 0 /f

:skipwifisense



echo. 
set ANSWER=y
set /p ANSWER= Turn off those annoying Windows Firewall notifications? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipfw

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableEnhancedNotifications" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableNotifications" /t REG_DWORD /d 1 /f

:skipfw



echo.
set ANSWER=y
set /p ANSWER= Disable some tracking services? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipsc

sc stop diagtrack
echo DiagTrack stopped.
sc config DiagTrack start= disabled
echo DiagTrack disabled.

sc stop diagnosticshub.standardcollector.service
echo standardcollectorstopped.
sc config diagnosticshub.standardcollector.service start= disabled
echo standardcollector disabled.

sc stop dmwappushservice
echo dmwappushservice stopped.
sc config dmwappushservice start= disabled
echo dmwappushservice disabled.

REM sc stop RemoteRegistry
REM echo RemoteRegistry stopped.
REM sc config RemoteRegistry start= disabled

sc stop TrkWks
echo TrkWks stopped.
sc config TrkWks start= disabled
echo TrkWks disabled.

sc stop WMPNetworkSvc
echo WMPNetworkSvc stopped.
sc config WMPNetworkSvc start= disabled
echo WMPNetworkSvc disabled.

sc stop WSearch
echo WSearch stopped.
sc config WSearch start= demand
echo WSearch on demand.

sc stop XblAuthManager
echo XblAuthManager stopped.
sc config XblAuthManager start= disabled
echo XblAuthManager disabled.

sc stop XblGameSave
echo XblGameSave stopped.
sc config XblGameSave start= disabled
echo XblGameSave disabled.

sc stop XboxNetApiSvc
echo XboxNetApiSvc stopped.
sc config XboxNetApiSvc start= disabled
echo XboxNetApiSvc disabled.

sc stop XboxGipSvc
echo XboxGipSvc stopped.
sc config XboxGipSvc start= disabled
echo XboxGipSvc disabled.

sc stop xbgm
echo xbgm stopped.
sc config xbgm start= disabled
echo xbgm disabled.

:skipsc



echo.
set ANSWER=y
set /p ANSWER= Disable Superfetch? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipsuperfetch

sc config SysMain start= disabled
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d 0 /f

:skipsuperfetch



echo.
set ANSWER=y
set /p ANSWER= Disable some scheduled tasks tracking? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipschedtasks

schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /Disable
echo AppID\SmartScreenSpecific disabled.
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
echo Microsoft Compatibility Appraiser disabled.
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
echo Application Experience\ProgramDataUpdater disabled.
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable
echo Application Experience\StartupAppTask" disabled.
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable
echo Autochk\Proxy disabled.
REM schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
echo Customer Experience Improvement Program\Consolidator disabled.
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable
echo Customer Experience Improvement Program\KernelCeipTask disabled.
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
echo Customer Experience Improvement Program\UsbCeip disabled.
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
echo Microsoft-Windows-DiskDiagnosticDataCollector disabled.
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable
echo File History (maintenance mode) disabled.
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Disable
echo WinSAT disabled.
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable
echo GatherNetworkInfo disabled.
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable
echo PI\Sqm-Tasks disabled.
schtasks /Change /TN "Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /Disable
echo ForceSynchronizeTime disabled.
REM schtasks /Change /TN "Microsoft\Windows\Time Synchronization\SynchronizeTime" /Disable
REM echo SynchronizeTime disabled.
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable
echo QueueReporting disabled.
REM schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Automatic App Update" /Disable
REM echo Automatic App Update disabled.
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /Disable
echo Siuf disabled.
:skipschedtasks




REM *** Disable the stubborn scheduled tasks "BackgroundUploadTask" & "Metadata Refresh" ***
REM "BackgroundUploadTask" is located in "Task Scheduler Library\Microsoft\Windows\SettingSync".
REM "Metadata Refresh" is located in "Task Scheduler Library\Microsoft\Windows\Device Setup".
REM These tasks are enabled by default (status Ready), and cannot be disabled by any regular means.
REM A single bit in the registry keys is responsible for enabling/disabling these tasks.
REM Go to: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks
REM Search for "BackgroundUploadTask" in this location, and note the task's ID.
REM 1st we need to take ownership. In the following commands, replace XXX with the task's ID, and run them in CMD:
REM %SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{XXXXXXXX-XXX-XXXX-XXXX-XXXXXXXXXXXX}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
REM %SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{XXXXXXXX-XXX-XXXX-XXXX-XXXXXXXXXXXX}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
REM Now we can edit the contents of the key.
REM Within this key, there is a binary value named "Triggers", which contains a series of bits.
REM Open it and make sure the format is set to "byte".
REM Go to the 6th row, 3rd column, and change (double-click on) it from "C0" to "00". Press OK and you're done.
REM Do all the steps above for the "Metadata Refresh" task.


echo.
set ANSWER=y
set /p ANSWER= Add the option "Processor performance core parking min cores"? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipprocessor

reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "Attributes" /t REG_DWORD /d 0 /f

:skipprocessor



echo.
set ANSWER=n
set /p ANSWER= Disable CPU Core Parking (should not be done on laptops)? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipparking

reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d 0 /f

:skipparking



echo.
set ANSWER=y
set /p ANSWER= Remove the DiagTrack package using DISM? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipdiagtrack

call C:\Windows\Temp\KillDiagTrack.exe Microsoft-Windows-DiagTrack
 
:skipdiagtrack



echo.
set ANSWER=y
set /p ANSWER= Remove already installed Apps? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipapps

call C:\Windows\Temp\AppUninstaller.exe


:skipapps

echo.
echo Waiting for some background services to stop...
echo.
timeout 100 /nobreak
echo.
echo.



echo.
set ANSWER=y
set /p ANSWER= Disable preinstalled Apps? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipdisableapps


reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f
REM reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f
:skipdisableapps

goto ending







REM HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection\AllowTelemetry=0
REM HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection\AllowTelemetry=0
REM HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\MRT\DontReportInfectionInformation=1
REM HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\AppCompat\DisableUAR=1
REM HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\AppCompat\DisableInventory=1
REM HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\AppCompat\AITEnable=0
REM HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\DataCollection\AllowTelemetry=0
REM HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\HandwritingErrorReports\PreventHandwritingErrorReports=1
REM HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\LocationAndSensors\DisableLocation=1
REM HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\LocationAndSensors\DisableWindowsLocationProvider=1
REM HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive\DisableFileSyncNGSC=1
REM HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\TabletPC\PreventHandwritingDataSharing=1
REM HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\Windows Search\AllowCortana=0
REM HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\Windows Search\AllowSearchToUseLocation=0
REM HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\Windows Search\DisableWebSearch=1
REM HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\Windows Search\ConnectedSearchUseWeb=0
REM HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender\Spynet\SubmitSamplesConsent=2
REM HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender\Spynet\SpyNetReporting=0
REM HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\WMDRM\DisableOnline=1
REM HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MRT\DontReportInfectionInformation=1
REM HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat\DisableUAR=1
REM HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat\DisableInventory=1
REM HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat\AITEnable=0
REM HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowTelemetry=0
REM HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports\PreventHandwritingErrorReports=1
REM HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors\DisableLocation=1
REM HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors\DisableWindowsLocationProvider=1
REM HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OneDrive\DisableFileSyncNGSC=1
REM HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC\PreventHandwritingDataSharing=1
REM HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search\AllowCortana=0
REM HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search\AllowSearchToUseLocation=0
REM HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search\DisableWebSearch=1
REM HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search\ConnectedSearchUseWeb=0
REM HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet\SubmitSamplesConsent=2
REM HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet\SpyNetReporting=0
REM HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WMDRM\DisableOnline=1
REM HKEY_CURRENT_USER\Control Panel\Desktop\TranscodedImageCount=2

REM HKEY_CURRENT_USER\Software\Microsoft\Input\TIPC\Enabled=0
REM HKEY_CURRENT_USER\Software\Microsoft\InputPersonalization\RestrictImplicitInkCollection=1
REM HKEY_CURRENT_USER\Software\Microsoft\InputPersonalization\RestrictImplicitTextCollection=1
REM HKEY_CURRENT_USER\Software\Microsoft\InputPersonalization\TrainedDataStore\HarvestContacts=0
REM HKEY_CURRENT_USER\Software\Microsoft\Personalization\Settings\AcceptedPrivacyPolicy=0
REM HKEY_CURRENT_USER\Software\Microsoft\Siuf\Rules\NumberOfSIUFInPeriod=0
REM HKEY_CURRENT_USER\Software\Microsoft\Siuf\Rules\PeriodInNanoSeconds=0
REM HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ExcludedFromStableAnaheimDownloadPromotionSL=1
REM HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search\BingSearchEnabled=0
REM HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SettingSync\SyncPolicy=5
REM HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility\Enabled=0
REM HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings\Enabled=0
REM HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials\Enabled=0
REM HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language\Enabled=0
REM HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization\Enabled=0
REM HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows\Enabled=0

REM HKEY_USERS\S-1-5-21-1708537768-448539723-725345543-124808\Control Panel\Desktop\TranscodedImageCount=2
REM HKEY_USERS\S-1-5-21-1708537768-448539723-725345543-124808\Software\Microsoft\Input\TIPC\Enabled=0
REM HKEY_USERS\S-1-5-21-1708537768-448539723-725345543-124808\Software\Microsoft\InputPersonalization\RestrictImplicitInkCollection=1
REM HKEY_USERS\S-1-5-21-1708537768-448539723-725345543-124808\Software\Microsoft\InputPersonalization\RestrictImplicitTextCollection=1
REM HKEY_USERS\S-1-5-21-1708537768-448539723-725345543-124808\Software\Microsoft\InputPersonalization\TrainedDataStore\HarvestContacts=0
REM HKEY_USERS\S-1-5-21-1708537768-448539723-725345543-124808\Software\Microsoft\Personalization\Settings\AcceptedPrivacyPolicy=0
REM HKEY_USERS\S-1-5-21-1708537768-448539723-725345543-124808\Software\Microsoft\Siuf\Rules\NumberOfSIUFInPeriod=0
REM HKEY_USERS\S-1-5-21-1708537768-448539723-725345543-124808\Software\Microsoft\Siuf\Rules\PeriodInNanoSeconds=0
REM HKEY_USERS\S-1-5-21-1708537768-448539723-725345543-124808\Software\Microsoft\Windows\CurrentVersion\Explorer\ExcludedFromStableAnaheimDownloadPromotionSL=1
REM HKEY_USERS\S-1-5-21-1708537768-448539723-725345543-124808\Software\Microsoft\Windows\CurrentVersion\Search\BingSearchEnabled=0
REM HKEY_USERS\S-1-5-21-1708537768-448539723-725345543-124808\Software\Microsoft\Windows\CurrentVersion\SettingSync\SyncPolicy=5
REM HKEY_USERS\S-1-5-21-1708537768-448539723-725345543-124808\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility\Enabled=0
REM HKEY_USERS\S-1-5-21-1708537768-448539723-725345543-124808\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings\Enabled=0
REM HKEY_USERS\S-1-5-21-1708537768-448539723-725345543-124808\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials\Enabled=0
REM HKEY_USERS\S-1-5-21-1708537768-448539723-725345543-124808\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language\Enabled=0
REM HKEY_USERS\S-1-5-21-1708537768-448539723-725345543-124808\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization\Enabled=0
REM HKEY_USERS\S-1-5-21-1708537768-448539723-725345543-124808\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows\Enabled=0





REM hier das neue! :)
:ver_win21h1
REM echo Windows 11!
echo.
set ANSWER=y
set /p ANSWER= Tweak everything automatically? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto manual_11
REM hier gehts automatisch los! :D

REM choice /c yn /t 5 /d y /m "Weitermachen (jetzt setze ich die Berechtigungen)"
REM if /I "%c%" EQU "n" goto :manuell
REM if /I "%c%" NEQ "n" goto :auto



choice /c yn /t 3 /d y /m "Disable creation of an Advertising ID"
if ERRORLEVEL 2 goto skipadid
if ERRORLEVEL 1 goto adid

:adid
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f
:skipadid



REM kein ie mehr.
echo.
choice /c yn /t 3 /d y /m "Disable Problem Step Recorder"
if ERRORLEVEL 2 goto skipuar
if ERRORLEVEL 1 goto uar

:uar
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f
:skipuar



echo.
choice /c yn /t 3 /d y /m "Prevent Windows Media DRM from connecting to the Internet"
if ERRORLEVEL 2 goto skipdrm
if ERRORLEVEL 1 goto drm

:drm
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\WMDRM" /v "DisableOnline" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WMDRM" /v "DisableOnline" /t REG_DWORD /d 1 /f
:skipdrm


echo.
choice /c yn /t 3 /d y /m "Keep Edge away from doing Stuff on it's own"
if ERRORLEVEL 2 goto skipedge
if ERRORLEVEL 1 goto edge

:edge
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ExcludedFromStableAnaheimDownloadPromotionSL" /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ExcludedFromStableAnaheimDownloadPromotionSL" /t REG_DWORD /d 1 /f
:skipedge




echo.
choice /c yn /t 3 /d y /m "Disable synchronisation of user settings"
if ERRORLEVEL 2 goto skipusersets
if ERRORLEVEL 1 goto usersets

:usersets

reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d 5 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d 0 /f

reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d 5 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d 0 /f

:skipusersets


echo.
choice /c yn /t 3 /d y /m "Don't allow Windows Defender to submit samples to MAPS (formerly SpyNet)"
if ERRORLEVEL 2 goto skipwindef
if ERRORLEVEL 1 goto windef


:windef
REM %SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%REM SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet" /v "SpyNetReporting" /t REG_DWORD /d 0 /f
REM die säcke haben das hardgecoded. :/
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender\Spynet" /v "SpyNetReporting" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d 2 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d 1 /f

:skipwindef



echo.
choice /c yn /t 3 /d n /m "Add Reboot to Recovery to right-click menu of This PC"
if ERRORLEVEL 2 goto skipreboottorecovery
if ERRORLEVEL 1 goto reboottorecovery


:reboottorecovery
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg add "HKEY_CLASSES_ROOT\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell\Reboot to Recovery" /v "Icon" /t REG_SZ /d %SystemRoot%\System32\imageres.dll,-110" /f
reg add "HKEY_CLASSES_ROOT\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell\Reboot to Recovery\command" /ve /d "shutdown.exe -r -o -f -t 00" /f

:skipreboottorecovery



echo.
choice /c yn /t 3 /d y /m "Disable Cortana"
if ERRORLEVEL 2 goto skipcortana
if ERRORLEVEL 1 goto cortana


:cortana
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f



REM HIER GUCKEN
REM reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!dss-winrt-telemetry.js" /t REG_DWORD /d 0 /f
REM reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry.js" /t REG_DWORD /d 0 /f
REM reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry-event_8ac43a41e5030538" /t REG_DWORD /d 0 /f
REM reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry-inter_58073761d33f144b" /t REG_DWORD /d 0 /f

reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f 
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f 
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f 
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f 
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f 
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f 
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f 
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f 

:skipcortana




echo.
choice /c yn /t 3 /d y /m "Remove telemetry from search"
if ERRORLEVEL 2 goto skipsearchtel
if ERRORLEVEL 1 goto searchtel

:searchtel
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d 1 /f

:skipsearchtel


echo.
choice /c yn /t 3 /d y /m "Remove more telemetry"
if ERRORLEVEL 2 goto skiptel
if ERRORLEVEL 1 goto tel

:tel

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d 1 /f

:skiptel


echo.
choice /c yn /t 3 /d y /m "Remove even more telemetry"
if ERRORLEVEL 2 goto skipmoretel
if ERRORLEVEL 1 goto moretel

:moretel
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d 0 /f

:skipmoretel

echo.
choice /c yn /t 3 /d y /m "Disable location"
if ERRORLEVEL 2 goto skiploc
if ERRORLEVEL 1 goto loc

:loc
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d 1 /f
:skiploc
				
			
echo.
choice /c yn /t 3 /d y /m "Remove sharing and improving detection of handwriting"
if ERRORLEVEL 2 goto skiphand
if ERRORLEVEL 1 goto hand	

:hand		
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v  "PreventHandwritingErrorReports" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\HandwritingErrorReports" /v  "PreventHandwritingErrorReports" /t REG_DWORD /d 1 /f	
reg add "HKEY_CURRENT_USER\Software\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d 0 /f		
:skiphand

echo.
choice /c yn /t 3 /d y /m "Disable MRU (jump lists) lists"
if ERRORLEVEL 2 goto skipmru
if ERRORLEVEL 1 goto mru


:mru
REM TESTEN*** Disable MRU lists (jump lists) of XAML apps in Start Menu ***
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d 0 /f

:skipmru


echo.
choice /c yn /t 3 /d y /m "Exchange Windows Explorer to start on This PC instead of Quick Access"
if ERRORLEVEL 2 goto skipexp
if ERRORLEVEL 1 goto exp


:exp
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d 1 /f
:skipexp


echo.
choice /c yn /t 3 /d y /m "Create Desktop Shortcuts"
if ERRORLEVEL 2 goto skipshorts
if ERRORLEVEL 1 goto shorts


:shorts
REM Computer
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0 /f 
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0 /f 
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0 /f 
REM Network 
REM reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" /t REG_DWORD /d 0 /f 
REM User's folder
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{450D8FBA-AD25-11D0-98A8-0800361B1103}" /t REG_DWORD /d 0 /f 
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{450D8FBA-AD25-11D0-98A8-0800361B1103}" /t REG_DWORD /d 0 /f 
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{450D8FBA-AD25-11D0-98A8-0800361B1103}" /t REG_DWORD /d 0 /f 
:skipshorts


echo.
choice /c yn /t 3 /d n /m "Add Take Ownership on right-click menu of files and folders"
if ERRORLEVEL 2 goto skipownership
if ERRORLEVEL 1 goto ownership


:ownership
reg add "HKEY_CLASSES_ROOT\*\shell\runas" /ve /t REG_SZ /d "Take ownership" /f
reg add "HKEY_CLASSES_ROOT\*\shell\runas" /v "HasLUAShield" /t REG_SZ /d "" /f
reg add "HKEY_CLASSES_ROOT\*\shell\runas" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
reg add "HKEY_CLASSES_ROOT\*\shell\runas\command" /ve /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" /a && icacls \"%%1\" /grant Administrators:F" /f
reg add "HKEY_CLASSES_ROOT\*\shell\runas\command" /v "IsolatedCommand" /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" /a && icacls \"%%1\" /grant Administrators:F" /f
reg add "HKEY_CLASSES_ROOT\Directory\shell\runas" /ve /t REG_SZ /d "Take ownership" /f
reg add "HKEY_CLASSES_ROOT\Directory\shell\runas" /v "HasLUAShield" /t REG_SZ /d "" /f
reg add "HKEY_CLASSES_ROOT\Directory\shell\runas" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
reg add "HKEY_CLASSES_ROOT\Directory\shell\runas\command" /ve /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" /a /r /d y && icacls \"%%1\" /grant Administrators:F /t" /f
reg add "HKEY_CLASSES_ROOT\Directory\shell\runas\command" /v "IsolatedCommand" /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" /a /r /d y && icacls \"%%1\" /grant Administrators:F /t" /f

:skipownership


echo.
choice /c yn /t 3 /d y /m "Turn OFF Sticky Keys when caps is pressed 5 times"
if ERRORLEVEL 2 goto skipstickykeys
if ERRORLEVEL 1 goto stickykeys

:stickykeys
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "506" /f
reg add "HKEY_USERS\.DEFAULT\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "506" /f
:skipstickykeys



echo.
choice /c yn /t 3 /d y /m "Underline keyboard shortcuts and access keys"
if ERRORLEVEL 2 goto skipunderline
if ERRORLEVEL 1 goto underline


:underline
REM *** Underline keyboard shortcuts and access keys ***
reg add "HKCU\Control Panel\Accessibility\Keyboard Preference" /v "On" /t REG_SZ /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Control Panel\Accessibility\Keyboard Preference" /v "On" /t REG_SZ /d 1 /f
:skipunderline



echo.
choice /c yn /t 3 /d y /m "Remove Music, Pictures and Videos from Start Menu places (remove links only)"
if ERRORLEVEL 2 goto skipstartmenuplaces
if ERRORLEVEL 1 goto startmenuplaces


:startmenuplaces
del "C:\ProgramData\Microsoft\Windows\Start Menu Places\05 - Music.lnk"
del "C:\ProgramData\Microsoft\Windows\Start Menu Places\06 - Pictures.lnk"
del "C:\ProgramData\Microsoft\Windows\Start Menu Places\07 - Videos.lnk"

:skipstartmenuplaces



echo.
choice /c yn /t 3 /d n /m "Remove Libraries"
if ERRORLEVEL 2 goto skiplibraries
if ERRORLEVEL 1 goto libraries


:libraries
del "%userprofile%\AppData\Roaming\Microsoft\Windows\Libraries\Music.library-ms"
del "%userprofile%\AppData\Roaming\Microsoft\Windows\Libraries\Pictures.library-ms"
del "%userprofile%\AppData\Roaming\Microsoft\Windows\Libraries\Videos.library-ms"
 

reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UsersLibraries" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{59BD6DD1-5CEC-4d7e-9AD2-ECC64154418D}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{C4D98F09-6124-4fe0-9942-826416082DA9}" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{59BD6DD1-5CEC-4d7e-9AD2-ECC64154418D}" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{C4D98F09-6124-4fe0-9942-826416082DA9}" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\UsersLibraries" /f
reg delete "HKCU\SOFTWARE\Classes\Local Settings\MuiCache\1\52C64B7E" /v "@C:\Windows\system32\windows.storage.dll,-50691" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\SettingSync\WindowsSettingHandlers\UserLibraries" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\SettingSync\WindowsSettingHandlers\UserLibraries" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\SettingSync\WindowsSettingHandlers\UserLibraries" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\SettingSync\Namespace\Windows\UserLibraries" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\SettingSync\Namespace\Windows\UserLibraries" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\SettingSync\Namespace\Windows\UserLibraries" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.NavPaneShowLibraries" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.NavPaneShowLibraries" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.NavPaneShowLibraries" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Namespace\Windows\UserLibraries" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Namespace\Windows\UserLibraries" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Namespace\Windows\UserLibraries" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\WindowsSettingHandlers\UserLibraries" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\WindowsSettingHandlers\UserLibraries" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\WindowsSettingHandlers\UserLibraries" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.NavPaneShowLibraries" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.NavPaneShowLibraries" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.NavPaneShowLibraries" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{c51b83e5-9edd-4250-b45a-da672ee3c70e}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{c51b83e5-9edd-4250-b45a-da672ee3c70e}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{c51b83e5-9edd-4250-b45a-da672ee3c70e}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{c51b83e5-9edd-4250-b45a-da672ee3c70e}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{c51b83e5-9edd-4250-b45a-da672ee3c70e}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{c51b83e5-9edd-4250-b45a-da672ee3c70e}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{e9711a2f-350f-4ec1-8ebd-21245a8b9376}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{e9711a2f-350f-4ec1-8ebd-21245a8b9376}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{e9711a2f-350f-4ec1-8ebd-21245a8b9376}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{1CF324EC-F905-4c69-851A-DDC8795F71F2}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{1CF324EC-F905-4c69-851A-DDC8795F71F2}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{1CF324EC-F905-4c69-851A-DDC8795F71F2}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{1CF324EC-F905-4c69-851A-DDC8795F71F2}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{1CF324EC-F905-4c69-851A-DDC8795F71F2}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{1CF324EC-F905-4c69-851A-DDC8795F71F2}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{51F649D3-4BFF-42f6-A253-6D878BE1651D}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{51F649D3-4BFF-42f6-A253-6D878BE1651D}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{51F649D3-4BFF-42f6-A253-6D878BE1651D}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{51F649D3-4BFF-42f6-A253-6D878BE1651D}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{51F649D3-4BFF-42f6-A253-6D878BE1651D}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{51F649D3-4BFF-42f6-A253-6D878BE1651D}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{896664F7-12E1-490f-8782-C0835AFD98FC}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{896664F7-12E1-490f-8782-C0835AFD98FC}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{896664F7-12E1-490f-8782-C0835AFD98FC}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{896664F7-12E1-490f-8782-C0835AFD98FC}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{896664F7-12E1-490f-8782-C0835AFD98FC}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{896664F7-12E1-490f-8782-C0835AFD98FC}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" /f


reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\NavPane\ShowLibraries" /f

reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Music" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Music" /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Music" /f
reg delete "HKEY_CLASSES_ROOT\SystemFileAssociations\MyMusic" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "CommonMusic" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Music" /f
reg delete "HKEY_USERS\S-1-5-19\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Music" /f
reg delete "HKEY_USERS\S-1-5-20\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Music" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "CommonMusic" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "CommonMusic" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "CommonMusic" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{3f2a72a7-99fa-4ddb-a5a8-c604edf61d6b}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" /f
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f


%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" /f


%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" /f


%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f


%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f

 
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Pictures" /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Pictures" /f
reg delete "HKEY_CLASSES_ROOT\SystemFileAssociations\MyPictures" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Pictures" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Pictures" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Classes\Local Settings\MuiCache\1\52C64B7E" /v "@C:\Windows\System32\Windows.UI.Immersive.dll,-38304" /f
reg delete "HKEY_USERS\S-1-5-19\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Pictures" /f
reg delete "HKEY_USERS\S-1-5-20\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Pictures" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "CommonPictures" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{0b2baaeb-0042-4dca-aa4d-3ee8648d03e5}" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\StartMenu\StartPanel\PinnedItems\Pictures" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "CommonPictures" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{b3690e58-e961-423b-b687-386ebfd83239}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{b3690e58-e961-423b-b687-386ebfd83239}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{b3690e58-e961-423b-b687-386ebfd83239}" /f

reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{c1f8339f-f312-4c97-b1c6-ecdf5910c5c0}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{0b2baaeb-0042-4dca-aa4d-3ee8648d03e5}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{4dcafe13-e6a7-4c28-be02-ca8c2126280d}" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{b3690e58-e961-423b-b687-386ebfd83239}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{b3690e58-e961-423b-b687-386ebfd83239}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{b3690e58-e961-423b-b687-386ebfd83239}" /f

reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{c1f8339f-f312-4c97-b1c6-ecdf5910c5c0}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "CommonPictures" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "CommonPictures" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Classes\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Classes\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Wow6432Node\Classes\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Classes\CLSID\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Classes\CLSID\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Wow6432Node\Classes\CLSID\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA" /f


%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA" /f


%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" /f


%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" /f


 

reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Video" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "CommonVideo" /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Video" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Video" /f
reg delete "HKEY_CLASSES_ROOT\SystemFileAssociations\MyVideo" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "CommonVideo" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Video" /f
reg delete "HKEY_USERS\S-1-5-19\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Video" /f
reg delete "HKEY_USERS\S-1-5-20\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Video" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "CommonVideo" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{51294DA1-D7B1-485b-9E9A-17CFFE33E187}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{ea25fbd7-3bf7-409e-b97f-3352240903f4}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{292108be-88ab-4f33-9a26-7748e62e37ad}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{5fa96407-7e77-483c-ac93-691d05850de8}" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "CommonVideo" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{51294DA1-D7B1-485b-9E9A-17CFFE33E187}" /f



%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" /f


%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" /f


%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" /f


%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" /f

reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Accents\0\Theme0" /v "Color" /t REG_DWORD /d "9538419" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Accents\0\Theme1" /v "Color" /t REG_DWORD /d "10915422" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Accents\1\Theme0" /v "Color" /t REG_DWORD /d "10766359" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Accents\1\Theme1" /v "Color" /t REG_DWORD /d "10766359" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Accents\2\Theme0" /v "Color" /t REG_DWORD /d "6392360" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Accents\2\Theme1" /v "Color" /t REG_DWORD /d "12235947" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Accents\3\Theme0" /v "Color" /t REG_DWORD /d "8764727" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Accents\3\Theme1" /v "Color" /t REG_DWORD /d "8764727" /f

reg delete "HKLM\SOFTWARE\Microsoft\DiskSnapshot\v2\0\.?users?*?music*" /f
reg delete "HKLM\SOFTWARE\Microsoft\DiskSnapshot\v2\0\.?users?*?onedrive*" /f
reg delete "HKLM\SOFTWARE\Microsoft\DiskSnapshot\v2\0\.?users?*?pictures*" /f
reg delete "HKLM\SOFTWARE\Microsoft\DiskSnapshot\v2\0\.?users?*?videos*" /f

reg delete "HKCU\SOFTWARE\Classes\Local Settings\MuiCache\1\52C64B7E" /v "@windows.storage.dll,-21790" /f
reg delete "HKCU\SOFTWARE\Classes\Local Settings\MuiCache\1\52C64B7E" /v "@windows.storage.dll,-34584" /f
reg delete "HKCU\SOFTWARE\Classes\Local Settings\MuiCache\1\52C64B7E" /v "@windows.storage.dll,-34595" /f
reg delete "HKCU\SOFTWARE\Classes\Local Settings\MuiCache\1\52C64B7E" /v "@windows.storage.dll,-34620" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Classes\Local Settings\MuiCache\1\52C64B7E" /v "@windows.storage.dll,-21790" /f

:skiplibraries



echo.
choice /c yn /t 3 /d y /m "Enable verbose status messages when you sign out of Windows"
if ERRORLEVEL 2 goto skipverbose
if ERRORLEVEL 1 goto verbose


:verbose
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "VerboseStatus" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\System" /v "VerboseStatus" /t REG_DWORD /d 1 /f
:skipverbose



echo.
choice /c yn /t 3 /d y /m "Re-enable automatic registry backups"
if ERRORLEVEL 2 goto skipregback
if ERRORLEVEL 1 goto regback


:regback
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager" /v "EnablePeriodicBackup" /t REG_DWORD /d 1 /f

:skipregback



echo.
choice /c yn /t 3 /d y /m "Disable fast startup for fewer errors while signing in"
if ERRORLEVEL 2 goto skipfstartup
if ERRORLEVEL 1 goto fstartup


:fstartup
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d 0 /f

:skipfstartup




echo.
choice /c yn /t 3 /d n /m "Remove OneDrive"
if ERRORLEVEL 2 goto skiponedrive
if ERRORLEVEL 1 goto onedrive


:onedrive
reg delete "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
reg delete "HKCU\SOFTWARE\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
reg delete "HKCU\SOFTWARE\Classes\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
reg delete "HKEY_USERS\.DEFAULT\SOFTWARE\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
reg delete "HKEY_USERS\.DEFAULT\SOFTWARE\Classes\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d 1 /f

:skiponedrive





REM *** Remove Logon screen wallpaper/background. Will use solid color instead (Accent color) ***
REM Changes in registry do not reflect back to GPEDIT.MSC. Better to do it directly through GPEDIT.MSC UI.
REM reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableLogonBackgroundImage" /t REG_DWORD /d 1 /f

REM *** Always show all icons on the taskbar (next to clock) ***
REM 0 = Show all icons
REM 1 = Hide icons on the taskbar
REM reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "EnableAutoTray" /t REG_DWORD /d 0 /f


echo.
choice /c yn /t 3 /d y /m "Show Hidden files with Explorer"
if ERRORLEVEL 2 goto skiphidden
if ERRORLEVEL 1 goto hidden


:hidden
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f

:skiphidden



echo.
choice /c yn /t 3 /d n /m "Show Super Hidden System files with Explorer"
if ERRORLEVEL 2 goto skipsuperhidden
if ERRORLEVEL 1 goto superhidden


:superhidden
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d 1 /f

:skipsuperhidden



echo.
choice /c yn /t 3 /d y /m "Show known file extensions with Explorer"
if ERRORLEVEL 2 goto skipfileext
if ERRORLEVEL 1 goto fileext


:fileext
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t  REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t  REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t  REG_DWORD /d 0 /f
 
:skipfileext



echo.
choice /c yn /t 3 /d n /m "Show super hidden file extensions with Explorer"
if ERRORLEVEL 2 goto skipsuperfileext
if ERRORLEVEL 1 goto superfileext


:superfileext
reg delete "HKEY_CLASSES_ROOT\lnkfile" /v "NeverShowExt" /f
reg delete "HKEY_CLASSES_ROOT\IE.AssocFile.URL" /v "NeverShowExt" /f
reg delete "HKEY_CLASSES_ROOT\IE.AssocFile.WEBSITE" /v "NeverShowExt" /f
reg delete "HKEY_CLASSES_ROOT\InternetShortcut" /v "NeverShowExt" /f
reg delete "HKEY_CLASSES_ROOT\Microsoft.Website" /v "NeverShowExt" /f
reg delete "HKEY_CLASSES_ROOT\piffile" /v "NeverShowExt" /f
reg delete "HKEY_CLASSES_ROOT\SHCmdFile" /v "NeverShowExt" /f
reg delete "HKEY_CLASSES_ROOT\LibraryFolder" /v "NeverShowExt" /f

:skipsuperfileext


echo.
choice /c yn /t 3 /d y /m "Make the Explorer a bit more colourful (compressed files)"
if ERRORLEVEL 2 goto skipcompressed
if ERRORLEVEL 1 goto compressed


:compressed
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCompColor" /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCompColor" /t REG_DWORD /d 1 /f
:skipcompressed





echo.
choice /c yn /t 3 /d y /m "Disable WiFi Sense"
if ERRORLEVEL 2 goto skipwifisense
if ERRORLEVEL 1 goto wifisense


:wifisense
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v "value" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v "value" /t REG_DWORD /d 0 /f

:skipwifisense



echo. 
choice /c yn /t 3 /d y /m "Turn off those annoying Windows Firewall notifications"
if ERRORLEVEL 2 goto skipfw
if ERRORLEVEL 1 goto fw


:fw
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableEnhancedNotifications" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableNotifications" /t REG_DWORD /d 1 /f

:skipfw



echo.
choice /c yn /t 3 /d y /m "Disable some tracking services"
if ERRORLEVEL 2 goto skipsc
if ERRORLEVEL 1 goto sc


:sc
sc stop diagtrack
echo DiagTrack stopped.
sc config DiagTrack start= disabled
echo DiagTrack disabled.

sc stop diagnosticshub.standardcollector.service
echo standardcollectorstopped.
sc config diagnosticshub.standardcollector.service start= disabled
echo standardcollector disabled.

sc stop dmwappushservice
echo dmwappushservice stopped.
sc config dmwappushservice start= disabled
echo dmwappushservice disabled.

REM sc stop RemoteRegistry
REM echo RemoteRegistry stopped.
REM sc config RemoteRegistry start= disabled

sc stop TrkWks
echo TrkWks stopped.
sc config TrkWks start= disabled
echo TrkWks disabled.

sc stop WMPNetworkSvc
echo WMPNetworkSvc stopped.
sc config WMPNetworkSvc start= disabled
echo WMPNetworkSvc disabled.

sc stop WSearch
echo WSearch stopped.
sc config WSearch start= demand
echo WSearch on demand.

sc stop BcastDVRUserService_c387c3f
echo BcastDVRUserService_c387c3f stopped.
sc config BcastDVRUserService_c387c3f start= disabled
echo BcastDVRUserService_c387c3f disabled.

sc stop BcastDVRUserService_c4ce224
echo BcastDVRUserService_c4ce224 stopped.
sc config BcastDVRUserService_c4ce224 start= disabled
echo BcastDVRUserService_c4ce224 disabled.


sc stop XblAuthManager
echo XblAuthManager stopped.
sc config XblAuthManager start= disabled
echo XblAuthManager disabled.

sc stop XblGameSave
echo XblGameSave stopped.
sc config XblGameSave start= disabled
echo XblGameSave disabled.

sc stop XboxNetApiSvc
echo XboxNetApiSvc stopped.
sc config XboxNetApiSvc start= disabled
echo XboxNetApiSvc disabled.

sc stop XboxGipSvc
echo XboxGipSvc stopped.
sc config XboxGipSvc start= disabled
echo XboxGipSvc disabled.

REM sc stop xbgm
REM echo xbgm stopped.
REM sc config xbgm start= disabled
REM echo xbgm disabled.
:skipsc



echo.
choice /c yn /t 3 /d y /m "Disable Superfetch"
if ERRORLEVEL 2 goto skipsuperfetch
if ERRORLEVEL 1 goto superfetch


:superfetch
sc config SysMain start= disabled
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d 0 /f

:skipsuperfetch



echo.
choice /c yn /t 3 /d y /m "Disable some scheduled tasks tracking"
if ERRORLEVEL 2 goto skipschedtasks
if ERRORLEVEL 1 goto schedtasks


:schedtasks
REM schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /Disable
REM echo AppID\SmartScreenSpecific disabled.
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
echo Microsoft Compatibility Appraiser disabled.
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
echo Application Experience\ProgramDataUpdater disabled.
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable
echo Application Experience\StartupAppTask" disabled.
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable
echo Autochk\Proxy disabled.
REM schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
echo Customer Experience Improvement Program\Consolidator disabled.
REM schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable
REM echo Customer Experience Improvement Program\KernelCeipTask disabled.
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
echo Customer Experience Improvement Program\UsbCeip disabled.
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
echo Microsoft-Windows-DiskDiagnosticDataCollector disabled.
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable
echo File History (maintenance mode) disabled.
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Disable
echo WinSAT disabled.
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable
echo GatherNetworkInfo disabled.
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable
echo PI\Sqm-Tasks disabled.
schtasks /Change /TN "Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /Disable
echo ForceSynchronizeTime disabled.
REM schtasks /Change /TN "Microsoft\Windows\Time Synchronization\SynchronizeTime" /Disable
REM echo SynchronizeTime disabled.
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable
echo QueueReporting disabled.
REM schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Automatic App Update" /Disable
REM echo Automatic App Update disabled.
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /Disable
echo Siuf disabled.
:skipschedtasks




echo.
choice /c yn /t 3 /d y /m "Add the option Processor performance core parking min cores"
if ERRORLEVEL 2 goto skipprocessor
if ERRORLEVEL 1 goto processor


:processor
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "Attributes" /t REG_DWORD /d 0 /f

:skipprocessor



echo.
choice /c yn /t 3 /d n /m "Disable CPU Core Parking"
if ERRORLEVEL 2 goto skipparking
if ERRORLEVEL 1 goto parking


:parking
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d 0 /f

:skipparking



echo.
choice /c yn /t 3 /d y /m "Remove the DiagTrack package using DISM"
if ERRORLEVEL 2 goto skipdiagtrack
if ERRORLEVEL 1 goto diagtrack


:diagtrack
REM dism /online /remove-package /packagename:Microsoft-Windows-DiagTrack-Internal-Package~31bf3856ad364e35~amd64~~10.0.10240.16384 /NoRestart
call C:\Windows\Temp\KillDiagTrack.exe Microsoft-Windows-DiagTrack
:skipdiagtrack



echo.
choice /c yn /t 3 /d y /m "Remove already installed Apps"
if ERRORLEVEL 2 goto skipapps
if ERRORLEVEL 1 goto apps


:apps
call C:\Windows\Temp\AppUninstaller.exe

echo.
echo Waiting for some background services to stop...
echo.
timeout 100 /nobreak
echo.
echo.
:skipapps




echo.
choice /c yn /t 3 /d y /m "Disable preinstalled Apps"
if ERRORLEVEL 2 goto skipdisableapps
if ERRORLEVEL 1 goto disableapps


:disableapps
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f
REM reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f
:skipdisableapps



goto ending













:manual_11
set ANSWER=y
set /p ANSWER= Disable creation of an Advertising ID? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipadid

reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f

:skipadid


set ANSWER=y
set /p ANSWER= Disable Problem Step Recorder? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipuar

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f
:skipuar



set ANSWER=y
set /p ANSWER= Prevent Windows Media DRM from connecting to the Internet? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipdrm

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\WMDRM" /v "DisableOnline" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WMDRM" /v "DisableOnline" /t REG_DWORD /d 1 /f
:skipdrm



set ANSWER=y
set /p ANSWER= Keep Edge away from doing Stuff on it's own? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipedge

reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ExcludedFromStableAnaheimDownloadPromotionSL" /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ExcludedFromStableAnaheimDownloadPromotionSL" /t REG_DWORD /d 1 /f
:skipedge




echo.
set ANSWER=y
set /p ANSWER= Disable synchronisation of user settings? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipusersets

reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d 5 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d 0 /f

reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d 5 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d 0 /f

:skipusersets


echo.
set ANSWER=y
set /p ANSWER= Don't allow Windows Defender to submit samples to MAPS (formerly SpyNet)? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipwindef

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet" /v "SpyNetReporting" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender\Spynet" /v "SpyNetReporting" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d 2 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d 1 /f

:skipwindef



echo.
set ANSWER=y
set /p ANSWER=  ***FOR SPECIAL USERS*** Add "Reboot to Recovery" to right-click menu of "This PC"? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipreboottorecovery

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg add "HKEY_CLASSES_ROOT\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell\Reboot to Recovery" /v "Icon" /t REG_SZ /d %SystemRoot%\System32\imageres.dll,-110" /f
reg add "HKEY_CLASSES_ROOT\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell\Reboot to Recovery\command" /ve /d "shutdown.exe -r -o -f -t 00" /f

:skipreboottorecovery



echo.
set ANSWER=y
set /p ANSWER=  Disable Cortana? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipcortana

REM HIER GUCKEN
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f


REM HIER GUCKEN
REM reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!dss-winrt-telemetry.js" /t REG_DWORD /d 0 /f
REM reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry.js" /t REG_DWORD /d 0 /f
REM reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry-event_8ac43a41e5030538" /t REG_DWORD /d 0 /f
REM reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry-inter_58073761d33f144b" /t REG_DWORD /d 0 /f

reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f 
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f 
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f 
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f 
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f 
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f 
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f 
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f 

:skipcortana





echo.
set ANSWER=y
set /p ANSWER=  Remove telemetry from search? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipsearchtel


reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d 1 /f

:skipsearchtel




echo.
set ANSWER=y
set /p ANSWER=  Remove more telemetry? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skiptel

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d 1 /f


:skiptel



echo.
set ANSWER=y
set /p ANSWER=  Remove even more telemetry? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipmoretel

reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d 0 /f

:skipmoretel




echo.
set ANSWER=y
set /p ANSWER=  Disable location? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skiploc

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d 1 /f
:skiploc



echo.
set ANSWER=y
set /p ANSWER= Remove sharing and improving detection of handwriting? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skiphand

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v  "PreventHandwritingErrorReports" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\HandwritingErrorReports" /v  "PreventHandwritingErrorReports" /t REG_DWORD /d 1 /f	
reg add "HKEY_CURRENT_USER\Software\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d 0 /f			
:skiphand



echo.
set ANSWER=y
set /p ANSWER=  Disable MRU (jump lists) lists? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipmru

REM TESTEN*** Disable MRU lists (jump lists) of XAML apps in Start Menu ***
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d 0 /f

:skipmru



echo.
set ANSWER=y
set /p ANSWER= Set Windows Explorer to start on This PC instead of Quick Access? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipexp

reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d 1 /f

:skipexp



echo.
set ANSWER=y
set /p ANSWER= Create Desktop Shortcuts? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipshorts

REM Computer
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0 /f 
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0 /f 
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0 /f 
REM Network 
REM reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" /t REG_DWORD /d 0 /f 
REM User's folder
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{450D8FBA-AD25-11D0-98A8-0800361B1103}" /t REG_DWORD /d 0 /f 
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{450D8FBA-AD25-11D0-98A8-0800361B1103}" /t REG_DWORD /d 0 /f 
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{450D8FBA-AD25-11D0-98A8-0800361B1103}" /t REG_DWORD /d 0 /f 

:skipshorts



echo.
set ANSWER=n
set /p ANSWER= ***ADMIN ONLY*** Add "Take Ownership" on right-click menu of files and folders? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipownership

reg add "HKEY_CLASSES_ROOT\*\shell\runas" /ve /t REG_SZ /d "Take ownership" /f
reg add "HKEY_CLASSES_ROOT\*\shell\runas" /v "HasLUAShield" /t REG_SZ /d "" /f
reg add "HKEY_CLASSES_ROOT\*\shell\runas" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
reg add "HKEY_CLASSES_ROOT\*\shell\runas\command" /ve /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" /a && icacls \"%%1\" /grant Administrators:F" /f
reg add "HKEY_CLASSES_ROOT\*\shell\runas\command" /v "IsolatedCommand" /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" /a && icacls \"%%1\" /grant Administrators:F" /f
reg add "HKEY_CLASSES_ROOT\Directory\shell\runas" /ve /t REG_SZ /d "Take ownership" /f
reg add "HKEY_CLASSES_ROOT\Directory\shell\runas" /v "HasLUAShield" /t REG_SZ /d "" /f
reg add "HKEY_CLASSES_ROOT\Directory\shell\runas" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
reg add "HKEY_CLASSES_ROOT\Directory\shell\runas\command" /ve /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" /a /r /d y && icacls \"%%1\" /grant Administrators:F /t" /f
reg add "HKEY_CLASSES_ROOT\Directory\shell\runas\command" /v "IsolatedCommand" /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" /a /r /d y && icacls \"%%1\" /grant Administrators:F /t" /f

:skipownership



echo.
set ANSWER=y
set /p ANSWER= Turn OFF Sticky Keys when SHIFT is pressed 5 times? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipstickykeys

reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "506" /f
reg add "HKEY_USERS\.DEFAULT\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "506" /f

:skipstickykeys



echo.
set ANSWER=y
set /p ANSWER= Underline keyboard shortcuts and access keys? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipunderline

REM *** Underline keyboard shortcuts and access keys ***
reg add "HKCU\Control Panel\Accessibility\Keyboard Preference" /v "On" /t REG_SZ /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Control Panel\Accessibility\Keyboard Preference" /v "On" /t REG_SZ /d 1 /f

:skipunderline



echo.
set ANSWER=y
set /p ANSWER= Use Windows Photo Viewer to open *.tif files instead of Paint? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skippaint

reg add "HKCU\Software\Classes\.jpg" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKCU\Software\Classes\.jpeg" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKCU\Software\Classes\.gif" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKCU\Software\Classes\.png" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKCU\Software\Classes\.bmp" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKCU\Software\Classes\.tiff" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKCU\Software\Classes\.ico" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKEY_USERS\.DEFAULT\Software\Classes\.jpg" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKEY_USERS\.DEFAULT\Software\Classes\.jpeg" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKEY_USERS\.DEFAULT\Software\Classes\.gif" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKEY_USERS\.DEFAULT\Software\Classes\.png" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKEY_USERS\.DEFAULT\Software\Classes\.bmp" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKEY_USERS\.DEFAULT\Software\Classes\.tiff" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKEY_USERS\.DEFAULT\Software\Classes\.ico" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKCR\Applications\photoviewer.dll\shell\open" /v "MuiVerb" /t REG_SZ /d "@photoviewer.dll,-3043" /f
reg add "HKCR\Applications\photoviewer.dll\shell\open\command" /ve /t REG_EXPAND_SZ /d "%%SystemRoot%%\System32\rundll32.exe \"%%ProgramFiles%%\Windows Photo Viewer\PhotoViewer.dll\", ImageView_Fullscreen %%1" /f
reg add "HKCR\Applications\photoviewer.dll\shell\open\DropTarget" /v "Clsid" /t REG_SZ /d "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" /f
reg add "HKCR\Applications\photoviewer.dll\shell\print\command" /ve /t REG_EXPAND_SZ /d "%%SystemRoot%%\System32\rundll32.exe \"%%ProgramFiles%%\Windows Photo Viewer\PhotoViewer.dll\", ImageView_Fullscreen %%1" /f
reg add "HKCR\Applications\photoviewer.dll\shell\print\DropTarget" /v "Clsid" /t REG_SZ /d "{60fd46de-f830-4894-a628-6fa81bc0190d}" /f

:skippaint



echo.
set ANSWER=y
set /p ANSWER= Remove Music, Pictures and Videos from Start Menu places (remove liks only)? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipstartmenuplaces

del "C:\ProgramData\Microsoft\Windows\Start Menu Places\05 - Music.lnk"
del "C:\ProgramData\Microsoft\Windows\Start Menu Places\06 - Pictures.lnk"
del "C:\ProgramData\Microsoft\Windows\Start Menu Places\07 - Videos.lnk"

:skipstartmenuplaces



echo.
set ANSWER=n
set /p ANSWER= Remove Libraries and everything in there? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skiplibraries

del "%userprofile%\AppData\Roaming\Microsoft\Windows\Libraries\Music.library-ms"
del "%userprofile%\AppData\Roaming\Microsoft\Windows\Libraries\Pictures.library-ms"
del "%userprofile%\AppData\Roaming\Microsoft\Windows\Libraries\Videos.library-ms"
 

reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UsersLibraries" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{59BD6DD1-5CEC-4d7e-9AD2-ECC64154418D}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{C4D98F09-6124-4fe0-9942-826416082DA9}" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{59BD6DD1-5CEC-4d7e-9AD2-ECC64154418D}" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{C4D98F09-6124-4fe0-9942-826416082DA9}" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\UsersLibraries" /f
reg delete "HKCU\SOFTWARE\Classes\Local Settings\MuiCache\1\52C64B7E" /v "@C:\Windows\system32\windows.storage.dll,-50691" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\SettingSync\WindowsSettingHandlers\UserLibraries" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\SettingSync\WindowsSettingHandlers\UserLibraries" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\SettingSync\WindowsSettingHandlers\UserLibraries" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\SettingSync\Namespace\Windows\UserLibraries" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\SettingSync\Namespace\Windows\UserLibraries" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\SettingSync\Namespace\Windows\UserLibraries" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.NavPaneShowLibraries" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.NavPaneShowLibraries" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.NavPaneShowLibraries" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Namespace\Windows\UserLibraries" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Namespace\Windows\UserLibraries" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Namespace\Windows\UserLibraries" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\WindowsSettingHandlers\UserLibraries" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\WindowsSettingHandlers\UserLibraries" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\WindowsSettingHandlers\UserLibraries" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.NavPaneShowLibraries" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.NavPaneShowLibraries" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.NavPaneShowLibraries" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{c51b83e5-9edd-4250-b45a-da672ee3c70e}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{c51b83e5-9edd-4250-b45a-da672ee3c70e}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{c51b83e5-9edd-4250-b45a-da672ee3c70e}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{c51b83e5-9edd-4250-b45a-da672ee3c70e}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{c51b83e5-9edd-4250-b45a-da672ee3c70e}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{c51b83e5-9edd-4250-b45a-da672ee3c70e}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{e9711a2f-350f-4ec1-8ebd-21245a8b9376}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{e9711a2f-350f-4ec1-8ebd-21245a8b9376}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{e9711a2f-350f-4ec1-8ebd-21245a8b9376}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{1CF324EC-F905-4c69-851A-DDC8795F71F2}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{1CF324EC-F905-4c69-851A-DDC8795F71F2}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{1CF324EC-F905-4c69-851A-DDC8795F71F2}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{1CF324EC-F905-4c69-851A-DDC8795F71F2}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{1CF324EC-F905-4c69-851A-DDC8795F71F2}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{1CF324EC-F905-4c69-851A-DDC8795F71F2}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{51F649D3-4BFF-42f6-A253-6D878BE1651D}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{51F649D3-4BFF-42f6-A253-6D878BE1651D}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{51F649D3-4BFF-42f6-A253-6D878BE1651D}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{51F649D3-4BFF-42f6-A253-6D878BE1651D}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{51F649D3-4BFF-42f6-A253-6D878BE1651D}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{51F649D3-4BFF-42f6-A253-6D878BE1651D}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{896664F7-12E1-490f-8782-C0835AFD98FC}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{896664F7-12E1-490f-8782-C0835AFD98FC}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{896664F7-12E1-490f-8782-C0835AFD98FC}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{896664F7-12E1-490f-8782-C0835AFD98FC}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{896664F7-12E1-490f-8782-C0835AFD98FC}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{896664F7-12E1-490f-8782-C0835AFD98FC}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" /f


reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\NavPane\ShowLibraries" /f

reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Music" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Music" /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Music" /f
reg delete "HKEY_CLASSES_ROOT\SystemFileAssociations\MyMusic" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "CommonMusic" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Music" /f
reg delete "HKEY_USERS\S-1-5-19\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Music" /f
reg delete "HKEY_USERS\S-1-5-20\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Music" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "CommonMusic" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "CommonMusic" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "CommonMusic" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{3f2a72a7-99fa-4ddb-a5a8-c604edf61d6b}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" /f
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f

 
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Pictures" /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Pictures" /f
reg delete "HKEY_CLASSES_ROOT\SystemFileAssociations\MyPictures" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Pictures" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Pictures" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Classes\Local Settings\MuiCache\1\52C64B7E" /v "@C:\Windows\System32\Windows.UI.Immersive.dll,-38304" /f
reg delete "HKEY_USERS\S-1-5-19\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Pictures" /f
reg delete "HKEY_USERS\S-1-5-20\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Pictures" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "CommonPictures" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{0b2baaeb-0042-4dca-aa4d-3ee8648d03e5}" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\StartMenu\StartPanel\PinnedItems\Pictures" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "CommonPictures" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{b3690e58-e961-423b-b687-386ebfd83239}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{b3690e58-e961-423b-b687-386ebfd83239}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{b3690e58-e961-423b-b687-386ebfd83239}" /f

reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{c1f8339f-f312-4c97-b1c6-ecdf5910c5c0}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{0b2baaeb-0042-4dca-aa4d-3ee8648d03e5}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{4dcafe13-e6a7-4c28-be02-ca8c2126280d}" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{b3690e58-e961-423b-b687-386ebfd83239}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{b3690e58-e961-423b-b687-386ebfd83239}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{b3690e58-e961-423b-b687-386ebfd83239}" /f

reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{c1f8339f-f312-4c97-b1c6-ecdf5910c5c0}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "CommonPictures" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "CommonPictures" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Classes\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Classes\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Wow6432Node\Classes\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Classes\CLSID\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Classes\CLSID\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Wow6432Node\Classes\CLSID\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" /f
 

reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Video" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "CommonVideo" /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Video" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Video" /f
reg delete "HKEY_CLASSES_ROOT\SystemFileAssociations\MyVideo" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "CommonVideo" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Video" /f
reg delete "HKEY_USERS\S-1-5-19\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Video" /f
reg delete "HKEY_USERS\S-1-5-20\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Video" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "CommonVideo" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{51294DA1-D7B1-485b-9E9A-17CFFE33E187}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{ea25fbd7-3bf7-409e-b97f-3352240903f4}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{292108be-88ab-4f33-9a26-7748e62e37ad}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{5fa96407-7e77-483c-ac93-691d05850de8}" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "CommonVideo" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{51294DA1-D7B1-485b-9E9A-17CFFE33E187}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" /f


reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Accents\0\Theme0" /v "Color" /t REG_DWORD /d "9538419" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Accents\0\Theme1" /v "Color" /t REG_DWORD /d "10915422" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Accents\1\Theme0" /v "Color" /t REG_DWORD /d "10766359" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Accents\1\Theme1" /v "Color" /t REG_DWORD /d "10766359" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Accents\2\Theme0" /v "Color" /t REG_DWORD /d "6392360" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Accents\2\Theme1" /v "Color" /t REG_DWORD /d "12235947" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Accents\3\Theme0" /v "Color" /t REG_DWORD /d "8764727" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Accents\3\Theme1" /v "Color" /t REG_DWORD /d "8764727" /f

reg delete "HKLM\SOFTWARE\Microsoft\DiskSnapshot\v2\0\.?users?*?music*" /f
reg delete "HKLM\SOFTWARE\Microsoft\DiskSnapshot\v2\0\.?users?*?onedrive*" /f
reg delete "HKLM\SOFTWARE\Microsoft\DiskSnapshot\v2\0\.?users?*?pictures*" /f
reg delete "HKLM\SOFTWARE\Microsoft\DiskSnapshot\v2\0\.?users?*?videos*" /f

reg delete "HKCU\SOFTWARE\Classes\Local Settings\MuiCache\1\52C64B7E" /v "@windows.storage.dll,-21790" /f
reg delete "HKCU\SOFTWARE\Classes\Local Settings\MuiCache\1\52C64B7E" /v "@windows.storage.dll,-34584" /f
reg delete "HKCU\SOFTWARE\Classes\Local Settings\MuiCache\1\52C64B7E" /v "@windows.storage.dll,-34595" /f
reg delete "HKCU\SOFTWARE\Classes\Local Settings\MuiCache\1\52C64B7E" /v "@windows.storage.dll,-34620" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Classes\Local Settings\MuiCache\1\52C64B7E" /v "@windows.storage.dll,-21790" /f

:skiplibraries



echo.
set ANSWER=y
set /p ANSWER= Enable verbose status messages when you sign in/out of Windows? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipverbose

reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "VerboseStatus" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\System" /v "VerboseStatus" /t REG_DWORD /d 1 /f
:skipverbose


echo.
set ANSWER=y
set /p ANSWER= Re-enable automatic registry backups? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipregback

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager" /v "EnablePeriodicBackup" /t REG_DWORD /d 1 /f

:skipregback



echo.
set ANSWER=y
set /p ANSWER= Disable fast startup for fewer errors while signing in? (y/n) [%ANSWER%]: 
echo. 
if %answer%==n goto skipfstartup

reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d 0 /f

:skipfstartup


echo.
set ANSWER=n
set /p ANSWER= Remove OneDrive? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skiponedrive

reg delete "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
reg delete "HKCU\SOFTWARE\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
reg delete "HKCU\SOFTWARE\Classes\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
reg delete "HKEY_USERS\.DEFAULT\SOFTWARE\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
reg delete "HKEY_USERS\.DEFAULT\SOFTWARE\Classes\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d 1 /f
:skiponedrive





REM *** Remove Logon screen wallpaper/background. Will use solid color instead (Accent color) ***
REM Changes in registry do not reflect back to GPEDIT.MSC. Better to do it directly through GPEDIT.MSC UI.
REM reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableLogonBackgroundImage" /t REG_DWORD /d 1 /f

REM *** Always show all icons on the taskbar (next to clock) ***
REM 0 = Show all icons
REM 1 = Hide icons on the taskbar
REM reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "EnableAutoTray" /t REG_DWORD /d 0 /f


echo.
set ANSWER=y
set /p ANSWER= ***FOR EXPERIENCED USERS*** Show Hidden files in Explorer? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skiphidden

reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f

:skiphidden



echo.
set ANSWER=n
set /p ANSWER= ***ADMIN ONLY*** Show Super Hidden System files in Explorer? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipsuperhidden

reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d 1 /f

:skipsuperhidden



echo.
set ANSWER=y
set /p ANSWER= Show known file extensions in Explorer (n is not an option!;)? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipfileext

reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t  REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t  REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t  REG_DWORD /d 0 /f
 
:skipfileext


echo.
set ANSWER=n
set /p ANSWER= ***ADMIN ONLY*** Show super-duper hidden extensions? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipsuperfileext

reg delete "HKEY_CLASSES_ROOT\lnkfile" /v "NeverShowExt" /f
reg delete "HKEY_CLASSES_ROOT\IE.AssocFile.URL" /v "NeverShowExt" /f
reg delete "HKEY_CLASSES_ROOT\IE.AssocFile.WEBSITE" /v "NeverShowExt" /f
reg delete "HKEY_CLASSES_ROOT\InternetShortcut" /v "NeverShowExt" /f
reg delete "HKEY_CLASSES_ROOT\Microsoft.Website" /v "NeverShowExt" /f
reg delete "HKEY_CLASSES_ROOT\piffile" /v "NeverShowExt" /f
reg delete "HKEY_CLASSES_ROOT\SHCmdFile" /v "NeverShowExt" /f
reg delete "HKEY_CLASSES_ROOT\LibraryFolder" /v "NeverShowExt" /f

:skipsuperfileext


echo.
set ANSWER=y
set /p ANSWER= Make the Explorer a bit more colourful (compressed files)? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipcompressed

reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCompColor" /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCompColor" /t REG_DWORD /d 1 /f

:skipcompressed




echo.
set ANSWER=y
set /p ANSWER= Disable WiFi Sense? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipwifisense

reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v "value" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v "value" /t REG_DWORD /d 0 /f

:skipwifisense



echo. 
set ANSWER=y
set /p ANSWER= Turn off those annoying Windows Firewall notifications? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipfw

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableEnhancedNotifications" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableNotifications" /t REG_DWORD /d 1 /f

:skipfw



echo.
set ANSWER=y
set /p ANSWER= Disable some tracking services? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipsc

sc stop diagtrack
echo DiagTrack stopped.
sc config DiagTrack start= disabled
echo DiagTrack disabled.

sc stop diagnosticshub.standardcollector.service
echo standardcollectorstopped.
sc config diagnosticshub.standardcollector.service start= disabled
echo standardcollector disabled.

sc stop dmwappushservice
echo dmwappushservice stopped.
sc config dmwappushservice start= disabled
echo dmwappushservice disabled.

REM sc stop RemoteRegistry
REM echo RemoteRegistry stopped.
REM sc config RemoteRegistry start= disabled

sc stop TrkWks
echo TrkWks stopped.
sc config TrkWks start= disabled
echo TrkWks disabled.

sc stop WMPNetworkSvc
echo WMPNetworkSvc stopped.
sc config WMPNetworkSvc start= disabled
echo WMPNetworkSvc disabled.

sc stop WSearch
echo WSearch stopped.
sc config WSearch start= demand
echo WSearch on demand.

sc stop BcastDVRUserService_c387c3f
echo BcastDVRUserService_c387c3f stopped.
sc config BcastDVRUserService_c387c3f start= disabled
echo BcastDVRUserService_c387c3f disabled.

sc stop BcastDVRUserService_c4ce224
echo BcastDVRUserService_c4ce224 stopped.
sc config BcastDVRUserService_c4ce224 start= disabled
echo BcastDVRUserService_c4ce224 disabled.

sc stop XblAuthManager
echo XblAuthManager stopped.
sc config XblAuthManager start= disabled
echo XblAuthManager disabled.

sc stop XblGameSave
echo XblGameSave stopped.
sc config XblGameSave start= disabled
echo XblGameSave disabled.

sc stop XboxNetApiSvc
echo XboxNetApiSvc stopped.
sc config XboxNetApiSvc start= disabled
echo XboxNetApiSvc disabled.

sc stop XboxGipSvc
echo XboxGipSvc stopped.
sc config XboxGipSvc start= disabled
echo XboxGipSvc disabled.

REM sc stop xbgm
REM echo xbgm stopped.
REM sc config xbgm start= disabled
REM echo xbgm disabled.

:skipsc



echo.
set ANSWER=y
set /p ANSWER= Disable Superfetch? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipsuperfetch

sc config SysMain start= disabled
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d 0 /f

:skipsuperfetch



echo.
set ANSWER=y
set /p ANSWER= Disable some scheduled tasks tracking? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipschedtasks

REM schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /Disable
REM echo AppID\SmartScreenSpecific disabled.
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
echo Microsoft Compatibility Appraiser disabled.
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
echo Application Experience\ProgramDataUpdater disabled.
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable
echo Application Experience\StartupAppTask" disabled.
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable
echo Autochk\Proxy disabled.
REM schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
echo Customer Experience Improvement Program\Consolidator disabled.
REM schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable
REM echo Customer Experience Improvement Program\KernelCeipTask disabled.
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
echo Customer Experience Improvement Program\UsbCeip disabled.
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
echo Microsoft-Windows-DiskDiagnosticDataCollector disabled.
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable
echo File History (maintenance mode) disabled.
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Disable
echo WinSAT disabled.
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable
echo GatherNetworkInfo disabled.
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable
echo PI\Sqm-Tasks disabled.
schtasks /Change /TN "Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /Disable
echo ForceSynchronizeTime disabled.
REM schtasks /Change /TN "Microsoft\Windows\Time Synchronization\SynchronizeTime" /Disable
REM echo SynchronizeTime disabled.
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable
echo QueueReporting disabled.
REM schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Automatic App Update" /Disable
REM echo Automatic App Update disabled.
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /Disable
echo Siuf disabled.
:skipschedtasks




REM *** Disable the stubborn scheduled tasks "BackgroundUploadTask" & "Metadata Refresh" ***
REM "BackgroundUploadTask" is located in "Task Scheduler Library\Microsoft\Windows\SettingSync".
REM "Metadata Refresh" is located in "Task Scheduler Library\Microsoft\Windows\Device Setup".
REM These tasks are enabled by default (status Ready), and cannot be disabled by any regular means.
REM A single bit in the registry keys is responsible for enabling/disabling these tasks.
REM Go to: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks
REM Search for "BackgroundUploadTask" in this location, and note the task's ID.
REM 1st we need to take ownership. In the following commands, replace XXX with the task's ID, and run them in CMD:
REM %SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{XXXXXXXX-XXX-XXXX-XXXX-XXXXXXXXXXXX}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
REM %SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{XXXXXXXX-XXX-XXXX-XXXX-XXXXXXXXXXXX}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
REM Now we can edit the contents of the key.
REM Within this key, there is a binary value named "Triggers", which contains a series of bits.
REM Open it and make sure the format is set to "byte".
REM Go to the 6th row, 3rd column, and change (double-click on) it from "C0" to "00". Press OK and you're done.
REM Do all the steps above for the "Metadata Refresh" task.


echo.
set ANSWER=y
set /p ANSWER= Add the option "Processor performance core parking min cores"? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipprocessor

reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "Attributes" /t REG_DWORD /d 0 /f

:skipprocessor



echo.
set ANSWER=n
set /p ANSWER= Disable CPU Core Parking (should not be done on laptops)? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipparking

reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d 0 /f

:skipparking



echo.
set ANSWER=y
set /p ANSWER= Remove the DiagTrack package using DISM? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipdiagtrack

call C:\Windows\Temp\KillDiagTrack.exe Microsoft-Windows-DiagTrack
 
:skipdiagtrack



echo.
set ANSWER=y
set /p ANSWER= Remove already installed Apps? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipapps

call C:\Windows\Temp\AppUninstaller.exe


:skipapps

echo.
echo Waiting for some background services to stop...
echo.
timeout 100 /nobreak
echo.
echo.



echo.
set ANSWER=y
set /p ANSWER= Disable preinstalled Apps? (y/n) [%ANSWER%]:
echo. 
if %answer%==n goto skipdisableapps


reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f
REM reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f
:skipdisableapps



goto ending














:ending
echo.
set ANSWER=y
set /p ANSWER=Final system setup restart :)? (y/n) [%ANSWER%]:
echo.

if %answer%==n goto skiprestart
shutdown -r -t 3

:skiprestart

:: ---# Registry Modification
:: ---------------------------

REG DELETE HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v MotherOfAllTweaks /f

:: ---# Final cleaning...
:: --------------------

REG DELETE HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v Setup_Part3 /f

REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /d "0" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName /d "" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword /d "" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName /d "INTERSHOPNET" /f

rd  %windir%\Temp\setACL /S /Q
del %windir%\Temp\third_setup.bat /S /Q /F
del %windir%\Temp\AppUninstaller.exe /S /Q /F
REM del %windir%\Temp\MotherOfAllTweaks.bat /S /Q /F

del %windir%\Temp\* /S /Q /F

echo ---# Done.
echo.
echo.











REM UPDATES


REM Dism /online /Cleanup-Image /StartComponentCleanup /ResetBase

REM DISK CLEANUP


REM IMAGEN

REM FERTIG.