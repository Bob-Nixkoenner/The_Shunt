; Inno Setup script for The Shunt. Built by build.sh (ISCC) from the folder with the built files.
;   iscc /DAppVersion=0.7.0 /DSrcDir=<dir with exes> /DOutDir=<dist> the-shunt.iss
#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef SrcDir
  #define SrcDir "."
#endif
#ifndef OutDir
  #define OutDir "."
#endif

[Setup]
AppId={{6E1F2A64-5B0C-4C4A-9B7E-7448B1E0A3D1}
AppName=The Shunt
AppVersion={#AppVersion}
AppPublisher=The Shunt
DefaultDirName={autopf}\The Shunt
DefaultGroupName=The Shunt
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#OutDir}
OutputBaseFilename=the-shunt-setup
SetupIconFile={#SrcDir}\the-shunt.ico
UninstallDisplayIcon={app}\the-shunt.ico
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
CloseApplications=no
; the language of Windows if the setup has it (German), else English; no question
ShowLanguageDialog=no
LanguageDetectionMethod=uilanguage

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"; InfoBeforeFile: "{#SrcDir}\disclaimer.txt"
Name: "german"; MessagesFile: "compiler:Languages\German.isl"; InfoBeforeFile: "{#SrcDir}\disclaimer-de.txt"

; The texts of this script. Another language: a [Languages] line above with its
; MessagesFile, a disclaimer-<code>.txt next to disclaimer.txt, one line per message here.
; This file has a UTF-8 byte order mark: Inno reads it as UTF-8 then.
[CustomMessages]
english.DesktopIcon=Create a desktop icon
english.Autostart=Start the tray icon at login
english.Comment=The Shunt - per-app split tunneling
english.InstallingService=Installing service...
english.StartingService=Starting service...
english.StartShunt=Start The Shunt
english.DeleteData=Also delete the configuration, tunnels and statistics (C:\ProgramData\Shunt)?
german.DesktopIcon=Ein Desktop-Symbol erstellen
german.Autostart=Das Tray-Symbol beim Login starten
german.Comment=The Shunt - Split-Tunneling pro App
german.InstallingService=Dienst wird installiert...
german.StartingService=Dienst wird gestartet...
german.StartShunt=The Shunt starten
german.DeleteData=Auch die Konfiguration, die Tunnel und die Statistik löschen (C:\ProgramData\Shunt)?

[Files]
Source: "{#SrcDir}\shuntd-win.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SrcDir}\shunt-desktop.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SrcDir}\wintun.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SrcDir}\tor\*"; DestDir: "{app}\tor"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SrcDir}\the-shunt.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SrcDir}\README.txt"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{commonprograms}\The Shunt"; Filename: "{app}\shunt-desktop.exe"; IconFilename: "{app}\the-shunt.ico"; Comment: "{cm:Comment}"
Name: "{commondesktop}\The Shunt"; Filename: "{app}\shunt-desktop.exe"; IconFilename: "{app}\the-shunt.ico"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "{cm:DesktopIcon}"; Flags: unchecked
Name: "autostart"; Description: "{cm:Autostart}"

[Registry]
; same value the tray menu's "Start at login" switch writes
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "TheShunt"; ValueData: """{app}\shunt-desktop.exe"" --hidden"; Tasks: autostart; Flags: uninsdeletevalue

[Run]
Filename: "{app}\shuntd-win.exe"; Parameters: "install"; Flags: runhidden; Check: not ServiceExists; StatusMsg: "{cm:InstallingService}"
Filename: "{sys}\sc.exe"; Parameters: "config Shunt binPath= ""\""{app}\shuntd-win.exe\"""""; Flags: runhidden; Check: ServiceExists
Filename: "{sys}\net.exe"; Parameters: "start Shunt"; Flags: runhidden; StatusMsg: "{cm:StartingService}"
; the tray runs as the user, never elevated (it starts launchers and browsers)
Filename: "{app}\shunt-desktop.exe"; Description: "{cm:StartShunt}"; Flags: postinstall nowait skipifsilent runasoriginaluser
Filename: "{app}\shunt-desktop.exe"; Parameters: "--hidden"; Flags: nowait skipifnotsilent runasoriginaluser

[Code]
function ServiceExists: Boolean;
var rc: Integer;
begin
  Result := Exec(ExpandConstant('{sys}\sc.exe'), 'query Shunt', '', SW_HIDE, ewWaitUntilTerminated, rc) and (rc = 0);
end;

procedure StopShunt;
var rc: Integer;
begin
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM shunt-desktop.exe', '', SW_HIDE, ewWaitUntilTerminated, rc);
  if ServiceExists then begin
    Exec(ExpandConstant('{sys}\net.exe'), 'stop Shunt', '', SW_HIDE, ewWaitUntilTerminated, rc);
    Sleep(1500);
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  StopShunt;
  Result := '';
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var rc: Integer;
begin
  if CurUninstallStep = usUninstall then begin
    StopShunt;
    Exec(ExpandConstant('{app}\shuntd-win.exe'), 'uninstall', '', SW_HIDE, ewWaitUntilTerminated, rc);
    RegDeleteValue(HKEY_CURRENT_USER, 'Software\Microsoft\Windows\CurrentVersion\Run', 'TheShunt');
  end;
  if CurUninstallStep = usPostUninstall then begin
    if MsgBox(CustomMessage('DeleteData'), mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
      DelTree(ExpandConstant('{commonappdata}\Shunt'), True, True, True);
  end;
end;
