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
InfoBeforeFile={#SrcDir}\disclaimer.txt
CloseApplications=no

[Files]
Source: "{#SrcDir}\shuntd-win.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SrcDir}\shunt-desktop.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SrcDir}\wintun.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SrcDir}\the-shunt.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SrcDir}\README.txt"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{commonprograms}\The Shunt"; Filename: "{app}\shunt-desktop.exe"; IconFilename: "{app}\the-shunt.ico"; Comment: "The Shunt - per-app split tunneling"
Name: "{commondesktop}\The Shunt"; Filename: "{app}\shunt-desktop.exe"; IconFilename: "{app}\the-shunt.ico"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop icon"; Flags: unchecked
Name: "autostart"; Description: "Start the tray icon at login"

[Registry]
; same value the tray menu's "Start at login" switch writes
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "TheShunt"; ValueData: """{app}\shunt-desktop.exe"" --hidden"; Tasks: autostart; Flags: uninsdeletevalue

[Run]
Filename: "{app}\shuntd-win.exe"; Parameters: "install"; Flags: runhidden; Check: not ServiceExists; StatusMsg: "Installing service..."
Filename: "{sys}\sc.exe"; Parameters: "config Shunt binPath= ""\""{app}\shuntd-win.exe\"""""; Flags: runhidden; Check: ServiceExists
Filename: "{sys}\net.exe"; Parameters: "start Shunt"; Flags: runhidden; StatusMsg: "Starting service..."
Filename: "{app}\shunt-desktop.exe"; Description: "Start The Shunt"; Flags: postinstall nowait skipifsilent

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
    if MsgBox('Also delete the configuration, tunnels and statistics (C:\ProgramData\Shunt)?', mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
      DelTree(ExpandConstant('{commonappdata}\Shunt'), True, True, True);
  end;
end;
