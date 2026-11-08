; Inno Setup 6.3+ script for a Windows installer of the qchat client.
;
; Package a client built by "qchat-server build-client", so that the
; installer carries a client locked to one server:
;
;   iscc /DClientExe=C:\build\qchat-clients\qchat_v0.5.0_windows_amd64.exe ^
;        /DAppVersion=0.5.0 /DArch=x64 packaging\windows\qchat.iss
;
; Defines (all optional except ClientExe):
;   ClientExe   path of qchat_<version>_windows_<arch>.exe (relative paths
;               resolve against this directory)
;   AppVersion  version shown in Apps & features (default 0.0.0)
;   Arch        x64 or arm64, matching ClientExe (default x64)
;   AppName     display name; give each server its own, e.g.
;               /DAppName="qchat (Example Org)", together with its own AppId
;   AppId       installer identity as {{GUID}; installers with the same AppId
;               replace each other
;   OutputDir   where the installer is written (default Output, next to
;               this script)
;   SignTool    name of a sign tool configured with iscc /S, to sign the
;               installer and the uninstaller with Authenticode (see
;               packaging/README.md)
;
; The installer copies qchat.exe to Program Files (or to the per-user
; programs folder if the user chooses to install for themselves only) and
; adds a Start menu shortcut that opens a terminal running qchat.
; Uninstalling removes both. The user's qchat profile (identity keys and the
; encrypted message database) is not part of the installation and is kept.

#ifndef ClientExe
  #error Define ClientExe: iscc /DClientExe=path\to\qchat_<version>_windows_<arch>.exe qchat.iss
#endif
#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef Arch
  #define Arch "x64"
#endif
#ifndef AppName
  #define AppName "qchat"
#endif
#ifndef AppId
  #define AppId "{{FE9203DF-01D5-4A8D-AFE0-3D7389A21552}"
#endif
#ifndef OutputDir
  #define OutputDir "Output"
#endif

#if Arch == "x64"
  #define ArchAllowed "x64compatible"
#elif Arch == "arm64"
  #define ArchAllowed "arm64"
#else
  #error Arch must be x64 or arm64
#endif

[Setup]
AppId={#AppId}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher=qchat
AppPublisherURL=https://github.com/craguS/qchat
AppSupportURL=https://github.com/craguS/qchat/issues
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed={#ArchAllowed}
ArchitecturesInstallIn64BitMode={#ArchAllowed}
MinVersion=10.0
LicenseFile={#SourcePath}..\..\LICENSE
OutputDir={#OutputDir}
OutputBaseFilename=qchat-setup-{#AppVersion}-{#Arch}
UninstallDisplayIcon={app}\qchat.exe
UninstallDisplayName={#AppName}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
#ifdef SignTool
SignTool={#SignTool}
SignedUninstaller=yes
#endif

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#ClientExe}"; DestDir: "{app}"; DestName: "qchat.exe"; Flags: ignoreversion
Source: "{#SourcePath}..\..\LICENSE"; DestDir: "{app}"; DestName: "LICENSE.txt"; Flags: ignoreversion

[Icons]
; cmd /k keeps the window open after qchat exits, so error messages stay
; readable.
Name: "{autoprograms}\{#AppName}"; Filename: "{sys}\cmd.exe"; Parameters: "/k ""{app}\qchat.exe"""; WorkingDir: "{%USERPROFILE}"; IconFilename: "{app}\qchat.exe"; Comment: "Open a terminal with qchat"
Name: "{autodesktop}\{#AppName}"; Filename: "{sys}\cmd.exe"; Parameters: "/k ""{app}\qchat.exe"""; WorkingDir: "{%USERPROFILE}"; IconFilename: "{app}\qchat.exe"; Comment: "Open a terminal with qchat"; Tasks: desktopicon

[Run]
Filename: "{sys}\cmd.exe"; Parameters: "/k ""{app}\qchat.exe"""; WorkingDir: "{%USERPROFILE}"; Description: "Start {#AppName} now"; Flags: postinstall nowait skipifsilent unchecked
