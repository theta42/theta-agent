; Theta Agent — Windows installer (Inno Setup 6.4+)
;
; Fully offline: bundles the agent, tray, session helper, the official WireGuard
; for Windows client, the OpenCredential credential provider, and the VC++ v14
; runtime. Nothing on the target machine requires internet access.
;
; Usage:
;   iscc installer\windows\installer.iss
;   theta-agent-2.1.0-windows-amd64-setup.exe /SILENT ^
;       /SERVER_URL=https://sso.example.com /JOIN_KEY=tjk_...
;
; /SERVER_URL and /JOIN_KEY are written into agent.yml so the installed service
; enrolls on first start (no UI, no extra click).

#ifndef MyAppVersion
  #define MyAppVersion "2.1.0"
#endif

#define MyAppName "Theta Agent"
#define MyAppPublisher "Theta42"
#define MyAppExeName "theta-agent-windows-amd64.exe"
#define AgentDir "..\..\dist"
#define VendorDir "vendor"

[Setup]
AppId={{E2F64E2C-7A2B-4F4D-9E8C-9C0D0E9F3A21}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
VersionInfoVersion={#MyAppVersion}
DefaultDirName={autopf}\Theta42
DefaultGroupName=Theta42
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#AgentDir}
OutputBaseFilename=theta-agent-{#MyAppVersion}-windows-amd64-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayName={#MyAppName}
CloseApplications=no
MinVersion=10.0.17763

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Dirs]
; The daemon (SYSTEM) and the tray (logged-in user) share %ProgramData%\Theta42
; for agent.yml, the tray IPC socket and the WireGuard config. Users need write
; access for the socket; the agent.yml ACL is tightened by the code.
Name: "{commonappdata}\Theta42"; Permissions: users-modify
Name: "{app}\vendor"

[Files]
Source: "{#AgentDir}\theta-agent-windows-amd64.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#AgentDir}\theta-agent-tray-windows-amd64.exe"; DestDir: "{app}\tray"; Flags: ignoreversion
Source: "{#AgentDir}\theta-agent-helper-windows-amd64.exe"; DestDir: "{app}"; Flags: ignoreversion

; WireGuard for Windows — official, vendor-signed MSI. Installs offline (the
; driver is signed; no signature phone-home).
Source: "{#VendorDir}\wireguard-amd64-0.5.3.msi"; DestDir: "{app}\vendor"; Flags: ignoreversion

; OpenCredential credential provider installer (BSD-3 pGina fork) + the VC++
; runtime it needs. Both install silently at [Run].
Source: "{#VendorDir}\OpenCredentialInstaller-1.0.0.0.exe"; DestDir: "{app}\vendor"; Flags: ignoreversion
Source: "{#VendorDir}\vc_redist.x64.exe"; DestDir: "{app}\vendor"; Flags: ignoreversion

[Registry]
; Start the tray for every interactive logon.
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "ThetaAgentTray"; ValueData: "{app}\tray\theta-agent-tray-windows-amd64.exe"; Flags: uninsdeletevalue

[Run]
; VC++ v14 runtime (OpenCredential native deps).
Filename: "{app}\vendor\vc_redist.x64.exe"; Parameters: "/install /quiet /norestart"; StatusMsg: "Installing VC++ runtime..."; Flags: runhidden waituntilterminated
; OpenCredential credential provider — must be registered before logon.
Filename: "{app}\vendor\OpenCredentialInstaller-1.0.0.0.exe"; Parameters: "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART"; StatusMsg: "Installing OpenCredential credential provider..."; Flags: runhidden waituntilterminated
; WireGuard for Windows client.
Filename: "msiexec.exe"; Parameters: "/i ""{app}\vendor\wireguard-amd64-0.5.3.msi"" /qn /norestart"; StatusMsg: "Installing WireGuard client..."; Flags: runhidden waituntilterminated
; Register the agent as a SYSTEM auto-start service.
Filename: "{app}\{#MyAppExeName}"; Parameters: "install-service"; StatusMsg: "Registering theta-agent service..."; Flags: runhidden waituntilterminated

[Code]
var
  ServerURL: String;
  JoinKey: String;

// Reads a custom setup command-line parameter (e.g. /SERVER_URL=https://...).
// {param:...} raises when the parameter is absent, so the exception becomes "".
function GetCmdParam(const Name: String): String;
begin
  try
    Result := ExpandConstant('{param:' + Name + '}');
  except
    Result := '';
  end;
end;

function InitializeSetup(): Boolean;
begin
  ServerURL := GetCmdParam('SERVER_URL');
  JoinKey := GetCmdParam('JOIN_KEY');
  Result := True;
end;

// Write agent.yml only after all files are in place. The file lives in
// ProgramData so the SYSTEM service and user processes share it.
procedure WriteAgentConfig(ConfigPath: String);
var
  Lines: TArrayOfString;
begin
  SetArrayLength(Lines, 13);
  Lines[0]  := '# theta-agent configuration (written by installer)';
  Lines[1]  := 'server_url: "' + ServerURL + '"';
  Lines[2]  := 'auth_token: ""';
  Lines[3]  := 'join_key: "' + JoinKey + '"';
  Lines[4]  := 'public_key: ""';
  Lines[5]  := 'auto_vpn: false';
  Lines[6]  := 'service_name: "theta-agent"';
  Lines[7]  := 'desktop_helper: "' + ExpandConstant('{app}') + '\theta-agent-helper-windows-amd64.exe"';
  Lines[8]  := 'public_ip_detect: true';
  Lines[9]  := 'capabilities:';
  Lines[10] := '  telemetry: true';
  Lines[11] := '  ldap_tunnel: true';
  Lines[12] := '  wireguard: true';
  SaveStringsToUTF8File(ConfigPath, Lines, False);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    WriteAgentConfig(ExpandConstant('{commonappdata}\Theta42\agent.yml'));
end;
