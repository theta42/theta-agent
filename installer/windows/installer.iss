; Theta Agent ??? Windows installer (Inno Setup 6.4+)
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
; Interactively, a wizard page asks for the Theta Directory URL and a join key
; (with a button that opens the Theta Directory's Directory -> Install Agent page
; to mint one). In silent mode, /SERVER_URL, /JOIN_KEY, /AUTH_TOKEN, /PUBLIC_KEY
; and /B64_CONFIG (base64 of a full agent.yml) drive the same result. The values
; are written into agent.yml so the installed service enrolls on first start.

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

; WireGuard for Windows ??? official, vendor-signed MSI. Installs offline (the
; driver is signed; no signature phone-home).
Source: "{#VendorDir}\wireguard-amd64-0.5.3.msi"; DestDir: "{app}\vendor"; Flags: ignoreversion

; OpenCredential credential provider installer (BSD-3 pGina fork) + the VC++
; runtime it needs. Both install silently at [Run].
Source: "{#VendorDir}\OpenCredentialInstaller-1.0.0.0.exe"; DestDir: "{app}\vendor"; Flags: ignoreversion
Source: "{#VendorDir}\vc_redist.x64.exe"; DestDir: "{app}\vendor"; Flags: ignoreversion

[Icons]
Name: "{group}\Theta Agent Tray"; Filename: "{app}\tray\theta-agent-tray-windows-amd64.exe"; Comment: "Theta Agent status tray"
Name: "{group}\Open Agent Config"; Filename: "notepad.exe"; Parameters: "{commonappdata}\Theta42\agent.yml"; Comment: "Open the agent configuration file"
Name: "{group}\Uninstall Theta Agent"; Filename: "{uninstallexe}"

[Registry]
; Start the tray for every interactive logon.
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "ThetaAgentTray"; ValueData: "{app}\tray\theta-agent-tray-windows-amd64.exe"; Flags: uninsdeletevalue

[Run]
; VC++ v14 runtime (OpenCredential native deps).
Filename: "{app}\vendor\vc_redist.x64.exe"; Parameters: "/install /quiet /norestart"; StatusMsg: "Installing VC++ runtime..."; Flags: runhidden waituntilterminated
; OpenCredential credential provider ??? must be registered before logon.
Filename: "{app}\vendor\OpenCredentialInstaller-1.0.0.0.exe"; Parameters: "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART"; StatusMsg: "Installing OpenCredential credential provider..."; Flags: runhidden waituntilterminated
; WireGuard for Windows client.
Filename: "msiexec.exe"; Parameters: "/i ""{app}\vendor\wireguard-amd64-0.5.3.msi"" /qn /norestart"; StatusMsg: "Installing WireGuard client..."; Flags: runhidden waituntilterminated
; The WireGuard client launches its UI at the end of the MSI; close it ??? the
; tunnel is managed by the agent (wireguard.exe /installtunnelservice).
Filename: "taskkill.exe"; Parameters: "/f /im wireguard.exe"; Flags: runhidden
; Register the agent as a SYSTEM auto-start service.
Filename: "{app}\{#MyAppExeName}"; Parameters: "install-service"; StatusMsg: "Registering theta-agent service..."; Flags: runhidden waituntilterminated
; Show the tray right away, in silent and interactive installs alike (a silent
; install is the common path from the Directory's install command, and the tray
; should appear immediately there too, not only at the next logon).
Filename: "{app}\tray\theta-agent-tray-windows-amd64.exe"; Description: "Start Theta Agent tray"; StatusMsg: "Starting Theta Agent tray..."; Flags: nowait postinstall

[Code]
var
  ServerURL: String;
  JoinKey: String;
  AuthToken: String;
  PublicKey: String;
  B64Config: String;

  AgentConfigPage: TWizardPage;
  ServerURLEdit: TNewEdit;
  JoinKeyEdit: TNewEdit;
  OpenSSOButton: TNewButton;

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
  AuthToken := GetCmdParam('AUTH_TOKEN');
  PublicKey := GetCmdParam('PUBLIC_KEY');
  B64Config := GetCmdParam('B64_CONFIG');
  Result := True;
end;

// Opens the Theta Directory page so the operator can mint a join key right
// from the wizard. Uses the Server URL they just typed.
procedure OnOpenSSOClick(Sender: TObject);
var
  Url: String;
  ErrorCode: Integer;
begin
  Url := Trim(ServerURLEdit.Text);
  if Url = '' then begin
    MsgBox('Enter the Theta Directory URL first (e.g. https://directory.example.com).',
      mbInformation, MB_OK);
    Exit;
  end;
  if not ShellExec('open', Url, '', '', SW_SHOWNORMAL, ewNoWait, ErrorCode) then
    MsgBox('Could not open the browser: ' + SysErrorMessage(ErrorCode), mbError, MB_OK);
end;

procedure CreateAgentConfigPage();
var
  InfoLabel: TNewStaticText;
  UrlLabel: TNewStaticText;
  KeyLabel: TNewStaticText;
  Y: Integer;
begin
  AgentConfigPage := CreateCustomPage(wpWelcome,
    'Theta Directory connection',
    'Tell the agent which Theta Directory to enroll with.');

  InfoLabel := TNewStaticText.Create(AgentConfigPage);
  InfoLabel.Parent := AgentConfigPage.Surface;
  InfoLabel.WordWrap := True;
  InfoLabel.Caption := 'Paste the Theta Directory URL for this deployment. Then either paste a join key '
    + '(mint one with the button below, under Directory -> Install Agent) or leave it blank to '
    + 'enroll from the tray / CLI later.';
  // WordWrap + AutoSize are mutually exclusive in VCL; give the wrapped label a
  // fixed height so the fields below it land on screen.
  InfoLabel.Width := AgentConfigPage.SurfaceWidth;
  InfoLabel.Height := ScaleY(48);

  Y := InfoLabel.Top + InfoLabel.Height + ScaleY(12);

  UrlLabel := TNewStaticText.Create(AgentConfigPage);
  UrlLabel.Parent := AgentConfigPage.Surface;
  UrlLabel.Caption := 'Theta Directory URL:';
  UrlLabel.Top := Y;

  ServerURLEdit := TNewEdit.Create(AgentConfigPage);
  ServerURLEdit.Parent := AgentConfigPage.Surface;
  ServerURLEdit.Top := UrlLabel.Top + UrlLabel.Height + ScaleY(4);
  ServerURLEdit.Width := AgentConfigPage.SurfaceWidth;
  ServerURLEdit.Text := ServerURL;

  OpenSSOButton := TNewButton.Create(AgentConfigPage);
  OpenSSOButton.Parent := AgentConfigPage.Surface;
  OpenSSOButton.Top := ServerURLEdit.Top + ServerURLEdit.Height + ScaleY(10);
  OpenSSOButton.Left := ServerURLEdit.Left;
  OpenSSOButton.Caption := 'Open Theta Directory install-agent page...';
  OpenSSOButton.Width := WizardForm.CalculateButtonWidth([OpenSSOButton.Caption]);
  OpenSSOButton.Height := ScaleY(23);
  OpenSSOButton.OnClick := @OnOpenSSOClick;

  KeyLabel := TNewStaticText.Create(AgentConfigPage);
  KeyLabel.Parent := AgentConfigPage.Surface;
  KeyLabel.Caption := 'Join key (optional):';
  KeyLabel.Top := OpenSSOButton.Top + OpenSSOButton.Height + ScaleY(12);

  JoinKeyEdit := TNewEdit.Create(AgentConfigPage);
  JoinKeyEdit.Parent := AgentConfigPage.Surface;
  JoinKeyEdit.Top := KeyLabel.Top + KeyLabel.Height + ScaleY(4);
  JoinKeyEdit.Width := AgentConfigPage.SurfaceWidth;
  JoinKeyEdit.Text := JoinKey;
end;

procedure InitializeWizard();
begin
  CreateAgentConfigPage();
end;

// Pull the values the operator typed into the wizard so WriteAgentConfig can
// use them. In silent mode the wizard is walked programmatically and
// CurPageChanged fires too -- reading the (empty) edit boxes there would wipe
// the /SERVER_URL /JOIN_KEY command-line params and leave agent.yml with an
// empty server_url. Only take the edit values when the wizard is actually
// being shown interactively.
procedure CurPageChanged(CurPageID: Integer);
begin
  if (CurPageID = AgentConfigPage.ID) and (not WizardSilent()) then begin
    ServerURL := Trim(ServerURLEdit.Text);
    JoinKey := Trim(JoinKeyEdit.Text);
  end;
end;

// Minimal base64 decoder returning a plain String (agent.yml is ASCII).
function B64Decode(const S: String): String;
var
  i, v, p: Integer;
  buf: array[0..3] of Integer;
  outStr: String;
begin
  outStr := '';
  v := 0;
  for i := 1 to Length(S) do begin
    if S[i] = '=' then begin
      buf[v] := 0;
      Inc(v);
    end else begin
      p := Pos(S[i], 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/');
      buf[v] := p - 1;
      Inc(v);
    end;
    if v = 4 then begin
      outStr := outStr + Chr((buf[0] shl 2) or (buf[1] shr 4));
      outStr := outStr + Chr(((buf[1] and $F) shl 4) or (buf[2] shr 2));
      outStr := outStr + Chr(((buf[2] and 3) shl 6) or buf[3]);
      v := 0;
    end;
  end;
  Result := outStr;
end;

// Write agent.yml only after all files are in place. The file lives in
// ProgramData so the SYSTEM service and user processes share it.
procedure WriteAgentConfig(ConfigPath: String);
var
  Lines: TArrayOfString;
  Decoded: String;
begin
  // /B64_CONFIG=<base64 agent.yml> overrides everything (the SSO's Custom Config
  // wizard emits it).
  if B64Config <> '' then begin
    Decoded := B64Decode(B64Config);
    SetArrayLength(Lines, 1);
    Lines[0] := Decoded;
    SaveStringsToUTF8FileWithoutBOM(ConfigPath, Lines, False);
    Exit;
  end;

  SetArrayLength(Lines, 17);
  Lines[0]  := '# theta-agent configuration (written by installer)';
  Lines[1]  := 'server_url: "' + ServerURL + '"';
  Lines[2]  := 'auth_token: "' + AuthToken + '"';
  Lines[3]  := 'join_key: "' + JoinKey + '"';
  Lines[4]  := 'public_key: "' + PublicKey + '"';
  Lines[5]  := 'auto_vpn: false';
  Lines[6]  := 'service_name: "theta-agent"';
  Lines[7]  := 'desktop_helper: "' + ExpandConstant('{app}') + '\theta-agent-helper-windows-amd64.exe"';
  Lines[8]  := 'public_ip_detect: true';
  Lines[9]  := 'capabilities:';
  Lines[10] := '  telemetry: true';
  Lines[11] := '  ldap_tunnel: true';
  Lines[12] := '  wireguard: true';
  Lines[13] := '  secrets: false';
  Lines[14] := '  iam: false';
  Lines[15] := '  reboot: false';
  Lines[16] := '  arbitrary_bash: false';
  SaveStringsToUTF8FileWithoutBOM(ConfigPath, Lines, False);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    WriteAgentConfig(ExpandConstant('{commonappdata}\Theta42\agent.yml'));
end;
