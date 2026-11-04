; The installer of the Teeckbox agent for Windows (Inno Setup 6): a wizard that asks for the address of Teeckbox, the one-time
; enrollment code and the allow list, installs the program, registers the service under its own virtual account, enrols the agent
; and starts it. Built by the release workflow:
;
;   ISCC.exe /DAppVersion=0.1.0 /DSourceDir=out deploy\windows\installer.iss
;
; Silent installation (deployment tools): setup.exe /VERYSILENT /URL=https://teeckbox.example.com /CODE=tbe_... /ALLOW=erp.corp.example.com:443,10.20.0.0/16
; (optional: /PROXY=http://proxy:3128 /LABEL=name). Running it again on a machine that is enrolled upgrades the program and keeps the keys.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\..\out"
#endif

#define ServiceName "TeeckboxAgent"

[Setup]
AppId={{6C1F4E52-93B0-4A57-8F0B-5E2D3A7C9B14}
AppName=Teeckbox agent
AppVersion={#AppVersion}
VersionInfoVersion={#AppVersion}
AppPublisher=Teeckbox
AppPublisherURL=https://teeckbox.com
DefaultDirName={autopf}\Teeckbox Agent
DisableProgramGroupPage=yes
DisableDirPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
WizardStyle=modern
Compression=lzma2
SolidCompression=yes
OutputDir=..\..\dist
OutputBaseFilename=teeckbox-agent-{#AppVersion}-win-x64-setup
UninstallDisplayName=Teeckbox agent
UninstallDisplayIcon={app}\teeckbox-agent.exe
CloseApplications=no

[Files]
Source: "{#SourceDir}\teeckbox-agent.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "install-service.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion

[UninstallRun]
Filename: "{sys}\sc.exe"; Parameters: "stop {#ServiceName}"; Flags: runhidden; RunOnceId: "StopService"
Filename: "{sys}\sc.exe"; Parameters: "delete {#ServiceName}"; Flags: runhidden; RunOnceId: "DeleteService"

[Code]
var
  ConnectionPage: TInputQueryWizardPage;
  AllowPage: TWizardPage;
  AllowMemo: TNewMemo;

function DataFolder: String;
begin
  Result := ExpandConstant('{commonappdata}\Teeckbox\Agent');
end;

function IsEnrolled: Boolean;
begin
  Result := FileExists(DataFolder + '\data\state.json');
end;

function ServiceExists: Boolean;
var
  ResultCode: Integer;
begin
  Result := Exec(ExpandConstant('{sys}\sc.exe'), 'query {#ServiceName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0);
end;

function AllowAsList: String;
var
  I: Integer;
  Line: String;
begin
  Result := '';
  for I := 0 to AllowMemo.Lines.Count - 1 do
  begin
    Line := Trim(AllowMemo.Lines[I]);
    if Line <> '' then
    begin
      if Result <> '' then
        Result := Result + ',';
      Result := Result + Line;
    end;
  end;
end;

procedure InitializeWizard;
var
  Help: TNewStaticText;
begin
  ConnectionPage := CreateInputQueryPage(wpWelcome, 'Connection to Teeckbox',
    'Where is Teeckbox, and which code enrols this agent?',
    'In Teeckbox, open Connections > Agents > New agent: it shows the address and a one-time code, valid 15 minutes.');
  ConnectionPage.Add('Address of Teeckbox (https://...):', False);
  ConnectionPage.Add('Enrollment code (tbe_...):', False);
  ConnectionPage.Add('HTTP proxy to reach Teeckbox (leave empty if none):', False);
  ConnectionPage.Values[0] := ExpandConstant('{param:URL|}');
  ConnectionPage.Values[1] := ExpandConstant('{param:CODE|}');
  ConnectionPage.Values[2] := ExpandConstant('{param:PROXY|}');

  AllowPage := CreateCustomPage(ConnectionPage.ID, 'What the agent may call',
    'The systems of your network that Teeckbox may reach through this agent. Anything not listed is refused.');
  Help := TNewStaticText.Create(AllowPage);
  Help.Parent := AllowPage.Surface;
  Help.WordWrap := True;
  Help.Width := AllowPage.SurfaceWidth;
  Help.Caption := 'One destination per line: a host name (erp.corp.example.com, or *.corp.example.com for any name below it) '
    + 'or an address or range (10.20.0.0/16), optionally followed by :port (erp.corp.example.com:443). '
    + 'The list is kept in agent.yaml, which you can edit later.';
  AllowMemo := TNewMemo.Create(AllowPage);
  AllowMemo.Parent := AllowPage.Surface;
  AllowMemo.Top := Help.Height + ScaleY(12);
  AllowMemo.Width := AllowPage.SurfaceWidth;
  AllowMemo.Height := AllowPage.SurfaceHeight - AllowMemo.Top;
  AllowMemo.ScrollBars := ssVertical;
  AllowMemo.WantReturns := True;
  AllowMemo.Text := ExpandConstant('{param:ALLOW|}');
  StringChangeEx(AllowMemo.Text, ',', #13#10, True);
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  // An agent that is enrolled is upgraded: nothing to ask.
  Result := IsEnrolled and ((PageID = ConnectionPage.ID) or (PageID = AllowPage.ID));
end;

function IsValidUrl(Url: String): Boolean;
var
  Lower: String;
begin
  Lower := LowerCase(Url);
  Result := (Pos('https://', Lower) = 1) or (Pos('http://localhost', Lower) = 1) or (Pos('http://127.0.0.1', Lower) = 1);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  I: Integer;
begin
  Result := True;
  if CurPageID = ConnectionPage.ID then
  begin
    for I := 0 to 2 do
      ConnectionPage.Values[I] := Trim(ConnectionPage.Values[I]);
    if not IsValidUrl(ConnectionPage.Values[0]) then
    begin
      MsgBox('The address of Teeckbox must start with https:// (for example https://teeckbox.example.com).', mbError, MB_OK);
      Result := False;
    end
    else if Pos('tbe_', ConnectionPage.Values[1]) <> 1 then
    begin
      MsgBox('The enrollment code starts with tbe_. Create one in Teeckbox: Connections > Agents > New agent.', mbError, MB_OK);
      Result := False;
    end
    else if (ConnectionPage.Values[2] <> '') and (Pos('http', LowerCase(ConnectionPage.Values[2])) <> 1) then
    begin
      MsgBox('The proxy is an address such as http://proxy.example.com:3128, or empty.', mbError, MB_OK);
      Result := False;
    end
    else if (Pos('"', ConnectionPage.Values[0] + ConnectionPage.Values[1] + ConnectionPage.Values[2]) > 0) then
    begin
      MsgBox('A quotation mark is not allowed here.', mbError, MB_OK);
      Result := False;
    end;
  end
  else if CurPageID = AllowPage.ID then
  begin
    if Pos('"', AllowMemo.Text) > 0 then
    begin
      MsgBox('A quotation mark is not allowed here.', mbError, MB_OK);
      Result := False;
    end
    else if AllowAsList = '' then
      Result := MsgBox('The list is empty: the agent will refuse every call until you list destinations in agent.yaml. Continue anyway?',
        mbConfirmation, MB_YESNO) = IDYES;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  Result := '';
  if not IsEnrolled and ((ConnectionPage.Values[0] = '') or (ConnectionPage.Values[1] = '')) then
  begin
    Result := 'The address of Teeckbox and the enrollment code are needed: /URL=... /CODE=...';
    Exit;
  end;
  if ServiceExists then
  begin
    // An upgrade: the program cannot be replaced while it runs.
    Exec(ExpandConstant('{sys}\sc.exe'), 'stop {#ServiceName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Sleep(3000);
  end;
end;

procedure Fail(Message: String);
var
  ResultCode: Integer;
begin
  Exec(ExpandConstant('{sys}\sc.exe'), 'delete {#ServiceName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  SuppressibleMsgBox(Message, mbCriticalError, MB_OK, IDOK);
  Abort;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
  Exe, Config, Data, Log, Args, Account: String;
  Output: AnsiString;
begin
  if CurStep <> ssPostInstall then
    Exit;

  Exe := ExpandConstant('{app}\teeckbox-agent.exe');
  Config := DataFolder + '\agent.yaml';
  Data := DataFolder + '\data';
  Account := 'NT SERVICE\{#ServiceName}';

  if not ServiceExists then
  begin
    if not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
      '-NoProfile -ExecutionPolicy Bypass -File "' + ExpandConstant('{app}\install-service.ps1') + '" -ExePath "' + Exe + '" -ConfigPath "' + Config + '"',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode) or (ResultCode <> 0) then
      Fail('The Windows service could not be installed.');
  end;
  // The service reads the program and the configuration; it writes only its data folder.
  Exec(ExpandConstant('{sys}\icacls.exe'), '"' + ExpandConstant('{app}') + '" /grant "' + Account + ':(OI)(CI)RX"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  if not IsEnrolled then
  begin
    Log := ExpandConstant('{tmp}\enroll.log');
    Args := 'enroll --url "' + ConnectionPage.Values[0] + '" --code "' + ConnectionPage.Values[1] + '" --config "' + Config
      + '" --data-folder "' + Data + '" --grant "' + Account + '"';
    if ConnectionPage.Values[2] <> '' then
      Args := Args + ' --proxy "' + ConnectionPage.Values[2] + '"';
    if AllowAsList <> '' then
      Args := Args + ' --allow "' + AllowAsList + '"';
    if ExpandConstant('{param:LABEL|}') <> '' then
      Args := Args + ' --label "' + ExpandConstant('{param:LABEL|}') + '"';

    // cmd /C "…" keeps the outer quotes together; the output is read back to show why it failed.
    if not Exec(ExpandConstant('{cmd}'), '/C ""' + Exe + '" ' + Args + ' > "' + Log + '" 2>&1"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) or (ResultCode <> 0) then
    begin
      Output := '';
      LoadStringFromFile(Log, Output);
      Fail('The agent could not be enrolled:'#13#10#13#10 + String(Output)
        + #13#10'The installation was cancelled. The code can be used once: create a new one in Teeckbox and run this installer again.');
    end;
  end;

  Exec(ExpandConstant('{sys}\sc.exe'), 'start {#ServiceName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(2500);
  Log := ExpandConstant('{tmp}\state.log');
  Exec(ExpandConstant('{cmd}'), '/C ""' + ExpandConstant('{sys}\sc.exe') + '" query {#ServiceName} > "' + Log + '" 2>&1"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Output := '';
  LoadStringFromFile(Log, Output);
  if Pos('RUNNING', String(Output)) = 0 then
    SuppressibleMsgBox('The agent is installed but the service is not running. See the Windows Event Viewer (Windows Logs > Application), '
      + 'then start it with: Start-Service {#ServiceName}', mbError, MB_OK, IDOK);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
  begin
    if DirExists(DataFolder) and (UninstallSilent = False) then
      if MsgBox('Also delete the keys and the configuration of the agent (' + DataFolder + ')?'#13#10#13#10
        + 'Keep them to install the agent again without enrolling it again. Disable the instance in Teeckbox (Connections > Agents) if you remove it for good.',
        mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
        DelTree(DataFolder, True, True, True);
  end;
end;
