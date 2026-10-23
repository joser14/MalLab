; Inno Setup 6 script for MalLab's installer and uninstaller. Built by build.ps1, after
; PyInstaller has produced dist\MalLab\.
;
; Install: MalLab + WebView2 (if missing), and optionally Windows Sandbox, Sysmon, capa, FakeNet-NG,
; threat-group data, the host network guard, the Defender exclusion for the sample folders, and
; threat-intel API keys (user environment variables).
; Uninstall: removes the app, shortcuts, the Defender exclusion and the host guard rules, then asks before deleting lab
; data (it contains live samples) and saved API keys. Windows Sandbox stays enabled, since other
; software may use it.

#define MyAppName "MalLab"
#define MyAppVersion "1.2.2"
#define MyAppExe "MalLab.exe"

[Setup]
AppId={{6F3B1C52-8E4A-4C1D-9B7E-2A5D0F9C3E11}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppName}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
; admin: turning on Windows Sandbox and installing WebView2 machine-wide both need it
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Windows Sandbox first shipped in Windows 10 1903
MinVersion=10.0.18362
AppMutex=MalLabDesktopSingleInstance
CloseApplications=yes
ChangesEnvironment=yes
InfoBeforeFile=before-install.txt
SetupIconFile=mallab.ico
UninstallDisplayIcon={app}\{#MyAppExe}
UninstallDisplayName={#MyAppName}
OutputDir=Output
OutputBaseFilename=MalLab-Setup-{#MyAppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern

[Tasks]
Name: "sandbox"; Description: "Turn on Windows Sandbox (needed to detonate samples, restart required)"; GroupDescription: "Required for detonation:"; Check: CanEnableSandbox
Name: "sysmon"; Description: "Sysmon from Microsoft Sysinternals (full process, network and registry events)"; GroupDescription: "Analysis tools, downloaded from their official sources:"
Name: "capa"; Description: "capa from Mandiant (what a program's code is capable of, mapped to ATT&&CK)"; GroupDescription: "Analysis tools, downloaded from their official sources:"
Name: "fakenet"; Description: "FakeNet-NG from Mandiant (the Simulated network mode: fake internet inside the sandbox)"; GroupDescription: "Analysis tools, downloaded from their official sources:"
Name: "memscan"; Description: "hollows_hunter / pe-sieve (dumps injected and unpacked code; runs only inside the sandbox)"; GroupDescription: "Analysis tools, downloaded from their official sources:"
Name: "sigma"; Description: "SigmaHQ community detection rules (thousands of behaviour detections)"; GroupDescription: "Analysis tools, downloaded from their official sources:"
Name: "yaraforge"; Description: "YARA Forge curated public YARA rules"; GroupDescription: "Analysis tools, downloaded from their official sources:"
Name: "actors"; Description: "Threat-group data from MITRE ATT&&CK, MISP Galaxy and Malpedia"; GroupDescription: "Analysis tools, downloaded from their official sources:"
Name: "hostguard"; Description: "Turn on the host network guard: block the sandbox from reaching this PC (Windows will ask you to approve)"; GroupDescription: "Protection:"
Name: "defender"; Description: "Exclude MalLab's sample folders from Microsoft Defender (Windows will ask you to approve)"; GroupDescription: "Protection:"; Flags: unchecked
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "dist\MalLab\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExe}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExe}"; Tasks: desktopicon

[Run]
; runasoriginaluser: the lab lives in the signed-in user's %LOCALAPPDATA%, not the elevated installer's
; Each step that fails is noted in the lab folder and offered for retry in MalLab's Settings.
Filename: "{app}\{#MyAppExe}"; Parameters: "--setup-sysmon"; StatusMsg: "Downloading Sysmon from Microsoft Sysinternals..."; Tasks: sysmon; Flags: runasoriginaluser runhidden waituntilterminated
Filename: "{app}\{#MyAppExe}"; Parameters: "--setup-capa"; StatusMsg: "Downloading capa from Mandiant's GitHub releases..."; Tasks: capa; Flags: runasoriginaluser runhidden waituntilterminated
Filename: "{app}\{#MyAppExe}"; Parameters: "--setup-fakenet"; StatusMsg: "Downloading FakeNet-NG from Mandiant's GitHub releases..."; Tasks: fakenet; Flags: runasoriginaluser runhidden waituntilterminated
Filename: "{app}\{#MyAppExe}"; Parameters: "--setup-memscan"; StatusMsg: "Downloading hollows_hunter from its GitHub releases..."; Tasks: memscan; Flags: runasoriginaluser runhidden waituntilterminated
Filename: "{app}\{#MyAppExe}"; Parameters: "--setup-sigma"; StatusMsg: "Downloading SigmaHQ rules..."; Tasks: sigma; Flags: runasoriginaluser runhidden waituntilterminated
Filename: "{app}\{#MyAppExe}"; Parameters: "--setup-yara-forge"; StatusMsg: "Downloading YARA Forge rules..."; Tasks: yaraforge; Flags: runasoriginaluser runhidden waituntilterminated
Filename: "{app}\{#MyAppExe}"; Parameters: "--import-actors"; StatusMsg: "Importing threat-group data (MITRE ATT&CK, MISP Galaxy, Malpedia)..."; Tasks: actors; Flags: runasoriginaluser runhidden waituntilterminated
Filename: "{app}\{#MyAppExe}"; Parameters: "--defender-exclude"; StatusMsg: "Adding the Defender exclusion (approve the Windows prompt)..."; Tasks: defender; Flags: runasoriginaluser waituntilterminated
; The guard needs the sandbox's network adapter, which appears only once Windows Sandbox is on (after
; the restart when this installer turned it on). Then it is left for Settings instead.
Filename: "{app}\{#MyAppExe}"; Parameters: "--host-guard"; StatusMsg: "Turning on the host network guard (approve the Windows prompt)..."; Tasks: hostguard; Check: SandboxInstalled; Flags: runasoriginaluser waituntilterminated
Filename: "{app}\{#MyAppExe}"; Parameters: "--defer ""host network guard"""; Tasks: hostguard; Check: not SandboxInstalled; Flags: runasoriginaluser runhidden waituntilterminated
Filename: "{app}\{#MyAppExe}"; Description: "Launch {#MyAppName}"; Flags: runasoriginaluser nowait postinstall skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

[Code]
const
  WebView2Guid = '{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}';
  WebView2Url = 'https://go.microsoft.com/fwlink/p/?LinkId=2124703';
  KeyCount = 5;

var
  DownloadPage: TDownloadWizardPage;
  KeysPage: TInputQueryWizardPage;
  SandboxEnabledNow: Boolean;

function KeyName(I: Integer): String;
begin
  case I of
    0: Result := 'VT_API_KEY';
    1: Result := 'ABUSECH_API_KEY';
    2: Result := 'HA_API_KEY';
    3: Result := 'OTX_API_KEY';
    4: Result := 'VX_API_KEY';
  end;
end;

function KeyLabel(I: Integer): String;
begin
  case I of
    0: Result := 'VirusTotal:';
    1: Result := 'abuse.ch (MalwareBazaar, ThreatFox, URLhaus):';
    2: Result := 'Hybrid Analysis:';
    3: Result := 'AlienVault OTX:';
    4: Result := 'virus.exchange (vx-underground, for fetching samples):';
  end;
end;

{ ---- prerequisite checks ---- }

function SandboxInstalled: Boolean;
begin
  Result := FileExists(ExpandConstant('{sys}\WindowsSandbox.exe'));
end;

function IsHomeEdition: Boolean;
var
  Edition: String;
begin
  Result := RegQueryStringValue(HKLM, 'SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'EditionID', Edition)
            and (Pos('Core', Edition) = 1);
end;

function CanEnableSandbox: Boolean;
begin
  Result := not SandboxInstalled and not IsHomeEdition;
end;

function WebView2Installed: Boolean;
var
  Version: String;
begin
  Result := (RegQueryStringValue(HKLM32, 'SOFTWARE\Microsoft\EdgeUpdate\Clients\' + WebView2Guid, 'pv', Version)
             or RegQueryStringValue(HKCU, 'Software\Microsoft\EdgeUpdate\Clients\' + WebView2Guid, 'pv', Version))
            and (Version <> '') and (Version <> '0.0.0.0');
end;

function InitializeSetup: Boolean;
begin
  Result := True;
  if not SandboxInstalled and IsHomeEdition then
    Result := SuppressibleMsgBox(
      'This PC runs Windows Home, which does not include Windows Sandbox.' + #13#10#13#10 +
      'MalLab will install and static analysis, YARA and threat intel will work, but samples ' +
      'cannot be detonated. Upgrading to Windows Pro enables detonation.' + #13#10#13#10 +
      'Continue installing?', mbConfirmation, MB_YESNO, IDYES) = IDYES;
end;

{ ---- wizard pages ---- }

function OnDownloadProgress(const Url, FileName: String; const Progress, ProgressMax: Int64): Boolean;
begin
  Result := True;
end;

procedure InitializeWizard;
var
  I: Integer;
begin
  DownloadPage := CreateDownloadPage(SetupMessage(msgWizardPreparing), SetupMessage(msgPreparingDesc), @OnDownloadProgress);
  KeysPage := CreateInputQueryPage(wpSelectTasks,
    'Threat-intel API keys (optional)',
    'Paste any keys you have. Leave a box empty to skip that source.',
    'MalLab looks up sample hashes with these services (only the SHA-256 is sent, never the file). ' +
    'Keys are saved as user environment variables. You can add or change them later in Settings.');
  for I := 0 to KeyCount - 1 do
  begin
    KeysPage.Add(KeyLabel(I), False);
    KeysPage.Values[I] := GetEnv(KeyName(I));
  end;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if (CurPageID = wpReady) and not WebView2Installed then
  begin
    DownloadPage.Clear;
    DownloadPage.Add(WebView2Url, 'MicrosoftEdgeWebview2Setup.exe', '');
    DownloadPage.Show;
    try
      try
        DownloadPage.Download;
      except
        if DownloadPage.AbortedByUser then
          Result := False
        else
          SuppressibleMsgBox('Could not download the Microsoft Edge WebView2 Runtime, which MalLab needs ' +
            'to show its window:' + #13#10 + GetExceptionMessage + #13#10#13#10 +
            'Setup will continue. Install WebView2 later from ' +
            'https://developer.microsoft.com/microsoft-edge/webview2/', mbError, MB_OK, IDOK);
      end;
    finally
      DownloadPage.Hide;
    end;
  end;
end;

function UpdateReadyMemo(Space, NewLine, MemoUserInfoInfo, MemoDirInfo, MemoTypeInfo,
  MemoComponentsInfo, MemoGroupInfo, MemoTasksInfo: String): String;
var
  I, N: Integer;
begin
  Result := MemoDirInfo + NewLine + NewLine;
  if not WebView2Installed then
    Result := Result + 'Prerequisites:' + NewLine + Space + 'Microsoft Edge WebView2 Runtime (download)' + NewLine + NewLine;
  if MemoTasksInfo <> '' then
    Result := Result + MemoTasksInfo + NewLine + NewLine;
  N := 0;
  for I := 0 to KeyCount - 1 do
    if Trim(KeysPage.Values[I]) <> '' then N := N + 1;
  Result := Result + 'Threat-intel API keys:' + NewLine + Space + IntToStr(N) + ' of ' + IntToStr(KeyCount) + ' provided';
  if SandboxInstalled then
    Result := Result + NewLine + NewLine + 'Windows Sandbox:' + NewLine + Space + 'already enabled'
  else if WizardIsTaskSelected('hostguard') then
    Result := Result + NewLine + NewLine + 'Host network guard:' + NewLine + Space +
              'turn it on in MalLab''s Settings after the restart (it needs Windows Sandbox to be on)';
end;

{ ---- install steps ---- }

procedure InstallWebView2;
var
  Setup: String;
  Code: Integer;
begin
  Setup := ExpandConstant('{tmp}\MicrosoftEdgeWebview2Setup.exe');
  if WebView2Installed or not FileExists(Setup) then Exit;
  WizardForm.StatusLabel.Caption := 'Installing Microsoft Edge WebView2 Runtime...';
  if not Exec(Setup, '/silent /install', '', SW_HIDE, ewWaitUntilTerminated, Code) or (Code <> 0) then
    SuppressibleMsgBox('The WebView2 Runtime installer failed (code ' + IntToStr(Code) + '). ' +
      'Install it from https://developer.microsoft.com/microsoft-edge/webview2/ before starting MalLab.',
      mbError, MB_OK, IDOK);
end;

procedure EnableSandbox;
var
  Code: Integer;
begin
  WizardForm.StatusLabel.Caption := 'Turning on Windows Sandbox (this can take a few minutes)...';
  if Exec(ExpandConstant('{sys}\dism.exe'),
          '/online /enable-feature /featurename:Containers-DisposableClientVM /all /norestart /quiet',
          '', SW_HIDE, ewWaitUntilTerminated, Code) and ((Code = 0) or (Code = 3010)) then
    SandboxEnabledNow := True
  else
    SuppressibleMsgBox('Windows Sandbox could not be turned on (DISM code ' + IntToStr(Code) + ').' + #13#10#13#10 +
      'Make sure virtualization (Intel VT-x / AMD-V) is enabled in the BIOS/UEFI, then run this in an ' +
      'administrator PowerShell and restart:' + #13#10 +
      'Enable-WindowsOptionalFeature -FeatureName "Containers-DisposableClientVM" -All -Online',
      mbError, MB_OK, IDOK);
end;

procedure SaveApiKeys;
var
  I: Integer;
  Value: String;
begin
  for I := 0 to KeyCount - 1 do
  begin
    Value := Trim(KeysPage.Values[I]);
    if Value <> '' then
      RegWriteStringValue(HKCU, 'Environment', KeyName(I), Value);
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    InstallWebView2;
    if WizardIsTaskSelected('sandbox') then
      EnableSandbox;
    SaveApiKeys;
  end;
end;

function NeedRestart: Boolean;
begin
  Result := SandboxEnabledNow;
end;

{ ---- uninstall ---- }

function LabDataDir: String;
begin
  Result := ExpandConstant('{localappdata}\MalLab');
end;

procedure RemoveDefenderExclusion;
var
  Code: Integer;
  Lab: String;
begin
  Lab := LabDataDir + '\lab';
  Exec('powershell.exe', '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "' +
       'Remove-MpPreference -ExclusionPath ''' + Lab + '\quarantine'',''' + Lab + '\runs'' -ErrorAction SilentlyContinue"',
       '', SW_HIDE, ewWaitUntilTerminated, Code);
end;

procedure RemoveHostGuard;
var
  Code: Integer;
begin
  Exec('powershell.exe', '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "' +
       'Get-NetFirewallRule -Group ''MalLab host guard'' -ErrorAction SilentlyContinue | Remove-NetFirewallRule"',
       '', SW_HIDE, ewWaitUntilTerminated, Code);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  I: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    RemoveDefenderExclusion;
    RemoveHostGuard;
  end;
  if CurUninstallStep = usPostUninstall then
  begin
    if DirExists(LabDataDir) and (SuppressibleMsgBox(
         'Also delete your MalLab data?' + #13#10#13#10 + LabDataDir + #13#10#13#10 +
         'This holds your cases, reports, YARA rules and the quarantined malware samples. ' +
         'Choose No to keep it for a later reinstall.',
         mbConfirmation, MB_YESNO or MB_DEFBUTTON2, IDNO) = IDYES) then
      DelTree(LabDataDir, True, True, True);
    if (GetEnv('VT_API_KEY') + GetEnv('ABUSECH_API_KEY') + GetEnv('HA_API_KEY') + GetEnv('OTX_API_KEY') + GetEnv('VX_API_KEY') <> '')
       and (SuppressibleMsgBox('Also remove the threat-intel API keys saved as environment variables ' +
         '(VT_API_KEY, ABUSECH_API_KEY, HA_API_KEY, OTX_API_KEY, VX_API_KEY)?',
         mbConfirmation, MB_YESNO, IDNO) = IDYES) then
      for I := 0 to KeyCount - 1 do
        RegDeleteValue(HKCU, 'Environment', KeyName(I));
  end;
end;
