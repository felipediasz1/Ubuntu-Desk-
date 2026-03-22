; Ubuntu Desk — Inno Setup Script
; Gera: installer/Output/ubuntu-desk-setup.exe
;
; ── Deploy em massa (parâmetros opcionais) ──────────────────────────────────
; Instalação silenciosa padrão:
;   ubuntu-desk-setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART
;
; Instalação silenciosa com servidor pré-configurado:
;   ubuntu-desk-setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SERVER=192.168.1.100 /KEY=SuaChavePublica
;
; Parâmetros disponíveis:
;   /SERVER=<ip_ou_host>    — endereço do servidor hbbs
;   /KEY=<chave_publica>    — chave pública RS_PUB_KEY
;   /API=<url_api>          — URL do painel admin (opcional)
;   /STARTMINIMIZED         — inicia minimizado na bandeja após instalação
; ────────────────────────────────────────────────────────────────────────────

[Setup]
AppId={{E4A2B7C1-3F8D-4E9A-B562-1D7F3C8A0E45}
AppName=Ubuntu Desk
AppVersion=1.0.0
AppPublisher=Ubuntu Desk
AppPublisherURL=https://ubuntudesk.app
AppSupportURL=https://ubuntudesk.app
DefaultDirName={autopf}\Ubuntu Desk
DefaultGroupName=Ubuntu Desk
OutputDir=Output
OutputBaseFilename=ubuntu-desk-setup
SetupIconFile=..\client\res\icon.ico
UninstallDisplayIcon={app}\icon.ico
Compression=lzma
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
MinVersion=10.0
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
; Fecha instâncias abertas automaticamente em deploy silencioso
CloseApplications=yes
; Não reinicia o sistema após instalação silenciosa
RestartIfNeededByRun=no

[Languages]
Name: "brazilianportuguese"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "startup"; Description: "Iniciar Ubuntu Desk com o Windows"; GroupDescription: "Inicialização:"; Flags: unchecked

[Files]
Source: "..\dist\windows\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\Ubuntu Desk"; Filename: "{app}\ubuntu-desk.exe"; IconFilename: "{app}\icon.ico"
Name: "{group}\{cm:UninstallProgram,Ubuntu Desk}"; Filename: "{uninstallexe}"
Name: "{commondesktop}\Ubuntu Desk"; Filename: "{app}\ubuntu-desk.exe"; IconFilename: "{app}\icon.ico"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "Ubuntu Desk"; ValueData: """{app}\ubuntu-desk.exe"""; Tasks: startup; Flags: uninsdeletevalue
; Deploy em massa: inicialização automática via HKLM (todos os usuários da máquina)
; Descomente a linha abaixo para forçar início automático em deploy corporativo:
; Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "Ubuntu Desk"; ValueData: """{app}\ubuntu-desk.exe"""; Flags: uninsdeletevalue

[Run]
; Lançamento interativo (instalação normal)
Filename: "{app}\ubuntu-desk.exe"; Description: "{cm:LaunchProgram,Ubuntu Desk}"; Flags: nowait postinstall skipifsilent

[Code]
{ ── Parâmetros de deploy em massa ─────────────────────────────────────── }
var
  DeployServer: String;
  DeployKey:    String;
  DeployApi:    String;

function InitializeSetup(): Boolean;
begin
  { Lê os parâmetros passados na linha de comando }
  DeployServer := ExpandConstant('{param:SERVER|}');
  DeployKey    := ExpandConstant('{param:KEY|}');
  DeployApi    := ExpandConstant('{param:API|}');
  Result := True;
end;

procedure CurStepChanged(CurStep: TSetupStep);
{ Aplica a configuração do servidor logo após a cópia dos arquivos }
var
  AppExe:     String;
  ConfigStr:  String;
  ResultCode: Integer;
begin
  if (CurStep = ssDone) and (DeployServer <> '') then
  begin
    AppExe    := ExpandConstant('{app}\ubuntu-desk.exe');
    ConfigStr := 'ubuntu-desk-host=' + DeployServer;
    if DeployKey <> '' then
      ConfigStr := ConfigStr + ',key=' + DeployKey;
    if DeployApi <> '' then
      ConfigStr := ConfigStr + ',api=' + DeployApi;
    { ubuntu-desk.exe --config "ubuntu-desk-host=IP,key=KEY.exe" aplica as opções }
    Exec(AppExe,
         '--config "' + ConfigStr + '.exe"',
         ExpandConstant('{app}'),
         SW_HIDE,
         ewWaitUntilTerminated,
         ResultCode);
  end;
end;
