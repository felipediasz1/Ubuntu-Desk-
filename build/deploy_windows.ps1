# Ubuntu Desk — Script de Deploy em Massa (Windows)
# Uso: .\build\deploy_windows.ps1 -ServerIP 192.168.1.100 -PubKey "SuaChave=" [-Silent] [-Startup] [-Api "http://IP:8088"]
#
# Exemplos:
#   Deploy silencioso com servidor pré-configurado:
#     .\deploy_windows.ps1 -ServerIP 192.168.1.100 -PubKey "SuaChave=" -Silent
#
#   Deploy via UNC (GPO Startup Script):
#     \\fileserver\deploy\deploy_windows.ps1 -InstallerPath \\fileserver\deploy\ubuntu-desk-setup.exe -ServerIP 192.168.1.100 -PubKey "SuaChave=" -Silent
#
#   Apenas configurar servidor em instalação existente:
#     .\deploy_windows.ps1 -ServerIP 192.168.1.100 -PubKey "SuaChave=" -ConfigOnly
#
# ── GPO ─────────────────────────────────────────────────────────────────────────
# Para GPO (Computador > Configurações Windows > Scripts > Inicialização):
#   Programa:    powershell.exe
#   Parâmetros:  -ExecutionPolicy Bypass -File "\\servidor\share\deploy_windows.ps1" -ServerIP 192.168.1.100 -PubKey "ChavePublica=" -Silent
# ────────────────────────────────────────────────────────────────────────────────

param(
    # Localização do instalador (EXE local ou UNC)
    [string]$InstallerPath = "",

    # Configuração do servidor
    [string]$ServerIP  = "",
    [string]$PubKey    = "",
    [string]$Api       = "",

    # Flags de comportamento
    [switch]$Silent     = $false,   # instalação sem janela
    [switch]$Startup    = $false,   # forçar início automático com o Windows
    [switch]$ConfigOnly = $false,   # apenas aplica config, não instala
    [switch]$Force      = $false    # reinstala mesmo se já instalado
)

$ErrorActionPreference = "Stop"

function Write-Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-OK($msg)   { Write-Host "    [OK] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "    [AVISO] $msg" -ForegroundColor Yellow }
function Write-Fail($msg) { Write-Host "    [ERRO] $msg" -ForegroundColor Red; exit 1 }

# ── Detectar instalação existente ────────────────────────────────────────────
$InstallDir  = "$env:ProgramFiles\Ubuntu Desk"
$AppExe      = "$InstallDir\ubuntu-desk.exe"
$IsInstalled = Test-Path $AppExe

Write-Step "Ubuntu Desk — Deploy"
Write-Host "  Instalado:  $IsInstalled" -ForegroundColor Gray
Write-Host "  Diretório:  $InstallDir" -ForegroundColor Gray
Write-Host "  Servidor:   $(if ($ServerIP) { $ServerIP } else { '(não definido)' })" -ForegroundColor Gray
Write-Host "  Chave pub:  $(if ($PubKey) { $PubKey.Substring(0, [Math]::Min(12, $PubKey.Length)) + '...' } else { '(não definida)' })" -ForegroundColor Gray

# ── Modo ConfigOnly: apenas aplica configuração ──────────────────────────────
if ($ConfigOnly) {
    if (-not $IsInstalled) {
        Write-Fail "Ubuntu Desk não está instalado em '$InstallDir'. Use sem -ConfigOnly para instalar primeiro."
    }
    if (-not $ServerIP) {
        Write-Fail "-ServerIP é obrigatório no modo -ConfigOnly"
    }
    Write-Step "Aplicando configuração do servidor..."
    $configStr = "ubuntu-desk-host=$ServerIP"
    if ($PubKey) { $configStr += ",key=$PubKey" }
    if ($Api)    { $configStr += ",api=$Api" }
    & $AppExe --config "$configStr.exe"
    Write-OK "Configuração aplicada"
    exit 0
}

# ── Verificar se já está instalado (skip se não for -Force) ──────────────────
if ($IsInstalled -and -not $Force) {
    Write-Warn "Ubuntu Desk já está instalado. Use -Force para reinstalar."
    # Aplica config mesmo sem reinstalar
    if ($ServerIP) {
        Write-Step "Atualizando configuração do servidor..."
        $configStr = "ubuntu-desk-host=$ServerIP"
        if ($PubKey) { $configStr += ",key=$PubKey" }
        if ($Api)    { $configStr += ",api=$Api" }
        & $AppExe --config "$configStr.exe"
        Write-OK "Configuração atualizada"
    }
    exit 0
}

# ── Localizar instalador ──────────────────────────────────────────────────────
if (-not $InstallerPath) {
    # Tenta encontrar na mesma pasta do script ou em dist/
    $ScriptDir = Split-Path $MyInvocation.MyCommand.Path -Parent
    $candidates = @(
        (Join-Path (Split-Path $ScriptDir -Parent) "installer\Output\ubuntu-desk-setup.exe"),
        (Join-Path $ScriptDir "ubuntu-desk-setup.exe"),
        ".\ubuntu-desk-setup.exe"
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { $InstallerPath = $c; break }
    }
}

if (-not $InstallerPath -or -not (Test-Path $InstallerPath)) {
    Write-Fail "Instalador não encontrado. Use -InstallerPath para especificar o caminho."
}

Write-OK "Instalador: $InstallerPath"

# ── Montar argumentos do instalador ──────────────────────────────────────────
$setupArgs = @()

if ($Silent) {
    $setupArgs += "/VERYSILENT"
    $setupArgs += "/SUPPRESSMSGBOXES"
    $setupArgs += "/NORESTART"
    $setupArgs += "/CLOSEAPPLICATIONS"
}

if ($ServerIP) {
    $setupArgs += "/SERVER=$ServerIP"
}
if ($PubKey) {
    $setupArgs += "/KEY=$PubKey"
}
if ($Api) {
    $setupArgs += "/API=$Api"
}

# Marca tarefa de startup se solicitado
if ($Startup) {
    $setupArgs += "/TASKS=startup"
}

# ── Executar instalador ───────────────────────────────────────────────────────
Write-Step "Instalando Ubuntu Desk..."
Write-Host "  Argumentos: $($setupArgs -join ' ')" -ForegroundColor Gray

$proc = Start-Process -FilePath $InstallerPath -ArgumentList $setupArgs -Wait -PassThru
if ($proc.ExitCode -ne 0) {
    Write-Fail "Instalador retornou código $($proc.ExitCode)"
}

Write-OK "Instalação concluída"

# ── Verificar instalação ──────────────────────────────────────────────────────
if (-not (Test-Path $AppExe)) {
    Write-Warn "Executável não encontrado em '$AppExe'. Verifique o diretório de instalação."
} else {
    Write-OK "Executável verificado: $AppExe"
}

# ── Forçar startup via HKLM se -Startup (todos os usuários) ──────────────────
if ($Startup) {
    Write-Step "Configurando início automático (todos os usuários)..."
    $regKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
    Set-ItemProperty -Path $regKey -Name "Ubuntu Desk" -Value "`"$AppExe`"" -Force
    Write-OK "Chave HKLM Run configurada"
}

Write-Host ""
Write-Host "  ✅ Deploy concluído!" -ForegroundColor Green
if ($ServerIP) {
    Write-Host "  🌐 Servidor: $ServerIP" -ForegroundColor Cyan
}
Write-Host ""
