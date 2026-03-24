# Ubuntu Desk — Build Script Windows
# Gera o executável Flutter + instalador MSI/EXE
# Uso: .\build\build_windows.ps1 [-Release] [-SkipCargo] [-Installer]
# Requer: Rust, Flutter em C:\flutter, vcpkg em C:\vcpkg, VS Build Tools 2022

param(
    [switch]$Release   = $true,
    [switch]$SkipCargo = $false,
    [switch]$Installer = $false
)

$ErrorActionPreference = "Stop"
$Root      = Split-Path $PSScriptRoot -Parent
$ClientDir = Join-Path $Root "client"
$DistDir   = Join-Path $Root "dist\windows"

function Write-Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-OK($msg)   { Write-Host "    [OK] $msg" -ForegroundColor Green }
function Write-Fail($msg) { Write-Host "    [ERRO] $msg" -ForegroundColor Red; exit 1 }

# ─── 1. Verificar dependências ───────────────────────────────────────────────
Write-Step "Verificando dependências..."

$rustc   = "$env:USERPROFILE\.cargo\bin\rustc.exe"
$cargo   = "$env:USERPROFILE\.cargo\bin\cargo.exe"
$flutter = "C:\flutter\bin\flutter.bat"
$vcpkg   = "C:\vcpkg\vcpkg.exe"
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
$python  = if ($pythonCmd) { $pythonCmd.Source } else { $null }

if (-not (Test-Path $rustc))   { Write-Fail "Rust não encontrado. Execute setup-deps.ps1" }
if (-not (Test-Path $flutter)) { Write-Fail "Flutter não encontrado em C:\flutter. Execute setup-deps.ps1" }
if (-not (Test-Path $vcpkg))   { Write-Fail "vcpkg não encontrado em C:\vcpkg. Execute setup-deps.ps1" }
if (-not $python)              { Write-Fail "Python não encontrado no PATH" }

Write-OK "rustc   $( & $rustc --version)"
Write-OK "flutter $( & $flutter --version --machine 2>$null | ConvertFrom-Json | Select-Object -ExpandProperty frameworkVersion 2>$null )"
Write-OK "python  $( & $python --version)"
Write-OK "vcpkg   OK"

# ─── 2. Configurar variáveis de ambiente ────────────────────────────────────
Write-Step "Configurando ambiente..."

$env:VCPKG_ROOT = "C:\vcpkg"
$env:PATH       = "$env:USERPROFILE\.cargo\bin;C:\flutter\bin;C:\vcpkg;$env:PATH"
$env:RUSTFLAGS  = ""

Write-OK "VCPKG_ROOT = $env:VCPKG_ROOT"

# ─── 3. Verificar pacotes vcpkg ─────────────────────────────────────────────
Write-Step "Verificando pacotes vcpkg..."

$required = @("libvpx:x64-windows-static", "libyuv:x64-windows-static", "opus:x64-windows-static", "aom:x64-windows-static")
$vcpkgInstalled = & $vcpkg list 2>$null  # chamada única — evita 4 subprocessos sequenciais
foreach ($pkg in $required) {
    $name = $pkg.Split(":")[0]
    if (-not ($vcpkgInstalled | Select-String $name)) {
        Write-Host "    Instalando $pkg..." -ForegroundColor Yellow
        & $vcpkg install $pkg
    } else {
        Write-OK "$pkg"
    }
}

# ─── 4. Build Flutter ───────────────────────────────────────────────────────
Write-Step "Build Flutter ($( if ($Release) { 'release' } else { 'debug' } ))..."

Set-Location $ClientDir

$buildArgs = @("--flutter")
# build.py always builds in release when --flutter is used on Windows (no --release flag in build.py)
if ($SkipCargo) { $buildArgs += "--skip-cargo" }

& $python build.py @buildArgs
if ($LASTEXITCODE -ne 0) { Write-Fail "build.py falhou (exit $LASTEXITCODE)" }

Write-OK "Build concluído"

# ─── 5. Copiar artefatos para dist/ ─────────────────────────────────────────
Write-Step "Copiando artefatos para dist\windows..."

$FlutterOut = Join-Path $ClientDir "flutter\build\windows\x64\runner\Release"
if (-not (Test-Path $FlutterOut)) {
    Write-Fail "Diretório de saída não encontrado: $FlutterOut"
}

if (Test-Path $DistDir) { Remove-Item $DistDir -Recurse -Force }
New-Item -ItemType Directory -Path $DistDir | Out-Null
Copy-Item "$FlutterOut\*" $DistDir -Recurse

# Fallback: renomear se o executável ainda sair com o nome antigo
$srcExe  = Join-Path $DistDir "rustdesk.exe"
$destExe = Join-Path $DistDir "ubuntu-desk.exe"
if (Test-Path $srcExe) { Rename-Item $srcExe $destExe }

# Copiar ícone
Copy-Item (Join-Path $ClientDir "res\icon.ico") $DistDir -Force

# Copiar dylib_virtual_display.dll e data/ do build Rust (não incluídos no output Flutter)
# Esses arquivos ficam em target\release\ e são necessários para o virtual display funcionar
$CargoReleaseDir = Join-Path $ClientDir "target\release"
$DylibSrc        = Join-Path $CargoReleaseDir "dylib_virtual_display.dll"
$DataSrc         = Join-Path $CargoReleaseDir "data"

if (Test-Path $DylibSrc) {
    Copy-Item $DylibSrc $DistDir -Force
    Write-OK "dylib_virtual_display.dll copiada"
} else {
    Write-Host "    [AVISO] dylib_virtual_display.dll não encontrada em $CargoReleaseDir" -ForegroundColor Yellow
}

if (Test-Path $DataSrc) {
    Copy-Item $DataSrc $DistDir -Recurse -Force
    Write-OK "Pasta data/ copiada"
} else {
    Write-Host "    [AVISO] Pasta data/ não encontrada em $CargoReleaseDir" -ForegroundColor Yellow
}

Write-OK "Artefatos em: $DistDir"

# ─── 6. Gerar instalador (opcional) ─────────────────────────────────────────
if ($Installer) {
    Write-Step "Gerando instalador..."

    $isccCmd = Get-Command iscc -ErrorAction SilentlyContinue
    $iscc = if ($isccCmd) { $isccCmd.Source } else { $null }
    if (-not $iscc) {
        $candidates = @(
            "C:\Program Files (x86)\Inno Setup 6\iscc.exe",
            "C:\Program Files\Inno Setup 6\iscc.exe",
            "$env:LOCALAPPDATA\Programs\Inno Setup 6\iscc.exe"
        )
        foreach ($c in $candidates) { if (Test-Path $c) { $iscc = $c; break } }
    }

    $issFile = Join-Path $Root "installer\ubuntu-desk.iss"

    if (-not (Test-Path $iscc)) {
        Write-Host "    [AVISO] Inno Setup não encontrado. Pule -Installer ou instale em C:\Program Files (x86)\Inno Setup 6" -ForegroundColor Yellow
    } elseif (-not (Test-Path $issFile)) {
        Write-Host "    [AVISO] installer\ubuntu-desk.iss não encontrado" -ForegroundColor Yellow
    } else {
        & $iscc $issFile
        if ($LASTEXITCODE -eq 0) {
            Write-OK "Instalador gerado em installer\Output\"
        } else {
            Write-Fail "iscc falhou (exit $LASTEXITCODE)"
        }
    }
}

# ─── 7. Resumo ───────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ✅ Ubuntu Desk build concluído!" -ForegroundColor Green
Write-Host "  📁 Saída: $DistDir" -ForegroundColor Cyan
Write-Host "  🚀 Executável: ubuntu-desk.exe" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Próximo passo: .\build\build_windows.ps1 -Installer (requer Inno Setup)" -ForegroundColor Gray
