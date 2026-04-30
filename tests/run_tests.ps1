$ErrorActionPreference = "Stop"

function Resolve-Compiler {
    foreach ($c in @($env:SPEER_CC, $env:CC, 'gcc')) {
        if ([string]::IsNullOrWhiteSpace($c)) { continue }
        $cmd = Get-Command $c -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
        if (Test-Path -LiteralPath $c) { return $c }
    }
    foreach ($p in @(
            'C:\MinGW\bin\gcc.exe',
            'C:\msys64\mingw64\bin\gcc.exe',
            'C:\msys64\ucrt64\bin\gcc.exe'
        )) {
        if (Test-Path -LiteralPath $p) { return $p }
    }
    throw "No C compiler found. Install MinGW/MSYS2 gcc or set SPEER_CC or CC to gcc.exe"
}

$Cc = Resolve-Compiler
Write-Host "Using CC: $Cc"

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$isWindows = ($env:OS -eq 'Windows_NT')

$includes = @(
    "-Iinclude", "-Isrc",
    "-Isrc/util", "-Isrc/crypto", "-Isrc/wire", "-Isrc/infra",
    "-Isrc/libp2p", "-Isrc/transport", "-Isrc/tls", "-Isrc/quic", "-Isrc/relay", "-Isrc/discovery"
)

# Align with speer Makefile defaults (release-ish unit-test build)
$cflags = @(
    "-std=c99", "-O3", "-Wall", "-Wextra", "-Werror",
    "-fno-exceptions", "-fno-unwind-tables",
    "-ffunction-sections", "-fdata-sections",
    "-fvisibility=hidden",
    "-DNDEBUG",
    "-msse2", "-maes"
)
if ($isWindows) {
    $cflags += "-D_WIN32_WINNT=0x0600"
}

$linkLibs = @()
if ($isWindows) {
    $linkLibs = @("-lws2_32", "-liphlpapi", "-ladvapi32")
} else {
    $linkLibs = @("-lm")
}

# Clean
Remove-Item -Recurse -Force obj -ErrorAction SilentlyContinue
Remove-Item -Force libspeer.a -ErrorAction SilentlyContinue
Get-ChildItem tests -Filter *_check.exe -ErrorAction SilentlyContinue | Remove-Item -Force

$srcRoot = Join-Path (Get-Location) "src"
$sources = Get-ChildItem -Path src -Recurse -Filter *.c
$objs = @()
foreach ($src in $sources) {
    $rel = $src.FullName.Substring($srcRoot.Length).TrimStart('\')
    $objRel = ($rel -replace '\.c$', '.o')
    $obj = Join-Path "obj" $objRel
    $dir = Split-Path $obj
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory $dir -Force | Out-Null }
    $compileArgs = $cflags + $includes + @("-c", $src.FullName, "-o", $obj)
    & $Cc @compileArgs
    if ($LASTEXITCODE -ne 0) { throw "compile failed: $($src.FullName)" }
    $objs += $obj
}

& ar rcs libspeer.a @objs
if ($LASTEXITCODE -ne 0) { throw "ar failed" }

$ranlib = Get-Command ranlib -ErrorAction SilentlyContinue
if ($ranlib) {
    & ranlib libspeer.a
}

$checkSources = Get-ChildItem tests -Filter *_check.c
foreach ($t in $checkSources) {
    $exe = Join-Path "tests" (($t.BaseName) + ".exe")
    $linkArgs = $cflags + $includes + @($t.FullName, "libspeer.a", "-o", $exe) + $linkLibs
    & $Cc @linkArgs
    if ($LASTEXITCODE -ne 0) { throw "link failed: $($t.Name)" }
}

Write-Host ""
Write-Host "Running unit tests (*_check.exe only; integration_echo is not run)"
Write-Host ""

$failures = 0
foreach ($exe in (Get-ChildItem tests -Filter *_check.exe | Sort-Object Name)) {
    Write-Host "==> $($exe.Name)"
    & $exe.FullName
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAIL: $($exe.Name) (exit=$LASTEXITCODE)"
        $failures++
    }
}
if ($failures -gt 0) {
    Write-Host ""
    Write-Host "$failures test(s) FAILED"
    exit 1
}
Write-Host ""
Write-Host "all unit tests passed"
