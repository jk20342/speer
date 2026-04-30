#!/usr/bin/env pwsh
# Build the speer static library, benchmarks and a few unit tests with
# clang -O3 -march=native. Targets x86_64-pc-windows-msvc, enables
# AVX2 / AES-NI / SHA-NI / PCLMUL fast paths.

param(
    [string]$Compiler = "clang",
    [switch]$Clean,
    [switch]$Run,
    [switch]$NoTests
)

$ErrorActionPreference = "Continue"
$PSNativeCommandUseErrorActionPreference = $false
Set-Location -LiteralPath $PSScriptRoot

$ROOT     = $PSScriptRoot
$OBJDIR   = Join-Path $ROOT "obj-bench"
$LIBNAME  = Join-Path $ROOT "libspeer-bench.a"
$BENCHDIR = Join-Path $ROOT "tests/benchmark"
$TESTDIR  = Join-Path $ROOT "tests"
$SRCDIR   = Join-Path $ROOT "src"
$INCDIR   = Join-Path $ROOT "include"
$SUBDIRS  = @("util", "crypto", "wire", "infra", "libp2p", "transport", "tls", "quic", "relay", "discovery")

if ($Clean) {
    if (Test-Path $OBJDIR) {
        $tmp = Join-Path $ROOT "_empty_clean_tmp"
        New-Item -ItemType Directory -Path $tmp -Force | Out-Null
        & robocopy.exe $tmp $OBJDIR /MIR /NFL /NDL /NJH /NJS /NC /NS 2>&1 | Out-Null
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
        Remove-Item -Recurse -Force $OBJDIR -ErrorAction SilentlyContinue
    }
    if (Test-Path $LIBNAME) { Remove-Item -Force $LIBNAME }
}

if (-not (Test-Path $OBJDIR)) { New-Item -ItemType Directory $OBJDIR | Out-Null }

$CFLAGS = @(
    "-std=c99",
    "-O3",
    "-march=native",
    "-mtune=native",
    "-fno-stack-protector",
    "-fno-strict-aliasing",
    "-DNDEBUG",
    "-D_WIN32_WINNT=0x0600",
    "-D_CRT_SECURE_NO_WARNINGS",
    "-D_WINSOCK_DEPRECATED_NO_WARNINGS",
    "-Wno-deprecated-declarations",
    "-Wno-implicit-function-declaration"
)

$INCLUDES = @("-I$INCDIR", "-I$SRCDIR")
foreach ($d in $SUBDIRS) { $INCLUDES += "-I$SRCDIR/$d" }

# Collect source files
$sources = @()
$sources += Get-ChildItem -Path $SRCDIR -Filter "*.c" -File
foreach ($d in $SUBDIRS) {
    $p = Join-Path $SRCDIR $d
    if (Test-Path $p) {
        $sources += Get-ChildItem -Path $p -Filter "*.c" -File
    }
}

$objects = @()
$built = 0
foreach ($src in $sources) {
    $relUnderSrc = $src.FullName.Substring($SRCDIR.Length).TrimStart('\','/').Replace('\','/')
    $objpath = (Join-Path $OBJDIR ($relUnderSrc -replace '\.c$', '.o')).Replace('\','/')
    $objdir  = Split-Path $objpath -Parent
    if (-not (Test-Path $objdir)) { New-Item -ItemType Directory $objdir -Force | Out-Null }

    if ((Test-Path $objpath) -and ((Get-Item $objpath).LastWriteTime -gt $src.LastWriteTime)) {
        $objects += $objpath
        continue
    }

    $args = @($CFLAGS) + $INCLUDES + @("-c", $src.FullName, "-o", $objpath)
    & $Compiler @args
    if ($LASTEXITCODE -ne 0) { Write-Error "compile failed: $($src.FullName)"; exit 1 }
    $objects += $objpath
    $built++
}
Write-Host "Compiled $built / $($sources.Count) source files"

# Static library
& llvm-ar rcs $LIBNAME @objects
if ($LASTEXITCODE -ne 0) { Write-Error "ar failed"; exit 1 }
Write-Host "Built $LIBNAME"

# Benchmarks
$benchExes = @()
$benches = @("bench_crypto", "bench_wire", "bench_protocol", "bench_throughput")
foreach ($b in $benches) {
    $exe = Join-Path $BENCHDIR "$b.exe"
    $args = @($CFLAGS) + $INCLUDES + @(
        (Join-Path $BENCHDIR "$b.c"), $LIBNAME,
        "-lws2_32", "-liphlpapi", "-ladvapi32", "-lbcrypt",
        "-o", $exe
    )
    & $Compiler @args
    if ($LASTEXITCODE -ne 0) { Write-Error "link failed: $b"; exit 1 }
    $benchExes += $exe
}
Write-Host "Built benchmarks: $($benchExes.Count)"

# Unit tests: every .c file directly under tests/ with a main()
$testExes = @()
$testFailedBuild = @()
if (-not $NoTests) {
    $unitSources = [System.IO.Directory]::GetFiles($TESTDIR, "*.c") | Sort-Object
    foreach ($src in $unitSources) {
        $name = [System.IO.Path]::GetFileNameWithoutExtension($src)
        $exe = Join-Path $TESTDIR "$name.exe"
        $args = @($CFLAGS) + $INCLUDES + @(
            $src, $LIBNAME,
            "-lws2_32", "-liphlpapi", "-ladvapi32", "-lbcrypt",
            "-o", $exe
        )
        & $Compiler @args 2>$null
        if ($LASTEXITCODE -ne 0) { $testFailedBuild += $name; continue }
        $testExes += $exe
    }
    Write-Host "Built unit tests: $($testExes.Count) (build-failed: $($testFailedBuild.Count))"
    if ($testFailedBuild.Count -gt 0) {
        Write-Host "  failed to build: $($testFailedBuild -join ', ')" -ForegroundColor DarkYellow
    }
}

# Fuzz harnesses: each LLVMFuzzerTestOneInput target with built-in main()
$fuzzExes = @()
$fuzzFailedBuild = @()
$FUZZDIR = Join-Path $ROOT "tests/fuzz"
if ((-not $NoTests) -and (Test-Path $FUZZDIR)) {
    $fuzzSources = [System.IO.Directory]::GetFiles($FUZZDIR, "*.c") | Sort-Object
    foreach ($src in $fuzzSources) {
        $name = [System.IO.Path]::GetFileNameWithoutExtension($src)
        $exe = Join-Path $FUZZDIR "$name.exe"
        $args = @($CFLAGS) + $INCLUDES + @(
            $src, $LIBNAME,
            "-lws2_32", "-liphlpapi", "-ladvapi32", "-lbcrypt",
            "-o", $exe
        )
        & $Compiler @args 2>$null
        if ($LASTEXITCODE -ne 0) { $fuzzFailedBuild += $name; continue }
        $fuzzExes += $exe
    }
    Write-Host "Built fuzz harnesses: $($fuzzExes.Count) (build-failed: $($fuzzFailedBuild.Count))"
    if ($fuzzFailedBuild.Count -gt 0) {
        Write-Host "  failed to build: $($fuzzFailedBuild -join ', ')" -ForegroundColor DarkYellow
    }
}

if ($Run) {
    if ($testExes.Count -gt 0) {
        Write-Host "`n=== Running Unit Tests ($($testExes.Count)) ==="
        $passed = 0; $failed = @()
        foreach ($exe in $testExes) {
            $name = Split-Path $exe -Leaf
            $out = & $exe 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Host "  FAIL  $name (exit $LASTEXITCODE)" -ForegroundColor Red
                $failed += $name
            } else {
                $passed++
            }
        }
        Write-Host "Unit tests: $passed passed, $($failed.Count) failed"
        if ($failed.Count -gt 0) {
            Write-Host "  failed: $($failed -join ', ')" -ForegroundColor Red
        }
    }

    if ($fuzzExes.Count -gt 0) {
        Write-Host "`n=== Running Fuzz Harness Smoke Tests ($($fuzzExes.Count)) ==="
        $passed = 0; $failed = @()
        foreach ($exe in $fuzzExes) {
            $name = Split-Path $exe -Leaf
            $out = & $exe 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Host "  FAIL  $name (exit $LASTEXITCODE)" -ForegroundColor Red
                $failed += $name
            } else {
                $passed++
            }
        }
        Write-Host "Fuzz smoke: $passed passed, $($failed.Count) failed"
        if ($failed.Count -gt 0) {
            Write-Host "  failed: $($failed -join ', ')" -ForegroundColor Red
        }
    }

    Write-Host "`n=== Running Benchmarks ==="
    foreach ($exe in $benchExes) {
        Write-Host "`n--- $(Split-Path $exe -Leaf) ---"
        & $exe
    }
}
