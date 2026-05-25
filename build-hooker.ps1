# build-hooker.ps1 - Compile HookerBridge.java -> hooker.dex and push to device
# Usage:
#   .\build-hooker.ps1            # compile and push
#   .\build-hooker.ps1 -NoPush    # compile only

param([switch]$NoPush)

$ErrorActionPreference = "Stop"

$ScriptDir  = $PSScriptRoot
$JavaSrc    = "$ScriptDir\app\src\main\java\com\pecker\payload\HookerBridge.java"
$OutDir     = "$ScriptDir\build\hooker"

# ---- locate ANDROID_HOME ----
$AndroidHome = $env:ANDROID_HOME
if (-not $AndroidHome) { $AndroidHome = "$env:LOCALAPPDATA\Android\Sdk" }
if (-not (Test-Path $AndroidHome)) {
    Write-Error "ANDROID_HOME not found: $AndroidHome"
    exit 1
}

# ---- locate android.jar ----
$AndroidJar = $null
# try android-35 first, then scan all installed platforms
foreach ($api in @("android-35","android-34","android-33","android-32","android-31")) {
    $candidate = "$AndroidHome\platforms\$api\android.jar"
    if (Test-Path $candidate) { $AndroidJar = $candidate; break }
}
if (-not $AndroidJar) {
    $AndroidJar = Get-ChildItem "$AndroidHome\platforms" -Filter "android.jar" -Recurse -ErrorAction SilentlyContinue |
                  Sort-Object FullName | Select-Object -Last 1 -ExpandProperty FullName
}
if (-not $AndroidJar) {
    Write-Error "android.jar not found under $AndroidHome\platforms\ - please install an Android SDK Platform"
    exit 1
}
Write-Host "android.jar : $AndroidJar"

# ---- locate d8.bat ----
# First try cmdline-tools (no separate build-tools needed), then build-tools fallback
$D8 = $null
$cmdlineD8 = "$AndroidHome\cmdline-tools\bin\d8.bat"
if (Test-Path $cmdlineD8) {
    $D8 = $cmdlineD8
} else {
    $D8 = Get-ChildItem "$AndroidHome\build-tools" -Filter "d8.bat" -Recurse -ErrorAction SilentlyContinue |
          Sort-Object FullName | Select-Object -Last 1 -ExpandProperty FullName
}
if (-not $D8) {
    Write-Error "d8.bat not found - please install Android Build Tools or Command Line Tools"
    exit 1
}
Write-Host "d8          : $D8"

# ---- Step 1: javac ----
Write-Host "[1/3] javac  HookerBridge.java"
$ClassesDir = "$OutDir\classes"
New-Item -ItemType Directory -Force $ClassesDir | Out-Null
# Locate javac: prefer explicit local JDK, then JAVA_HOME, then PATH
$LocalJdk = if (Test-Path "D:\develop\tools\jdk-21.0.11+10\bin\javac.exe") { "D:\develop\tools\jdk-21.0.11+10" } else { "D:\develop\tools\jdk-25.0.2+10" }
$Javac = if (Test-Path "$LocalJdk\bin\javac.exe") { "$LocalJdk\bin\javac.exe" }
         elseif ($env:JAVA_HOME) { "$env:JAVA_HOME\bin\javac.exe" }
         else { "javac" }
# Ensure JAVA_HOME is set for d8 (which calls java internally)
if (-not $env:JAVA_HOME) { $env:JAVA_HOME = $LocalJdk }
& $Javac --release 11 -classpath $AndroidJar -d $ClassesDir $JavaSrc
if ($LASTEXITCODE -ne 0) { Write-Error "javac failed"; exit 1 }

# ---- Step 2: d8 ----
Write-Host "[2/3] d8  ->  hooker.dex"
$DexDir = "$OutDir\dex"
New-Item -ItemType Directory -Force $DexDir | Out-Null
# Pack .class files into a jar first to avoid Windows path issues with d8
$JdkBin = Split-Path $Javac
$Jar = "$JdkBin\jar.exe"
$ClassesJar = "$OutDir\classes.jar"
& $Jar cf $ClassesJar -C $ClassesDir .
if ($LASTEXITCODE -ne 0) { Write-Error "jar failed"; exit 1 }
& $D8 --min-api 21 --output $DexDir --lib $AndroidJar $ClassesJar
if ($LASTEXITCODE -ne 0) { Write-Error "d8 failed"; exit 1 }

Copy-Item "$DexDir\classes.dex" "$OutDir\hooker.dex" -Force
$Size = (Get-Item "$OutDir\hooker.dex").Length
Write-Host "output      : $OutDir\hooker.dex ($Size bytes)"

if ($NoPush) {
    Write-Host "[3/3] skipped push (-NoPush)"
    exit 0
}

# ---- Step 3: adb push ----
Write-Host "[3/3] adb push  ->  /data/local/tmp/hooker.dex"
& adb push "$OutDir\hooker.dex" /data/local/tmp/hooker.dex
if ($LASTEXITCODE -ne 0) { Write-Error "adb push failed"; exit 1 }
# Android 10+ blocks DEX loading from world-writable files; set to 644
& adb shell chmod 644 /data/local/tmp/hooker.dex

Write-Host "done. Restart the target app to activate hooks."
