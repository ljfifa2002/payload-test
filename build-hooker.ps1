# build-hooker.ps1 — 编译 HookerBridge.java -> hooker.dex 并推送到设备
# 用法:
#   .\build-hooker.ps1            # 编译并推送
#   .\build-hooker.ps1 -NoPush    # 只编译，不推送

param([switch]$NoPush)

$ErrorActionPreference = "Stop"

$ScriptDir  = $PSScriptRoot
$JavaSrc    = "$ScriptDir\app\src\main\java\com\pecker\payload\HookerBridge.java"
$OutDir     = "$ScriptDir\build\hooker"

# ---- 查找 ANDROID_HOME ----
$AndroidHome = $env:ANDROID_HOME
if (-not $AndroidHome) { $AndroidHome = "$env:LOCALAPPDATA\Android\Sdk" }
if (-not (Test-Path $AndroidHome)) {
    Write-Error "ANDROID_HOME 未设置或路径不存在: $AndroidHome"
    exit 1
}

# ---- 查找 android.jar ----
$AndroidJar = "$AndroidHome\platforms\android-35\android.jar"
if (-not (Test-Path $AndroidJar)) {
    $AndroidJar = Get-ChildItem "$AndroidHome\platforms" -Filter "android.jar" -Recurse |
                  Sort-Object FullName | Select-Object -Last 1 -ExpandProperty FullName
}
if (-not $AndroidJar) {
    Write-Error "android.jar 未找到，请确认已安装 Android SDK Platform"
    exit 1
}

# ---- 查找 d8.bat ----
$D8 = Get-ChildItem "$AndroidHome\build-tools" -Filter "d8.bat" -Recurse |
      Sort-Object FullName | Select-Object -Last 1 -ExpandProperty FullName
if (-not $D8) {
    Write-Error "d8.bat 未找到，请确认已安装 Android Build Tools"
    exit 1
}

Write-Host "[1/3] javac  HookerBridge.java"
$ClassesDir = "$OutDir\classes"
New-Item -ItemType Directory -Force $ClassesDir | Out-Null
& javac -source 11 -target 11 -bootclasspath $AndroidJar -d $ClassesDir $JavaSrc
if ($LASTEXITCODE -ne 0) { Write-Error "javac 失败"; exit 1 }

Write-Host "[2/3] d8  ->  hooker.dex"
$DexDir = "$OutDir\dex"
New-Item -ItemType Directory -Force $DexDir | Out-Null
$Classes = (Get-ChildItem $ClassesDir -Filter "*.class" -Recurse).FullName
& $D8 --min-api 21 --output $DexDir --lib $AndroidJar @Classes
if ($LASTEXITCODE -ne 0) { Write-Error "d8 失败"; exit 1 }

Copy-Item "$DexDir\classes.dex" "$OutDir\hooker.dex" -Force
$Size = (Get-Item "$OutDir\hooker.dex").Length
Write-Host "      output: $OutDir\hooker.dex ($Size bytes)"

if ($NoPush) {
    Write-Host "[3/3] skip push"
    exit 0
}

Write-Host "[3/3] adb push  ->  /data/local/tmp/hooker.dex"
& adb push "$OutDir\hooker.dex" /data/local/tmp/hooker.dex
if ($LASTEXITCODE -ne 0) { Write-Error "adb push 失败"; exit 1 }

Write-Host "done. 重启 smzdm App 即可生效。"
