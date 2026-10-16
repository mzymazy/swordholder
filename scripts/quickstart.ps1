#requires -version 5.1
<#
.SYNOPSIS
    Swordholder 30 秒离线闭环 Quick Start（Windows / PowerShell 5.1+）。

.DESCRIPTION
    四条命令、全部离线，无需 Ollama / 无需 GPU / 无需模型权重：
      1. 安装核心依赖（requirements.txt）
      2. 校验 4 份威慑凭证（ed25519 签名 + 信任锚 + 新鲜度）      -> 期望 4/4 VALID
      3. 验证器对抗自测（17 类伪造/篡改/换钥/降级/过期/无锚/重复键） -> 期望 17/17 PASS
      4. 评测记录 <-> 原始工件绑定审计（482 条记录三重核验）        -> 期望 482/482 bound

.PARAMETER SkipInstall
    跳过 pip 安装（依赖已就绪时使用，可缩短到数秒）。

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\quickstart.ps1
    powershell -ExecutionPolicy Bypass -File scripts\quickstart.ps1 -SkipInstall
#>
param([switch]$SkipInstall)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
Write-Host "== [0/4] 仓库根：$root" -ForegroundColor Cyan

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw "未找到 python：请先安装 Python 3.11+ 并加入 PATH"
}
$ver = (python -c "import sys;print(sys.version.split()[0])")
Write-Host "    Python $ver"

# ---------------------------------------------------------------- 1) 依赖
if ($SkipInstall) {
    Write-Host "== [1/4] 跳过依赖安装（-SkipInstall）" -ForegroundColor DarkGray
} else {
    Write-Host "== [1/4] 安装核心依赖（requirements.txt）" -ForegroundColor Cyan
    python -m pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) { throw "依赖安装失败（exit=$LASTEXITCODE）" }
}

# ------------------------------------------------- 2) 4 份凭证校验 -> VALID
Write-Host "== [2/4] 校验 4 份威慑凭证（期望全部 VALID）" -ForegroundColor Cyan
$proofs = @(
    "proofs\deterrence_proof_baseline_ed25519.yaml",
    "proofs\deterrence_proof_injected_ed25519.yaml",
    "proofs\deterrence_proof_lora_ed25519.yaml",
    "proofs\deterrence_proof_combined_ed25519.yaml"
)
foreach ($p in $proofs) {
    if (-not (Test-Path $p)) { throw "缺少凭证文件：$p" }
    $out = (python verify_proof.py $p --trusted-keys trusted_keys.json --max-age-days 365) -join "`n"
    if ($LASTEXITCODE -ne 0) { throw "凭证校验失败（exit=$LASTEXITCODE）：$p`n$out" }
    $last = ($out.Trim() -split "`n" | Select-Object -Last 1).Trim()
    Write-Host ("   {0,-46} {1}" -f (Split-Path -Leaf $p), $last)
    if ($last -notmatch "VALID$") { throw "凭证未判 VALID：$p" }
}
Write-Host "   凭证自检：4/4 VALID" -ForegroundColor Green

# ------------------------------------------------ 3) 验证器对抗自测 17/17
Write-Host "== [3/4] 验证器对抗自测（期望 17/17 PASS）" -ForegroundColor Cyan
python evidence/adversarial_verifier_test.py
if ($LASTEXITCODE -ne 0) { throw "对抗自测未全通过（exit=$LASTEXITCODE）" }

# ---------------------------------------------------- 4) 绑定审计 482/482
Write-Host "== [4/4] 评测记录 <-> 工件绑定审计（期望 482/482）" -ForegroundColor Cyan
python evidence/verify_artifact_binding.py
if ($LASTEXITCODE -ne 0) { throw "绑定审计未通过（exit=$LASTEXITCODE）" }

Write-Host ""
Write-Host "30 秒离线闭环全部通过：4/4 凭证 VALID、17/17 验证器断言、482/482 记录绑定。" -ForegroundColor Green
Write-Host "下一步：README「模型权重与复现」了解四态评测与 QLoRA 注入链；docs/proof-issuance.md 了解自签出证。" -ForegroundColor Green
