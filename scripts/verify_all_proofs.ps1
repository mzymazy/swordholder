# 逐份验证 proofs/ 下全部凭证（verify_proof.py 本身无 --all 参数，这里做循环封装）
# 用法：powershell -File scripts/verify_all_proofs.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    $proofs = Get-ChildItem -Path (Join-Path $root "proofs") -Filter *.yaml | Sort-Object Name
    if (-not $proofs) { Write-Output "NO_PROOFS"; exit 2 }
    $py = Join-Path $root ".venv\Scripts\python.exe"
    if (-not (Test-Path $py)) { $py = "python" }
    $bad = 0
    foreach ($p in $proofs) {
        $rel = "proofs/" + $p.Name
        $out = & $py verify_proof.py $rel 2>&1 | Out-String
        $line = ($out -split "`n" | Where-Object { $_ -match "VERDICT|VALID|INVALID" } | Select-Object -First 1)
        if ($out -notmatch "VALID" -or $out -match "INVALID") {
            $bad++
            Write-Output ("FAIL  {0} :: {1}" -f $rel, $line.Trim())
        } else {
            Write-Output ("OK    {0} :: {1}" -f $rel, $line.Trim())
        }
    }
    Write-Output ("TOTAL={0} FAILED={1}" -f $proofs.Count, $bad)
    if ($bad -gt 0) { exit 1 } else { exit 0 }
}
finally { Pop-Location }
