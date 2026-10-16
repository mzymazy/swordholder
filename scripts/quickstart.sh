#!/usr/bin/env bash
# Swordholder 30 秒离线闭环 Quick Start（Linux / macOS / Git Bash）
#
# 四条命令、全部离线，无需 Ollama / 无需 GPU / 无需模型权重：
#   1. 安装核心依赖（requirements.txt）
#   2. 校验 4 份威慑凭证（ed25519 签名 + 信任锚 + 新鲜度）        -> 期望 4/4 VALID
#   3. 验证器对抗自测（17 类伪造/篡改/换钥/降级/过期/无锚/重复键） -> 期望 17/17 PASS
#   4. 评测记录 <-> 原始工件绑定审计（482 条记录三重核验）         -> 期望 482/482 bound
#
# 用法：
#   bash scripts/quickstart.sh              # 含依赖安装
#   bash scripts/quickstart.sh --skip-install
set -euo pipefail

SKIP_INSTALL=0
[ "${1:-}" = "--skip-install" ] && SKIP_INSTALL=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"
cd "$ROOT"
echo "== [0/4] 仓库根：$ROOT"

PY="$(command -v python3 || command -v python)"
echo "    $("$PY" -c 'import sys;print("Python " + sys.version.split()[0])')"

if [ "$SKIP_INSTALL" = "1" ]; then
  echo "== [1/4] 跳过依赖安装（--skip-install）"
else
  echo "== [1/4] 安装核心依赖（requirements.txt）"
  "$PY" -m pip install -r requirements.txt
fi

echo "== [2/4] 校验 4 份威慑凭证（期望全部 VALID）"
for p in proofs/deterrence_proof_baseline_ed25519.yaml \
         proofs/deterrence_proof_injected_ed25519.yaml \
         proofs/deterrence_proof_lora_ed25519.yaml \
         proofs/deterrence_proof_combined_ed25519.yaml; do
  [ -f "$p" ] || { echo "缺少凭证文件：$p" >&2; exit 1; }
  last="$("$PY" verify_proof.py "$p" --trusted-keys trusted_keys.json --max-age-days 365 | tail -n 1)"
  echo "   $(basename "$p")  ->  $last"
  case "$last" in
    *VALID) ;;
    *) echo "凭证未判 VALID：$p" >&2; exit 1 ;;
  esac
done
echo "   凭证自检：4/4 VALID"

echo "== [3/4] 验证器对抗自测（期望 17/17 PASS）"
"$PY" evidence/adversarial_verifier_test.py

echo "== [4/4] 评测记录 <-> 工件绑定审计（期望 482/482）"
"$PY" evidence/verify_artifact_binding.py

echo
echo "30 秒离线闭环全部通过：4/4 凭证 VALID、17/17 验证器断言、482/482 记录绑定。"
echo "下一步：README「模型权重与复现」；docs/proof-issuance.md（自签出证与私钥说明）。"
