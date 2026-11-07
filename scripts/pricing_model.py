"""定价与单位经济模型：用公开竞品单价做锚，算清"能收多少、成本多少、毛利多少"。

方法
----
不做拍脑袋定价。全部用**公开可核验的单价**做锚，把本项目的能力折算到同一计价单位上：

1. **锚点**取公开报价：AI 告警调查（Dropzone AI）、人力分诊成本（SANS/时薪换算）、
   不可篡改审计日志 SaaS（AuditKit / Immutable）、云审计事件（AWS CloudTrail）、
   SIEM 摄取（Sentinel / Sumo / Elastic）、GRC 平台（Drata / Vanta）。
2. **单位经济**用本仓库实测耗时（seal 0.54 ms / verify 4.91 ms，来自
   `examples/minimal_integration.py` 的 30 次迭代中位数）换算云算力成本。
3. **档位**按"每张凭证 = 一条被追责的结论"计价，而不是按日志条数或席位——这是定位
   决定的计价口径差异，也是唯一能跟上述锚点直接对比的地方。

诚实的边界
----------
本模型给出的是**成本下限 + 竞品锚定的价格带**，不是需求验证。截至本阶段：无付费用户、
无试点、无报价成交、无第三方复现。价格带只能说明"报价不违反市场常识"，不能说明
"有人会买"。所有假设写在 assumptions 里，改一个数就能重算。

用法
----
    python scripts/pricing_model.py --out-dir evidence/stage4_pricing
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import statistics

# ---------------------------------------------------------------- 公开锚点
# 单位统一折算为 USD；折算过程写在 derived 里，便于复核
ANCHORS = [
    {
        "id": "dropzone_investigation",
        "vendor": "Dropzone AI",
        "what": "AI 告警调查（Standard 档）",
        "public_price": "$36,000 / 年，含 4,000 次完整调查",
        "per_unit_usd": 9.0,
        "unit": "每次调查",
        "derived": "36000 / 4000 = 9.00",
        "source": "dropzone.ai 官方定价页（2025）；第三方目录同载 $36K/yr for 4,000 investigations",
    },
    {
        "id": "dropzone_entry",
        "vendor": "Dropzone AI",
        "what": "入门档",
        "public_price": "$500 / 月",
        "per_unit_usd": 6000.0,
        "unit": "每年",
        "derived": "500 × 12 = 6000",
        "source": "官方定价页 Standard Plan $500/month",
    },
    {
        "id": "human_triage_tp",
        "vendor": "人力分诊（SANS 2025 SOC Survey 假设）",
        "what": "Tier-1 分析师分诊一条真阳性告警",
        "public_price": "年薪 $120K × 1.35 福利 = $162K，时薪 ≈ $78，20 分钟",
        "per_unit_usd": 26.0,
        "unit": "每条告警",
        "derived": "78 / 60 × 20 = 26.00",
        "source": "SANS 2025 SOC Survey（误报率 65–80%、单告警 12–20 分钟）+ 时薪模型",
    },
    {
        "id": "human_triage_fp",
        "vendor": "人力分诊（同上）",
        "what": "分诊一条误报",
        "public_price": "同上，15 分钟",
        "per_unit_usd": 19.5,
        "unit": "每条告警",
        "derived": "78 / 60 × 15 = 19.50",
        "source": "同上",
    },
    {
        "id": "auditkit_business",
        "vendor": "AuditKit",
        "what": "不可篡改审计日志（Business）",
        "public_price": "$99 / 月，500K 事件",
        "per_unit_usd": 0.000198,
        "unit": "每事件",
        "derived": "99 × 12 / (500000 × 12) = 1.98e-4",
        "source": "AuditKit 公开定价（SHA-256 哈希链 + Merkle 证明）",
    },
    {
        "id": "immutable_pro",
        "vendor": "getimmutable.dev",
        "what": "不可篡改审计日志（Pro）",
        "public_price": "$49 / 月，1M 事件",
        "per_unit_usd": 0.000049,
        "unit": "每事件",
        "derived": "49 × 12 / (1000000 × 12) = 4.9e-5",
        "source": "getimmutable.dev 公开定价；超限 $2/10 万事件",
    },
    {
        "id": "cloudtrail_copy",
        "vendor": "AWS CloudTrail",
        "what": "额外管理事件副本",
        "public_price": "$2.00 / 10 万事件",
        "per_unit_usd": 0.00002,
        "unit": "每事件",
        "derived": "2.00 / 100000 = 2e-5",
        "source": "AWS CloudTrail 官方定价（Log File Integrity Validation 免费）",
    },
    {
        "id": "siem_elastic_low",
        "vendor": "Elastic Security Serverless",
        "what": "SIEM 摄取（公开下限）",
        "public_price": "$0.09–$0.11 / GB",
        "per_unit_usd": 0.09,
        "unit": "每 GB",
        "derived": "取区间下限 0.09",
        "source": "Elastic 官方定价（2025-11-01 生效）",
    },
    {
        "id": "siem_sentinel",
        "vendor": "Microsoft Sentinel",
        "what": "SIEM 摄取（PAYG）",
        "public_price": "~$4.30 / GB（承诺层 $2.96）",
        "per_unit_usd": 4.30,
        "unit": "每 GB",
        "derived": "PAYG 列表价",
        "source": "Microsoft Sentinel 官方定价",
    },
    {
        "id": "grc_drata_vanta",
        "vendor": "Drata / Vanta",
        "what": "GRC 平台（含证据收集）",
        "public_price": "$5,000–$15,000+ / 年",
        "per_unit_usd": 10000.0,
        "unit": "每年",
        "derived": "取区间中位 10,000",
        "source": "公开交易基准 / TrustRadius 价目区间",
    },
]

# ---------------------------------------------------------------- 档位设计
TIERS = [
    {
        "name": "OSS 自托管",
        "price_usd_year": 0,
        "included_seals": None,
        "overage_per_seal_usd": 0.0,
        "note": "Apache-2.0，无支持 SLA；获客漏斗与可复算底座，不贡献收入",
    },
    {
        "name": "Starter",
        "price_usd_year": 1200,
        "included_seals": 50_000,
        "overage_per_seal_usd": 0.012,
        "note": "对齐 AuditKit Business（$99/月 ≈ $1,188/年）这一档的年度预算，避免入门价被读成'贵 4 倍'",
    },
    {
        "name": "Team",
        "price_usd_year": 4800,
        "included_seals": 200_000,
        "overage_per_seal_usd": 0.01,
        "note": "以 20 万条被追责结论/年为量级；≈ 1 个 Auditing 工时包的预算",
    },
    {
        "name": "Business",
        "price_usd_year": 24000,
        "included_seals": 2_000_000,
        "overage_per_seal_usd": 0.006,
        "note": "对齐 Sentinel 100GB 承诺档 / 中小 SOC 的年度工具预算区间",
    },
    {
        "name": "Enterprise",
        "price_usd_year": 72000,
        "included_seals": 10_000_000,
        "overage_per_seal_usd": 0.004,
        "note": "含 HSM/KMS 托管、密钥轮换演练、可审计部署评审；仍低于 Dropzone 4 千次调查的 2 倍",
    },
]

# ---------------------------------------------------------------- 单位经济
COST = {
    "seal_ms": 0.538,          # 实测中位数（本机，单进程）
    "verify_ms": 4.911,        # 实测中位数（含 schema 校验 + Ed25519 验签 + 信任锚判定）
    "verifications_per_seal": 3,   # 假设：签发方自检 1 次 + 审计方 1 次 + 争议时 1 次
    "vcpu_hour_usd": 0.042,    # 通用云 vCPU 小时价（按需档，量级参考）
    "seal_bytes": 2048,        # 凭证 JSON 体积量级
    "storage_gb_month_usd": 0.023,  # 对象存储标准档
    "retention_months": 12,
}


def unit_economics() -> dict:
    cycle_ms = COST["seal_ms"] + COST["verify_ms"] * COST["verifications_per_seal"]
    compute_usd = (cycle_ms / 1000.0) / 3600.0 * COST["vcpu_hour_usd"]
    storage_gb = COST["seal_bytes"] / (1024 ** 3)
    storage_usd = storage_gb * COST["storage_gb_month_usd"] * COST["retention_months"]
    per_seal = compute_usd + storage_usd
    return {
        "cycle_ms_per_seal": round(cycle_ms, 3),
        "compute_usd_per_seal": compute_usd,
        "storage_usd_per_seal_12mo": storage_usd,
        "marginal_usd_per_seal": per_seal,
        "seals_per_vcpu_hour": int(3_600_000 / cycle_ms),
        "note": ("只含算力与存储的边际成本；不含人力维护、支持、密钥托管、合规审计。"
                 "据此得出的毛利率是上限，不是财务预测。"),
    }


def tiers_table(ue: dict) -> list[dict]:
    rows = []
    marginal = ue["marginal_usd_per_seal"]
    for t in TIERS:
        included = t["included_seals"]
        if not included:
            rows.append({
                "tier": t["name"], "price_usd_year": 0, "included_seals": "",
                "implied_usd_per_seal": "", "overage_usd_per_seal": "",
                "vs_dropzone_per_investigation": "", "vs_auditkit_per_event": "",
                "gross_margin_pct": "", "note": t["note"],
            })
            continue
        per_seal = t["price_usd_year"] / included
        rows.append({
            "tier": t["name"],
            "price_usd_year": t["price_usd_year"],
            "included_seals": included,
            "implied_usd_per_seal": f"{per_seal:.8f}",
            "overage_usd_per_seal": t["overage_per_seal_usd"],
            "vs_dropzone_per_investigation": f"{per_seal / 9.0 * 100:.4f}%",
            "vs_auditkit_per_event": f"{per_seal / 0.000198:.1f}x",
            "gross_margin_pct": f"{(1 - marginal / per_seal) * 100:.4f}",
            "note": t["note"],
        })
    return rows


def sensitivity(ue: dict) -> list[dict]:
    """验签次数与档位变化对单价、毛利的影响。"""
    out = []
    for verifies in (1, 3, 10):
        cycle = COST["seal_ms"] + COST["verify_ms"] * verifies
        cost = (cycle / 1000.0) / 3600.0 * COST["vcpu_hour_usd"] + ue["storage_usd_per_seal_12mo"]
        for t in TIERS[1:]:
            per_seal = t["price_usd_year"] / t["included_seals"]
            out.append({
                "verifications_per_seal": verifies,
                "tier": t["name"],
                "implied_usd_per_seal": f"{per_seal:.8f}",
                "cost_usd_per_seal": f"{cost:.10f}",
                "gross_margin_pct": f"{(1 - cost / per_seal) * 100:.4f}",
                "headroom_x": f"{per_seal / cost:.0f}",
            })
    return out


def value_bridge() -> dict:
    """把"每条被追责结论"的价格折算到客户已有的计价口径上。"""
    dropzone = 9.0
    human_tp = 26.0
    out = {}
    for t in TIERS[1:]:
        per_seal = t["price_usd_year"] / t["included_seals"]
        out[t["name"]] = {
            "usd_per_seal": round(per_seal, 8),
            "as_pct_of_ai_investigation_9usd": round(per_seal / dropzone * 100, 4),
            "as_pct_of_human_triage_26usd": round(per_seal / human_tp * 100, 4),
            "seals_per_9usd_of_budget": int(dropzone / per_seal),
        }
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="swordholder 定价与单位经济模型")
    ap.add_argument("--out-dir", default=os.path.join("evidence", "stage4_pricing"))
    args = ap.parse_args(argv)
    os.makedirs(args.out_dir, exist_ok=True)

    ue = unit_economics()
    rows = tiers_table(ue)
    sens = sensitivity(ue)
    bridge = value_bridge()

    model = {
        "tool": "swordholder.pricing_model",
        "currency": "USD",
        "pricing_unit": "每张被追责结论的凭证（seal），非日志条数、非席位",
        "measured_inputs": {
            "seal_ms_median": COST["seal_ms"],
            "verify_ms_median": COST["verify_ms"],
            "source": "examples/minimal_integration.py --bench-iterations 30（隔离安装环境）",
        },
        "assumptions": COST,
        "unit_economics": ue,
        "anchors": ANCHORS,
        "tiers": rows,
        "value_bridge": bridge,
        "sensitivity": sens,
        "honest_limits": [
            "无付费用户、无试点、无成交、无第三方复现：价格带是竞品锚定的推演，不是需求验证。",
            "算力成本按通用云 vCPU 小时价估算，未计入人力维护、支持、密钥托管与合规审计成本。",
            "锚点均为公开列表价/第三方基准，实际合同价可低 40–70%，因此这里的相对倍数应视为上限。",
            "不计入'避免一次事故'的期望损失：S2/S3 已证明本项目不提供检测能力，不能把事故避免计入本方价值。",
        ],
    }

    with open(os.path.join(args.out_dir, "pricing_model.json"), "w", encoding="utf-8") as f:
        json.dump(model, f, ensure_ascii=False, indent=2)

    with open(os.path.join(args.out_dir, "tiers.csv"), "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    with open(os.path.join(args.out_dir, "sensitivity.csv"), "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(sens[0].keys()))
        w.writeheader()
        w.writerows(sens)

    with open(os.path.join(args.out_dir, "anchors.csv"), "w", encoding="utf-8", newline="") as f:
        cols = ["id", "vendor", "what", "public_price", "per_unit_usd", "unit", "derived", "source"]
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for a in ANCHORS:
            w.writerow({k: a.get(k, "") for k in cols})

    print(f"[pricing_model] marginal cost/seal = ${ue['marginal_usd_per_seal']:.2e}, "
          f"{ue['seals_per_vcpu_hour']:,} seals per vCPU-hour")
    for r in rows:
        if r["implied_usd_per_seal"]:
            print(f"  {r['tier']:<10} ${r['price_usd_year']:>6,}/yr  "
                  f"{r['included_seals']:>10,} seals  ${r['implied_usd_per_seal']}/seal  "
                  f"vs Dropzone {r['vs_dropzone_per_investigation']}")
    print(f"[pricing_model] outputs -> {os.path.abspath(args.out_dir)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
