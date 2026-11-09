# -*- coding: utf-8 -*-
"""S7 对比汇总：把三方实测 JSON 合成一张可复算的对照表。

输入（均在本目录）：
  s7_ours.json           —— Swordholder 同机重跑（库调用、进程内）
  s7_intoto.json         —— in-toto 3.1.0 layout 级全流程（CLI 子进程）
  s7_intoto_offline.json —— in-toto layout 级 verify 离线探针（socket 全封）
  s7_cosign.json         —— cosign v2.6.1 sign-blob / verify-blob
  s7_cosign_probe.json   —— cosign 联网/离线/缓存删改探针
输出：s7_compare.json（含每档比率），供报告直接引用。
"""
from __future__ import annotations

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    with open(os.path.join(HERE, name), encoding="utf-8") as fh:
        return json.load(fh)


def r(x, nd=2):
    return round(x, nd) if isinstance(x, (int, float)) else x


def main() -> int:
    ours = load("s7_ours.json")
    ito = load("s7_intoto.json")
    cos = load("s7_cosign.json")
    ito_off = load("s7_intoto_offline.json")
    probe_path = os.path.join(HERE, "s7_cosign_probe.json")
    cprobe = load("s7_cosign_probe.json") if os.path.exists(probe_path) else {}
    resign_path = os.path.join(HERE, "s7_intoto_resign.json")
    resign = load("s7_intoto_resign.json") if os.path.exists(resign_path) else {}

    ito_rows = {row["steps"]: row for row in ito["scaling"]}
    ito_inproc = {row["steps"]: row for row in ito["inproc_link_cost"]}
    cos_rows = {row["steps"]: row for row in cos["rows"]}
    n_list = [row["steps"] for row in ours["rows"]]

    rows = []
    for row in ours["rows"]:
        n = row["steps"]
        i = ito_rows[n]
        ip = ito_inproc[n]
        c = cos_rows.get(n, {})
        rows.append({
            "steps": n,
            # ---- 凭证体积（不含被签数据本身） ----
            "ours_credential_bytes": row["seal_bytes"],
            "intoto_credential_bytes": i["signed_metadata_bytes"],
            "intoto_credential_breakdown": {"layout": i["layout_bytes"], "links": i["link_bytes_total"],
                                            "pubkeys": i["pubkey_bytes"]},
            "intoto_link_bytes_only": i["link_bytes_total"],
            "cosign_signature_bytes": c.get("sig_bytes"),
            "cosign_bundle_bytes": c.get("bundle_bytes"),
            "size_ratio_intoto_over_ours": r(i["signed_metadata_bytes"] / row["seal_bytes"]),
            "size_ratio_intoto_links_only_over_ours": r(i["link_bytes_total"] / row["seal_bytes"]),
            "size_ratio_ours_over_cosign_sig": r(row["seal_bytes"] / c["sig_bytes"]) if c.get("sig_bytes") else None,
            # ---- 签名次数 ----
            "ours_sig_count": row["signature_count"],
            "intoto_sig_count": i["signature_count"],
            "cosign_sig_count_whole_trace": 1,
            "cosign_sig_count_per_step": n,
            "sig_count_ratio_intoto_over_ours": r(i["signature_count"] / row["signature_count"]),
            # ---- 验签耗时 ----
            "ours_verify_ms": row["verify_ms"],
            "ours_verify_min_ms": row["verify_min_ms"],
            "intoto_verify_wall_ms_median": i["verify_ms_median"],
            "intoto_verify_net_ms_median": i["verify_net_ms_median"],
            "intoto_link_only_inproc_verify_ms_total": ip["verify_ms_total"],
            "cosign_verify_offline_net_ms_median": c.get("verify_sig_offline_net_ms"),
            "cosign_verify_online_ms_median": c.get("verify_sig_net_median_ms"),
            "verify_ratio_intoto_net_over_ours": r(i["verify_net_ms_median"] / row["verify_ms"]),
            "verify_ratio_ours_over_cosign_offline_net": (r(row["verify_ms"] / c["verify_sig_offline_net_ms"])
                                                          if c.get("verify_sig_offline_net_ms") else None),
            # ---- 签名耗时 ----
            "ours_sign_ms": row["sign_ms"],
            "intoto_sign_net_ms_total": i["step_net_ms_total"],
            "intoto_sign_layout_net_ms": i["sign_layout_net_ms"],
            "intoto_sign_net_ms_total_with_layout": r(i["step_net_ms_total"] + i["sign_layout_net_ms"]),
            "cosign_sign_net_ms_median": c.get("sign_net_ms"),
            # ---- 验签输入 ----
            "ours_verify_files_required": row["verify_files_required"],
            "ours_verify_inputs_bytes": row["verify_inputs_bytes"],
            "intoto_verify_files_required": 1 + n + 1,   # layout + N links + 公钥
            "cosign_verify_files_required": 3,            # blob + sig + pub
        })

    summary = {
        "versions": {
            "swordholder": ours["version"],
            "in-toto": "3.1.0",
            "cosign": "v2.6.1",
            "python": ours["python"],
            "cryptography": ito["deps"]["cryptography"],
            "securesystemslib": ito["deps"]["securesystemslib"],
        },
        "offline": {
            "ours": {"verdict": ours["offline"]["probe"]["verdict"], "net_hits": ours["offline"]["probe"]["net_hits"],
                     "rc": ours["offline"]["rc"], "ok": ours["offline"]["rc"] == 0
                     and ours["offline"]["probe"]["net_hits"] == 0},
            "intoto": {"rc": ito_off["offline_verify"]["rc"], "net_hits": ito_off["offline_verify"]["net_hits"],
                       "ms_wall": ito_off["offline_verify"]["ms"], "ok": ito_off["offline_verify"]["ok"]},
            "cosign": {"key_based_verify_rc": cprobe["cases"]["C_dead_proxy_warm_cache"]["rc"],
                       "key_based_verify_ms_dead_proxy": cprobe["cases"]["C_dead_proxy_warm_cache"]["ms"],
                       "verify_ms_online": cprobe["cases"]["A_online_warm_cache"]["ms"],
                       "bundle_rc_default": cprobe["cases"]["E_bundle"]["verify_bundle_offline_rc"],
                       "bundle_rc_with_ignore_tlog": cprobe["cases"]["E_bundle"]["with_insecure_ignore_tlog"]["bundle_offline_ignore_tlog"]["rc"],
                       "keyless_offline_rc": cprobe["cases"]["F_keyless_offline"]["rc"],
                       "tuf_attempted_every_run": True},
        },
        "tamper": {
            "ours": {"cases": 4, "detected": 4,
                     "localized_to_step": sum(1 for pair in ours["tamper"] for x in pair if x["localized_to_step"]),
                     "note": "weak 模式定位到步；strong 模式（只验头）只判 INVALID 不定位"},
            "intoto": {"cases": ito["tamper"]["cases_total"], "detected": ito["tamper"]["detected"],
                       "localized_to_step": ito["tamper"]["localized_to_step"],
                       "unlocalized": [c["case"] for c in ito["tamper"]["cases"] if not c["named_steps_in_error"]],
                       "resign_cases": resign.get("summary", {}).get("cases") if resign else None,
                       "resign_detected": resign.get("summary", {}).get("detected") if resign else None,
                       "resign_undetected": resign.get("summary", {}).get("undetected") if resign else None,
                       "note": ("MATCH 是消费式规则，哈希不符只是不消费、不报错；必须配 DISALLOW * 才转为失败。"
                                "缺 DISALLOW 时 H1（改 link 内哈希并用该步 functionary 重签）静默通过 verify_rc=0；"
                                "补齐 DISALLOW * 后 H1/H2 均 rc=1 并点名 step02")},
            "cosign": {"whole_blob_localized": False, "per_step_sign_localized": True, "per_step_sigs": 3, "per_step_verify_calls": 3},
        },
        "external_dependency": {
            "ours": "无外部日志 / 无 CA / 无在线密钥源；公钥离线分发",
            "intoto": "无 Rekor / 无 Fulcio / 无 TSA / 无 OIDC；授权清单写在 layout 内",
            "cosign": "key-based 起手即访问 tuf-repo-cdn.sigstore.dev；默认签名上传 Rekor；keyless 需 OIDC+Fulcio+Rekor",
        },
    }

    rep = {"generated_at": __import__("datetime").datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
           "table": rows, "summary": summary}
    out = os.path.join(HERE, "s7_compare.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(rep, fh, ensure_ascii=False, indent=2)
    print(json.dumps(rep, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
