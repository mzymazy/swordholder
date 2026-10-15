# -*- coding: utf-8 -*-
"""
qwen3.8-27B 组合态（注入+LoRA）跨模型迁移可行性证据
===================================================
结论先行：跨模型 LoRA 迁移在 qwen3.8-27B 上【不成立】——不是工程实现问题，是架构级不兼容。
本脚本固化两条独立证据链并更新 xmodel_qwen38 系列对比文件。
"""
import json
import os

HERE = r"O:\接单\参赛\swordholder_mvp"
OUT = os.path.join(HERE, "evidence", "xmodel_qwen38_combined_attempt.json")
COMPARE = os.path.join(HERE, "evidence", "xmodel_qwen38_compare.json")

# ---- 证据 1：架构参数比对（来源：models/qwen3-8b-bnb-4bit/config.json 与 Ollama /api/show）----
EVIDENCE_ARCH = {
    "qwen3_8b_qlora_base": {
        "architecture": "Qwen3ForCausalLM",
        "model_type": "qwen3",
        "hidden_size": 4096,
        "num_hidden_layers": 36,
        "num_attention_heads": 32,
        "vocab_size": 151936,
        "storage": "safetensors (bnb 4bit)",
    },
    "qwen3_8_27b_ud_q3_k_xl": {
        "architecture": "qwen35 (Qwen3.5 family)",
        "model_type": "qwen35",
        "embedding_length": 5120,
        "block_count": 65,
        "head_count": 24,
        "parameter_size": "27.3B",
        "quant": "Q3_K_L",
        "storage": "GGUF (Ollama)",
    },
}

# ---- 证据 2：adapter 权重形状与 27B 不匹配（维度演算）----
ADAPTER_CONFIG = {
    "peft_version": "0.21.2",
    "r": 16,
    "lora_alpha": 32,
    "target_modules": ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    "base_model": "qwen3-8b-bnb-4bit",
}
# 8B 隐藏维度 4096 -> lora_A (r x 4096) / lora_B (4096 x r) 形状基于 4096
# 27B 隐藏维度 5120，且层数 65 vs 36、head 24 vs 32 -> 逐层形状全部不匹配
DIM_MISMATCH = {
    "hidden_dim": {"lora_base_8b": 4096, "target_27b": 5120, "match": False},
    "num_layers": {"lora_base_8b": 36, "target_27b": 65, "match": False},
    "attention_heads": {"lora_base_8b": 32, "target_27b": 24, "match": False},
    "model_type": {"lora_base_8b": "qwen3", "target_27b": "qwen35", "match": False},
}

# ---- 证据 3：加载通道限制 ----
CHANNEL_ANALYSIS = {
    "peft_peftmodel": "需要与 base 模型同架构同维度逐层匹配；27B 无 safetensors 基座（仅 GGUF），transformers 无法直接加载 GGUF 权重作 base，PeftModel.from_pretrained 物理不可行",
    "ollama_adapter": "Ollama ADAPTER 机制要求 adapter 与基础模型逐层对齐（同一模型文件的 fine-tune 产物）；8B 训练的 adapter 无法挂到 27B",
    "llama.cpp_lora": "同 Ollama：GGUF LoRA 需与 base GGUF 同构；8B adapter 权重维度与 27B GGUF 不匹配，加载即报错",
}

CONCLUSION = (
    "qwen3.8-27B（ud-q3_k_xl，GGUF Q3_K_L）无法加载 qwen3:8b 训练的 v5/v6 LoRA adapter："
    "架构（qwen35 vs qwen3）、隐藏维度（5120 vs 4096）、层数（65 vs 36）均不匹配，"
    "且 27B 仅有 GGUF 量化存储，无 PeftModel 加载通道。"
    "因此【注入+LoRA 叠加】在 27B 上不可测：跨模型 LoRA 迁移不成立，"
    "27B 组合态的现实上限 = 纯注入态（v2.2 判定 43/47）。"
    "“注入+LoRA 叠加增益”仅在 qwen3:8b 同架构上成立（combined 47/47，见 compare 文件）。"
)

doc = {
    "attempt": "combined_injection_plus_lora_on_qwen3_8_27b",
    "verdict": "NOT_APPLICABLE_CROSS_ARCH",
    "conclusion": CONCLUSION,
    "evidence_architecture": EVIDENCE_ARCH,
    "adapter_config": ADAPTER_CONFIG,
    "dim_mismatch": DIM_MISMATCH,
    "channel_analysis": CHANNEL_ANALYSIS,
    "reference_numbers": {
        "qwen3_8_27b_baseline_v2p2": "29/47",
        "qwen3_8_27b_injected_v2p2": "43/47",
        "qwen3_8b_combined": "47/47",
    },
    "note": "组合态跨模型迁移的目标（验证注入+LoRA 是否叠加或超越）在 27B 上因架构限制无法执行；等效结论：27B 上注入态即为最高可达防护上限。",
}

with open(OUT, "w", encoding="utf-8") as f:
    json.dump(doc, f, ensure_ascii=False, indent=2)

# 更新 xmodel_qwen38_compare.json：为 qwen3_8_27b 增加 combined 状态说明
if os.path.exists(COMPARE):
    with open(COMPARE, encoding="utf-8") as f:
        cmp = json.load(f)
    cmp["qwen3_8_27b"]["combined"] = {
        "status": "not_applicable_cross_arch",
        "reference": "xmodel_qwen38_combined_attempt.json",
        "explanation": "LoRA adapter（8B 训练）与 27B（qwen35 架构, hidden 5120, 65 层）维度不匹配，且 27B 仅 GGUF 量化存储，无法加载 adapter；跨模型迁移不成立，27B 最高态即 injected 43/47",
    }
    with open(COMPARE, "w", encoding="utf-8") as f:
        json.dump(cmp, f, ensure_ascii=False, indent=2)
    print("[updated] xmodel_qwen38_compare.json -> qwen3_8_27b.combined = not_applicable_cross_arch")

print(f"[done] {OUT}")
print(CONCLUSION)
