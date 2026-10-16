# -*- coding: utf-8 -*-
"""
记忆增强重训脚本 v6：qwen3:8b QLoRA（修正 v5 幻觉扩写）
======================================================
训练数据：temp/swordholder_lora_train_v6_memory.jsonl（500 条 = v4 330 + v6 增强 170）
增强点：recite 固定模板 60 + 逐字强化 40 + 绝不做变体 30 + 负例纠错 20 + drift 20
输出适配器：models/lora_adapter_v6_memory
配置与 v5 一致（4bit QLoRA + r=16 + epochs=4 + lr=2e-4），保证可对照。
"""
import json
import os
import sys
import torch
from transformers import (
    AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig,
    TrainingArguments, Trainer, DataCollatorForLanguageModeling
)
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training, TaskType

sys.stdout.reconfigure(encoding='utf-8', errors='replace')
HERE = os.environ.get("SWORDHOLDER_ROOT") or os.path.dirname(  # 仓库根：优先环境变量，其次按脚本位置相对定位
    os.path.dirname(os.path.abspath(__file__)))
BASE_MODEL = os.path.join(HERE, "models", "qwen3-8b-bnb-4bit")
DATA = os.path.join(HERE, "temp", "swordholder_lora_train_v6_memory.jsonl")
OUT_DIR = os.path.join(HERE, "models", "lora_adapter_v6_memory")
MAX_LEN = 512
EPOCHS = 4
BATCH = 2
LR = 2e-4


def main():
    assert os.path.exists(BASE_MODEL), f"base model missing: {BASE_MODEL}"
    assert os.path.exists(DATA), f"train data missing: {DATA}"
    with open(DATA, encoding="utf-8") as f:
        samples = [json.loads(line) for line in f if line.strip()]
    print(f"[train v6] samples={len(samples)} base={BASE_MODEL}", flush=True)

    tok = AutoTokenizer.from_pretrained(BASE_MODEL, trust_remote_code=True)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token

    def fmt(m):
        return tok.apply_chat_template(m["messages"], tokenize=False, add_generation_prompt=False)

    texts = [fmt(s) for s in samples]
    enc = tok(texts, truncation=True, max_length=MAX_LEN, padding=True)

    bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                             bnb_4bit_compute_dtype=torch.float16, bnb_4bit_use_double_quant=True)
    model = AutoModelForCausalLM.from_pretrained(BASE_MODEL, quantization_config=bnb,
                                                 device_map="auto", trust_remote_code=True,
                                                 torch_dtype=torch.float16)
    model = prepare_model_for_kbit_training(model)
    lora = LoraConfig(task_type=TaskType.CAUSAL_LM, r=16, lora_alpha=32,
                      lora_dropout=0.05, bias="none",
                      target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                                      "gate_proj", "up_proj", "down_proj"])
    model = get_peft_model(model, lora)
    model.print_trainable_parameters()

    class DS(torch.utils.data.Dataset):
        def __init__(self, enc):
            self.input_ids = [torch.tensor(x, dtype=torch.long) for x in enc["input_ids"]]
            self.attn = [torch.tensor(x, dtype=torch.long) for x in enc["attention_mask"]]
        def __len__(self):
            return len(self.input_ids)
        def __getitem__(self, i):
            return {"input_ids": self.input_ids[i], "attention_mask": self.attn[i],
                    "labels": self.input_ids[i].clone()}

    args = TrainingArguments(
        output_dir=os.path.join(HERE, "temp", "train_v6_memory"),
        per_device_train_batch_size=BATCH, gradient_accumulation_steps=2,
        num_train_epochs=EPOCHS, learning_rate=LR, lr_scheduler_type="linear",
        logging_steps=20, save_strategy="no",
        fp16=True, report_to=[], disable_tqdm=False,
    )
    trainer = Trainer(model=model, args=args, train_dataset=DS(enc),
                      data_collator=DataCollatorForLanguageModeling(tok, mlm=False))
    trainer.train()
    model.save_pretrained(OUT_DIR)
    tok.save_pretrained(OUT_DIR)
    print(f"[train v6 done] adapter -> {OUT_DIR}", flush=True)


if __name__ == "__main__":
    main()
