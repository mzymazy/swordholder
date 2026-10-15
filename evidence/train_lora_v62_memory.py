# -*- coding: utf-8 -*-
"""
记忆增强重训脚本 v62：qwen3:8b QLoRA（§3.5 v6 建议落地）
======================================================
训练数据：evidence/swordholder_lora_train_v62_memory.jsonl（635 条 = v6 500 + v62 增强 135）
v62 增强点（承接 v5 幻觉扩写负结果）：
  1) 精确原文锚定模板（rec-03/rec-06 逐字复述类）——所有 recite 样本 assistant 侧固定为
     公理原文一个字节不改，禁止任何扩写/解释；
  2) 提高 recite 占比：新增精确复述变体 + 首句引导（以「伤害人类即伤害自己」开头）；
  3) "绝不做的事"四域完整列举模板（rec-02/rec-05 类）——assistant 侧固定四域
     data_integrity/authority/truthfulness/supervision 完整列举，禁止缺域；
  4) 负例纠错：把 v5 幻觉扩写输出作为反例（user 问法 + assistant 拒绝/纠正）；
  5) 提示词注入/对抗例句（与公理系统一致的拒绝表达）。
输出适配器：models/lora_adapter_v62_memory
配置与 v6 一致（4bit QLoRA + r=16 + epochs=4 + lr=2e-4），保证可对照。
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
HERE = r"O:\接单\参赛\swordholder_mvp"
BASE_MODEL = os.path.join(HERE, "models", "qwen3-8b-bnb-4bit")
DATA = os.path.join(HERE, "evidence", "swordholder_lora_train_v62_memory.jsonl")
OUT_DIR = os.path.join(HERE, "models", "lora_adapter_v62_memory")
MAX_LEN = 512
EPOCHS = 4
BATCH = 2
LR = 2e-4


def main():
    assert os.path.exists(BASE_MODEL), f"base model missing: {BASE_MODEL}"
    assert os.path.exists(DATA), f"train data missing: {DATA}"
    with open(DATA, encoding="utf-8") as f:
        samples = [json.loads(line) for line in f if line.strip()]
    print(f"[train v62] samples={len(samples)} base={BASE_MODEL}", flush=True)

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
        output_dir=os.path.join(HERE, "temp", "train_v62_memory"),
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
    print(f"[train v62 done] adapter -> {OUT_DIR}", flush=True)


if __name__ == "__main__":
    main()
