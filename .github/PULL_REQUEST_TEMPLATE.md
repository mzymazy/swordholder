# Pull Request

## 这个 PR 做了什么

<!-- 一句话说明目的，细节放正文 -->

## 类型

- [ ] 缺陷修复
- [ ] 新能力
- [ ] 文档
- [ ] 评测题组 / 判定口径变更（**需额外说明 diff 依据**）
- [ ] 工程化 / CI

## 自检清单

- [ ] 本地 `python verify_proof.py proofs/*.yaml --trusted-keys trusted_keys.json --max-age-days 365` 全部 VALID
- [ ] 新增或修改的评测结果，其数字来自 `evidence/` 下的证据文件，不是手写
- [ ] 未提交任何私钥、`.env`、token 或本机绝对路径（含 `O:\`、`C:\Users\` 等）
- [ ] 文档中的四态数字与 `evidence/judge_v2p2_aggregate.json` 一致，且未出现口径回退（v0.4 / 10 用例等旧口径）
- [ ] 若改动凭证格式或验签逻辑，已同步更新 `swordholder-boundary-map.schema.yaml` 与 CHANGELOG
- [ ] 若改动对外接口，已更新 README 与 `docs/`

## 复现 / 验证方式

<!-- 评审者如何验证你的改动，给出命令 -->

## 关联 issue

Closes #
