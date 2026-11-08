# S6：公开发行物与质量门禁的实测记录

本文件只回答四件事，每件都给可复核的原始输出或 API 返回，做不到的写进负结果，不用"应该可以"替代：

1. GitHub Actions 四个 workflow 在 `v0.7.4` 上是否真跑通，run id 与结论是什么；
2. 可安装发行物是否以 GitHub Release 附件形式公开，下载 URL 与字节哈希是什么；
3. 在**干净隔离环境**里按仓库文档从公开发行物装一次，是否装得上、装完能不能跑通判定链；
4. 覆盖率与质量门禁的实际数字是多少，CI 与本机是否一致。

机器可读版本：`evidence/release/v0.7.4_ci_release_evidence.json`（同目录，字段与本文件一一对应）。

---

## 1. CI 实跑证据

`v0.7.4` tag 指向 `dbdf7d88fd896e127862e92e233afc79bf3dc4e3`，其承载提交为
`b3897be96db8c5d2b569a3dac0960e3cc81e8233`（`docs(s6): changelog for 0.7.4`）。

| workflow | run id | 结论 | 链接 |
|---|---|---|---|
| release | 42454039062 | success | https://github.com/mzymazy/swordholder/actions/runs/42454039062 |
| verify | 42454039185 | success | https://github.com/mzymazy/swordholder/actions/runs/42454039185 |
| mcp-selftest | 42454039055 | success | https://github.com/mzymazy/swordholder/actions/runs/42454039055 |
| security-hardening | 42454039045 | success | https://github.com/mzymazy/swordholder/actions/runs/42454039045 |

### 1.1 release run 的 job 与步骤

`build` job 的 12 个实质步骤全部 success（`gh run view 42454039062 --json jobs`）：

| # | 步骤 | 结论 |
|---|---|---|
| 1–3 | Set up job / checkout@v4 / setup-python@v5 | success |
| 4 | Install build tooling（pip / build / twine / setuptools / wheel） | success |
| 5 | Build wheel and sdist | success |
| 6 | Install wheel runtime dependencies (from wheel METADATA) | success |
| 7 | Verify release (hashes, version, package data, examples) | success |
| 8 | Show release verification report | success |
| 9 | Upload release verification report | success |
| 10 | Twine metadata check | success |
| 11 | Install the built wheel into a clean venv and run the public quickstart | success |
| 12 | upload-artifact@v4（name=dist） | success |

`github-release` job：success（`Create GitHub Release with installable artifacts` 这一步创建了 v0.7.4）。
`publish` job：**skipped**，原因是 `vars.PYPI_TRUSTED_PUBLISHER != 'true'`，属设计内的 fail-closed，
不是失败。

步骤 6 的实际输出（证明依赖清单来自 wheel 自己的 METADATA，不是手写）：

```
runtime deps: cryptography>=42.0.0 pyyaml<7,>=6.0.1 jsonschema>=4.18
Successfully installed attrs-26.1.0 jsonschema-4.26.0 jsonschema-specifications-2025.9.1
pyyaml-6.0.3 referencing-0.37.0 rpds-py-2026.9.1 typing-extensions-4.16.0
```

步骤 10：`Checking dist/swordholder-0.7.4-py3-none-any.whl: PASSED` /
`Checking dist/swordholder-0.7.4.tar.gz: PASSED`。
步骤 11：`wheel 冒烟：判定 -> 盖章 -> 独立验签 VALID 全通`。

### 1.2 verify run 的 job 矩阵

| job | 结论 |
|---|---|
| quality-gate（ruff + pytest + 覆盖率门禁） | success |
| verify-proofs | success |
| exit-integrity | success |
| package-smoke (ubuntu-latest, 3.11 / 3.12 / 3.13) | 3× success |
| package-smoke (windows-latest, 3.11 / 3.12 / 3.13) | 3× success |
| package-smoke-macos | skipped（矩阵条件未启用） |

---

## 2. 公开发行物

Release 页面（匿名可访问）：https://github.com/mzymazy/swordholder/releases/tag/v0.7.4
`draft=false`、`prerelease=false`。

| 附件 | 字节 | SHA256 | 下载 URL |
|---|---|---|---|
| swordholder-0.7.4-py3-none-any.whl | 145 637 | `8986fb4cd6b474283806a57b70656243f6070e56eaee001662197c1d8eb70db1` | https://github.com/mzymazy/swordholder/releases/download/v0.7.4/swordholder-0.7.4-py3-none-any.whl |
| swordholder-0.7.4.tar.gz | 261 920 | `22c40bec37ae2bc0a4615e102cd243cf0e598c4fa613d87415868576888a96f5` | https://github.com/mzymazy/swordholder/releases/download/v0.7.4/swordholder-0.7.4.tar.gz |
| SHA256SUMS | 192 | `0e1cf5bd2f923beac88e26f2d379ed17ca2c03303acb05a754d3d6e98d2dd16e` | https://github.com/mzymazy/swordholder/releases/download/v0.7.4/SHA256SUMS |

三方交叉核对：GitHub API 返回的 asset digest、`SHA256SUMS` 内登记的哈希、以及我实际取回的字节哈希，
三处完全一致（wheel `8986fb4c…`、sdist `22c40bec…`）。

---

## 3. 干净隔离环境的安装实测

统一条件：Windows 11 26200 / Python 3.11.8 / **全新 venv**，创建后 `pip list` 只有
`pip 24.0` 与 `setuptools 65.5.0`，无项目路径、无 `PYTHONPATH`、无源码树。

### 3.1 wheel（Release 附件）

```text
python -m pip install swordholder-0.7.4-py3-none-any.whl
Processing ...\swordholder-0.7.4-py3-none-any.whl
Requirement already satisfied: cryptography>=42.0.0 ... (50.0.2)
Requirement already satisfied: pyyaml<7,>=6.0.1 ... (6.0.3)
Requirement already satisfied: jsonschema>=4.18 ... (4.26.0)
```

安装后：`pip show swordholder` →
`Name: swordholder` / `Version: 0.7.4` / `Requires: cryptography, jsonschema, pyyaml`；
`import swordholder` 的 `__file__` 落在该 venv 的 `site-packages\swordholder\__init__.py`，
`__version__` 打印 `0.7.4`。

### 3.2 sdist（Release 附件）

```text
python -m pip install swordholder-0.7.4.tar.gz
Building wheels for collected packages: swordholder
  Building wheel for swordholder (pyproject.toml): finished with status 'done'
  Created wheel for swordholder: filename=swordholder-0.7.4-py3-none-any.whl size=145776
Successfully built swordholder
Successfully installed ... swordholder-0.7.4
```

装完 `swordholder --version` → `swordholder 0.7.4`（exit 0）。这条证明 Release 上的 sdist 不是摆设，
在无网络源码路径的新环境里能自建 wheel。

### 3.3 装完按文档跑一次最小链路（陌生人视角）

全部在该干净 venv 内执行。工作目录只放一个 `alert.json`（取自 wheel 内置 `swordholder/samples/alert_01_egress.json`，
即"只用装进来的东西，不用仓库源码"）：

```text
$ swordholder --version
swordholder 0.7.4                                                     [exit=0]

$ swordholder keygen --out keys
{ "private_key_path": "keys\\swordholder_ed25519_private.pem",
  "public_key_path": "keys\\swordholder_ed25519_public.pem",
  "public_key_hex": "f51b36a99bb82c290eb664a159f70c472a9caf1890b7df397f0cf48acc893c38" }   [exit=0]

$ swordholder triage alert.json --seal -k keys\swordholder_ed25519_private.pem
{ "alert_id": "ALRT-2026-1102-0007", "asset": "build-runner-07",
  "verdict": "suspicious", "severity": "high", "confidence": 0.78, "engine": "rules-v1",
  "seal": "alert.seal.json",
  "payload_sha256": "de2cc7d671d86bdaf104b0cb9ddc9ac1b4a675eedcd379085a1e8897890e644a" }     [exit=0]

$ swordholder trust add --pubkey f51b36a9... --keys-file trusted.json --key-id clean-room
{ "ok": true, "total_keys": 1,
  "key": { "key_id": "clean-room", "algorithm": "ed25519", "status": "active",
           "fingerprint_sha256": "a226ee7893cb8b42cee17fb9a3bc7ec1914871f8fa9e516d9dc1052f32396f48" } }  [exit=0]

$ swordholder verify alert.seal.json --keys trusted.json
{ "verdict": "VALID", "reason": "OK", "trust": "trusted",
  "seal_id": "b431bdaa-665d-43bd-ac5f-9940cb0d1e49",
  "created_at": "2026-11-08T07:21:18Z",
  "payload_sha256": "de2cc7d671d86bdaf104b0cb9ddc9ac1b4a675eedcd379085a1e8897890e644a",
  "public_key_hex": "f51b36a99bb82c290eb664a159f70c472a9caf1890b7df397f0cf48acc893c38",
  "key_id": "clean-room", "key_status": "active" }                                          [exit=0]
```

读法：盖章前算出的 `payload_sha256`（`de2cc7d6…`）与验签返回的是同一串，`verdict=VALID`、`trust=trusted`，
`public_key_hex` 与 `keygen` 打印的一致，说明凭证是用这把私钥盖的、且这把公钥已作为信任锚登记。

---

## 4. 覆盖率与质量门禁

CI `quality-gate` job（run 42454039185）原始输出：

```text
All checks passed!                                          # ruff
TOTAL                           3260    339   1092    151    88%
Coverage XML written to file coverage.xml
Required test coverage of 85.0% reached. Total coverage: 88.19%
471 passed, 1 skipped in 21.24s
```

**口径必须写清，否则同一个 88.19% 会被误读：**

| 口径 | 计算 | 数值 |
|---|---|---|
| 合并（行 + 分支，`fail_under` 判定用的就是这个） | (3260−339 + 917) / (3260 + 1092) = 3838 / 4352 | **88.19%** |
| 纯行 | (3260 − 339) / 3260 = 2921 / 3260 | 89.60% |
| 纯分支 | 917 / 1092 | 83.97% |

`coverage.xml` 的 `line-rate="0.896"`、`branch-rate="0.8397"` 就是后两行，分别对应纯行与纯分支，
与 88.19% 不矛盾，只是分母不同。对外只引用 88.19% 时必须带上"行+分支"三个字。

用例数：CI 记 471 passed / 1 skipped；本机 `--collect-only` 计 472 条（471 + 1 skip），两者对齐。

本机复跑（同一命令、同一 `pyproject.toml` 阈值）：

```text
TOTAL                           3260    339   1092    151    88%
Required test coverage of 85.0% reached. Total coverage: 88.19%
```

TOTAL 行的四个数与 CI 完全一致，即 CI 与本机不存在双口径。

---

## 5. 负结果登记（N-S6-01 … N-S6-06）

| 编号 | 做不到 / 未验证 | 事实与原因 |
|---|---|---|
| N-S6-01 | `pip install <Release 直链>` 在本机失败 | `ERROR: HTTP error 403 while getting https://github.com/mzymazy/swordholder/releases/download/v0.7.4/swordholder-0.7.4-py3-none-any.whl`；换 `curl.exe` 同 URL 亦 `http=403`。同一资产经 GitHub API `application/octet-stream` 能取回且哈希与 digest 一致，说明是本机网络出口对该下载路径的限制，不是发行物问题。README 的直链安装方式因此在本机无法自证，需在无该限制的网络复验 |
| N-S6-02 | PyPI 仍未发布 | `publish` job 因 `vars.PYPI_TRUSTED_PUBLISHER != 'true'` 跳过；Trusted Publisher 未登记，`pip install swordholder` 仍会失败 |
| N-S6-03 | macOS 冒烟未跑 | `package-smoke-macos` 在 run 42454039185 中为 skipped，Apple Silicon 上的安装链仍无证据 |
| N-S6-04 | 无第三方独立安装 | 三个干净 venv 都在同一台机器、同一网络出口，不是外部用户；"陌生人按文档装上了"这句话只在同网络条件下成立 |
| N-S6-05 | 覆盖率只覆盖仓库自身测试 | 88.19% 是 `swordholder` + `mcp_server` 两个包的合并覆盖率，不含 `scripts/`、`examples/`；不能据此说"全仓覆盖率 88.19%" |
| N-S6-06 | Release 资产无签名 | 附件靠 SHA256 与 GitHub 平台托管保证完整性，未做 cosign/sigstore 签名，第三方无法离线验证来源 |

---

## 6. 任何人都能复算的步骤

```bash
# 1) 看 CI 结论（匿名可用）
gh run view 42454039062 --repo mzymazy/swordholder --json jobs,conclusion

# 2) 取资产并核对哈希（浏览器或 curl 皆可，需网络放行 release 下载）
curl -L -o w.whl https://github.com/mzymazy/swordholder/releases/download/v0.7.4/swordholder-0.7.4-py3-none-any.whl
certutil -hashfile w.whl SHA256      # 期望 8986fb4cd6b474283806a57b70656243f6070e56eaee001662197c1d8eb70db1

# 3) 干净环境装 + 跑最小链路
python -m venv clean && clean\Scripts\activate
pip install w.whl
swordholder --version
swordholder keygen --out keys
swordholder triage alert.json --seal -k keys\swordholder_ed25519_private.pem
swordholder trust add --pubkey <public_key_hex> --keys-file trusted.json --key-id me
swordholder verify alert.seal.json --keys trusted.json      # 期望 VALID

# 4) 复算覆盖率
git clone https://github.com/mzymazy/swordholder && cd swordholder
pip install -e ".[dev]"
pytest --cov=swordholder --cov=mcp_server --cov-report=term
```
