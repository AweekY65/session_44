# local-sss — 本地 Shamir 秘密共享工具

一个**完全离线、零外部依赖**的命令行工具与 Rust 库，用 Shamir Secret Sharing
（沙米尔秘密共享）把小型敏感数据（密钥、种子码、口令、短文档等任意二进制数据）
拆分为 `n` 份 share，任意不少于 `k` 份即可还原；少于 `k` 份在信息论意义上
无法获得秘密的任何信息。

- 有限域：GF(2⁸)，不可约多项式 `x⁸+x⁴+x³+x+1`（与 AES 相同，0x11B）
- 所有运算为**整数/查表运算**，秘密恢复使用拉格朗日插值，**没有任何浮点运算**
- 每份 share 自带版本号、阈值参数、索引、随机会话标识与 SHA-256 完整性校验
- 支持任意二进制 secret，最大 **64 KiB**
- 不依赖 KMS / Vault / 远程密钥服务；密码学原语（GF 运算、SHA-256、系统随机数）
  全部在本仓库内实现，`Cargo.toml` 无任何第三方 crate

---

## 1. 数学模型

### 1.1 有限域 GF(2⁸)

秘密的每个**字节**独立处理。GF(2⁸) 中有 256 个元素，正好用一个 `u8` 表示：

- 加法/减法 = 按位异或（特征 2 下减法等于加法）；
- 乘法通过以 3 为生成元的对数/反对数表完成，模不可约多项式 0x11B 归约；
- 逆元由对数表得到：`a⁻¹ = 3^(255 − log₃(a))`。

域中非零坐标只有 255 个，因此约束为 `1 ≤ k ≤ n ≤ 255`。

### 1.2 拆分（Shamir）

对 secret 的每个字节 `s`（`s ∈ GF(2⁸)`）独立采样一个 `k−1` 次随机多项式：

```
f(x) = s + a₁x + a₂x² + … + aₖ₋₁x^(k−1)
```

其中常数项 `f(0) = s`，`a₁..aₖ₋₁` 来自系统 CSPRNG。第 `i` 份 share
（`i = 1..n`）对应该字节的值就是 `f(i)`。每个字节使用独立的随机系数。

`k = 1` 时没有随机系数，所有 share 都等于 secret（仍然合法，相当于明文复制）。

### 1.3 恢复（拉格朗日插值 @ x=0）

给定任意 `m ≥ k` 个点 `(xᵢ, yᵢ)`（索引互不相同），用拉格朗日插值求 `f(0)`：

```
              ⎧        xⱼ      ⎫
f(0) =   ⊕    ⎨ yᵢ · ∏ ─────── ⎬
         i    ⎩    j≠i xⱼ⊕xᵢ   ⎭
```

全部乘法、除法、异或都在 GF(2⁸) 内精确完成（见 `src/gf256.rs`）。
因为次数至多为 `k−1` 的多项式由任意 `k` 个点唯一确定，所以：

- 任意 `k` 份（或更多）share 恢复出**逐字节完全一致**的原始数据；
- 任意 `k−1` 份对每个字节都还有 256 种等可能的常数项，零信息泄露。

多于 `k` 份同样可以直接参与插值（实现不要求恰好 `k` 份）。

---

## 2. Share 文件格式（版本 1）

每份 share 是一个独立的二进制文件，默认写入 `--out-dir` 目录，
文件名为 `share-001.bin … share-NNN.bin`，Unix 权限 `0600`。

| 偏移 | 长度 | 字段 | 说明 |
|---|---|---|---|
| 0 | 4 | magic | ASCII `LSSS` |
| 4 | 1 | version | 格式版本，当前为 `1` |
| 5 | 1 | k | 恢复阈值 |
| 6 | 1 | n | share 总数 |
| 7 | 1 | index | 本份 share 的索引 `i`，`1 ≤ i ≤ n`（即 x 坐标） |
| 8 | 4 | secret_len | 大端 u32，secret / y 的字节数 |
| 12 | 16 | session_id | 一次拆分随机生成的 128-bit 标识，同一次拆分的所有 share 相同 |
| 28 | secret_len | y | 本份 share 的 y 字节（GF(2⁸) 求值结果） |
| 28+… | 32 | checksum | 对前面所有字节计算的 SHA-256 |

校验机制能检测的异常：

- **内容损坏/篡改**：任何字节被改都会导致末尾 SHA-256 校验失败（常量时间比较）；
- **重复索引**：恢复时若两份 share 的 `index` 相同，直接报错；
- **不同 secret 的 share 混用**：`session_id` 不同即报错；
- **参数不一致**：同一会话但 `k`/`n`/`secret_len` 不一致即报错；
- **错误版本**：`version != 1` 返回 `unsupported version`；
- **截断/结构损坏**：magic、长度字段等逐项校验。

---

## 3. 安全边界

**保证：**

1. 少于 `k` 份 share 不返回任何（哪怕部分的）秘密；工具直接以非零退出码报错
   （`not enough shares`）。
2. `k−1` 份 share 对秘密的信息论泄露为零（每个字节 256 种等可能取值），
   不依赖计算假设。
3. 每份 share 与 secret 等长；单份 share 本身就是敏感材料，按 `0600` 保存。
4. 随机数只来自内核 CSPRNG（Unix 上是 `/dev/urandom`，Windows 上是
   `BCryptGenRandom`），读取失败即报错，绝不降级为弱随机数。
5. 程序日志/`--inspect` 输出只包含元数据，不打印原始 secret 或 share 的 y 值；
   `SecretBytes`/`Share` 实现了不泄露内容的 `Debug`，并在 drop 时
   以 volatile 写尽力清零内存。

**不保证（使用前必须理解）：**

- SHA-256 校验和只防**意外损坏与识别混用**，它不是 MAC：持有 share 的人可以
  自行重算校验和。本方案不针对“持单方恶意伪造 share”的主动攻击模型。
- 信息论安全针对的是拆分结果；**恢复出来的明文**、split 读取的输入文件
  以及内核/交换分区层面的内存落盘不在本工具控制范围内，请自行处理
  （如内存盘、加密交换、用完安全删除输入）。
- 只支持 64 KiB 以内的小数据；大文件请先加密再用本工具共享其数据加密密钥
  （DEK 模式）。
- 侧信道（内存被转储、恶意进程、备份系统复制 share 文件）超出工具边界。

---

## 4. 构建与运行

需要 Rust stable（≥ 1.74 即可；开发使用 1.98）。**构建过程仅需从 crates.io
拉取依赖，而本项目没有任何依赖**；运行时完全离线。

```bash
cargo build --release

# 拆分：把 secret.bin 拆成 5 份，任意 3 份恢复
./target/release/sss split -k 3 -n 5 \
    --secret secret.bin --out-dir ./shares
# => 输出 5 个 share 文件路径；secret 内容不会出现在日志中

# 也支持从标准输入读取 secret（'-'）
cat secret.bin | ./target/release/sss split -k 2 -n 3 \
    --secret - --out-dir ./shares

# 恢复：从目录中收集所有 share-*.bin（必须 >= k 份）
./target/release/sss combine --in-dir ./shares --out recovered.bin

# 也可显式列出任意 >= k 份 share；结果可写到标准输出（'-'）
./target/release/sss combine --out - \
    ./shares/share-001.bin ./shares/share-003.bin ./shares/share-005.bin \
    > recovered.bin

# 只查看元数据与完整性状态（不显示 share 数据）
./target/release/sss inspect ./shares/share-001.bin
```

退出码：`0` 成功；`1` 运行/校验错误（份额不足、校验失败等）；`2` 用法错误。

参数约束：`1 ≤ k ≤ n ≤ 255`，secret `≤ 65536` 字节（64 KiB，含空 secret）。

---

## 5. 测试

```bash
cargo test
```

测试分两层：

- **库内单元测试**（`src/*.rs`）：
  - GF(2⁸)：AES 官方测试向量、乘法交换/恒等/零元、除法全表往返、求逆；
  - 多项式求值与朴素算法逐点比对（x = 0..255）；
  - 拉格朗日插值：对 1..=5 阶枚举 7 个点的**所有 k-子集**恢复常数项，
    以及重复坐标拒绝；
  - SHA-256：FIPS 180-4 空串/abc/长串与百万字节官方向量、流式与一次性一致；
  - SSS：不同 `k/n`（含 `k=1`、`k=n`）、所有 quorum 子集恢复、空 secret、
    达到 64 KiB 上限与超限拒绝、重复索引、不同 session 混用、参数不一致、
    y 字节篡改（checksum 失败）、确定性随机数可复现性。
- **CLI 集成测试**（`tests/cli.rs`，直接跑编译出的 `sss` 二进制）：
  文本/二进制 secret、stdio 往返、任意 4-of-6 子集恢复、
  份额不足拒绝且无字节输出、磁盘文件篡改、错误版本号、重复索引、
  不同秘密 share 混用、超大 secret 拒绝、`inspect` 输出。

预期结果：全部测试通过，`cargo test` 汇总行显示
`test result: ok. 36 passed; 0 failed`（26 个库单元测试 + 10 个 CLI 集成测试）。

---

## 6. 目录结构

```
Cargo.toml          # 无任何第三方依赖
src/
  lib.rs            # 库入口
  gf256.rs          # GF(2^8) 查表运算、多项式求值、拉格朗日插值
  sha256.rs         # 本地实现的 SHA-256（仅用于完整性校验）
  rng.rs            # getrandom(2) / /dev/urandom + 测试用确定性 RNG
  share.rs          # share 二进制格式编解码 + 校验
  sss.rs            # split/combine 核心逻辑、参数校验、SecretBytes
  error.rs          # 错误类型（每种失败场景独立变体）
  main.rs           # sss 命令行
tests/
  cli.rs            # 端到端集成测试
```
