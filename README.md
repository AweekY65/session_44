# local-shamir — 本地 Shamir 秘密共享工具

一个**完全本地化**的 Shamir Secret Sharing 命令行工具与 Rust 库：把小型敏感
数据（任意二进制）拆分为 `n` 份 share，其中任意不少于 `k` 份即可逐字节恢复
原始数据。

- **零外部服务、零网络依赖**：不使用 KMS、Vault 或任何远程密钥服务；
  随机数来自操作系统 CSPRNG，SHA-256 与 GF(2⁸) 运算全部本地实现；
  crate 自身**只依赖 Rust 标准库**。
- **精确有限域运算**：秘密恢复使用 GF(2⁸) 上的精确拉格朗日插值，
  **全程不使用任何浮点运算**。
- 每份 share 自带版本、索引、会话标识、承诺值与完整性校验；
  重复索引、跨秘密混用 share、内容损坏/伪造均被明确检测。
- secret、share、临时缓冲只存在于本地文件或内存中；日志不输出任何
  secret 或 share 载荷，敏感缓冲在 drop 时清零。

---

## 1. 数学模型

### 1.1 有限域 GF(2⁸)

所有运算都在 Galois 域 GF(2⁸) 中进行，归约多项式取 AES 使用的
Rijndael 多项式：

```
p(x) = x⁸ + x⁴ + x³ + x + 1   (0x11B)
```

- 域元素为 8 位整数（一个字节即一个域元素）。
- 加法/减法 = 按位 XOR（特征 2）。
- 乘法 = 多项式相乘后对 `p(x)` 归约（移位 + XOR，精确整数运算）。
- 逆元由费马小定理 `a⁻¹ = a²⁵⁴` 计算；代码同时有针对 AES 标准向量
  `0x57 · 0x13 = 0xFE`、`0x53 · 0xCA = 0x01` 的测试。

### 1.2 拆分（share generation）

设参数为阈值 `k`、总份数 `n`（`2 ≤ k ≤ n ≤ 255`）。
对消息 `M = R ‖ secret`，其中 `R` 是 32 字节 CSPRNG 随机 nonce，
**逐字节位置** `p` 构造一个 `k−1` 次随机多项式：

```
f_p(x) = M[p] + a_{p,1}·x + … + a_{p,k−1}·x^{k−1}
```

- 常数项 `f_p(0) = M[p]`（即被保护的字节）；
- 其余系数 `a_{p,i}` 全部取自 `/dev/urandom`（Windows 下为
  `BCryptGenRandom`）；
- 第 `j` 份 share（索引 `x = j ∈ 1..=n`）的载荷为
  `y_p = f_p(j)`，覆盖 `M` 的每个字节。

### 1.3 恢复（exact Lagrange interpolation）

给定任意 `k` 个不同点 `(x_j, y_j)`，在 `x = 0` 处做拉格朗日插值：

```
f(0) = Σ_j y_j · Π_{m≠j} x_m / (x_m ⊕ x_j)
```

乘法、除法（×逆元）、加法全部是 GF(2⁸) 上的精确运算，
**没有任何浮点数参与**，因此恢复结果与原始数据逐字节一致。

### 1.4 安全性（信息论层面）

对任意字节位置，`k−1` 个点只能把多项式的 `k` 个系数约束到
`256` 种等可能情形之一 —— 常数项 `M[p]` 在缺少一份 share 时
**信息论意义上完全不可区分**。由于前 32 字节是均匀随机的 `R`，
少于 `k` 份时 `R` 不可确定，恢复阶段的承诺检查（见下）也无法通过：
程序会返回明确错误 `TooFewShares` / `CommitmentCheckFailed`，
而不是返回“看起来像秘密”的数据。

> 注意：标准 Shamir 不提供针对*恶意持有者*的稳健性（robustness）。
> 本工具通过对随机 nonce 的承诺 + 每份文件的校验和，检测损坏、
> 混用与单份伪造（见第 4 节安全边界），但不使用 Verifiable Secret
> Sharing 的公钥机制。

---

## 2. Share 文件格式

所有整数为大端序；文件为定长头 + 载荷 + 校验和：

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 4 | `magic` | ASCII `LSSS` |
| 4 | 1 | `version` | 格式版本，当前为 `1` |
| 5 | 1 | `k` | 恢复阈值（2..=n） |
| 6 | 1 | `n` | share 总数（k..=255） |
| 7 | 2 | `secret_len` | 原始 secret 长度（u16 BE） |
| 9 | 1 | `index` | 本份 share 的 x 坐标（1..=n） |
| 10 | 32 | `session_id` | 本次拆分的随机 nonce `R`（32B） |
| 42 | 32 | `commitment` | `SHA-256(R)` |
| 74 | `secret_len + 32` | `payload` | `R ‖ secret` 每个字节在 `index` 处的多项式求值 |
| 74+`S+32` | 32 | `checksum` | 对以上全部字节的 SHA-256 |

单份 share 总大小：**`secret_len + 138` 字节**。

最大 secret 大小：**`65 535` 字节（约 64 KiB，u16 长度字段可表达的最大值）**（常量
`MAX_SECRET_LEN`），超限在拆分阶段直接报错。

### 字段如何对应检测要求

| 威胁 | 检测机制 | 错误类型 |
|---|---|---|
| 文件损坏 / 单比特翻转 | 末尾 SHA-256 `checksum`，解析时最先验证 | `CorruptedShare` |
| 重复索引 | 恢复前扫描全部 `index` | `DuplicateIndex` |
| 不同秘密的 share 混用 | `session_id` / `commitment` / `k`/`n`/长度一致性检查 | `MixedShares` |
| 攻击者整份重写 share（含伪造 checksum） | 插值恢复出的 `R′` 必须满足 `SHA-256(R′) = commitment` | `CommitmentCheckFailed` |
| share 数量不足 | 计数 `< k` 直接拒绝，不做插值 | `TooFewShares` |
| 错误版本 / 错误 magic | 解析头时分别拒绝 | `VersionMismatch(v)` / `BadMagic` |

承诺设计说明：`commitment = SHA-256(R)` 中 `R` 是 32 字节（256 位）
CSPRNG 随机值，攻击者无法在不知道 `R` 的情况下构造一份 share，使
`k` 份 share 插值出的 `R′` 恰好哈希到既有 commitment。

---

## 3. 运行方式

### 3.1 构建

仅需 Rust 稳定版工具链（无需联网下载任何 crate —— 无第三方依赖）：

```bash
cargo build --release
# 二进制位于 target/release/local-shamir
```

### 3.2 拆分

secret 只能通过**文件或标准输入**提供，绝不接受命令行参数
（`argv` 可被本机其他进程通过 `ps`/`/proc` 看到）：

```bash
# 从文件读取 secret，生成 5 份 share，任意 3 份可恢复
./target/release/local-shamir split -k 3 -n 5 \
    -s ./secret.bin -o ./shares

# 或从标准输入（适合管道，避免 secret 落盘成明文文件）
printf '%s' "my binary secret \x00\xff" | \
    ./target/release/local-shamir split -k 2 -n 3 -s - -o ./shares
```

输出目录下生成 `share-01.bin … share-NN.bin`，权限 `0600`；
若同名文件已存在则拒绝覆盖。

### 3.3 恢复

```bash
# 用任意 >= k 份 share 恢复（多给的 share 在通过校验后忽略）
./target/release/local-shamir combine -o ./recovered.bin \
    ./shares/share-01.bin ./shares/share-03.bin ./shares/share-05.bin

# 恢复到标准输出
./target/release/local-shamir combine -o - \
    ./shares/share-02.bin ./shares/share-04.bin
```

各类失败的报错示例（均不含 secret 内容）：

```
error: not enough shares: have 2, need at least 3
error: duplicate share index 1
error: shares from different splits: share 3 carries a different session id
error: reconstruction failed the commitment check: a share is forged or mismatched
error: unsupported share format version 100 (supported: 1)
error: share index 1 is corrupted: integrity checksum mismatch
```

### 3.4 作为库使用

```rust
use local_shamir::{split, combine};

let shares = split(b"any \x00 binary data", 3, 5)?;
let subset: Vec<_> = vec![
    shares[0].clone_share(),
    shares[2].clone_share(),
    shares[4].clone_share(),
];
let secret = combine(&subset)?;   // ZeroizingBytes，drop 时清零
assert_eq!(&secret[..], b"any \x00 binary data");
```

---

## 4. 安全边界

**本工具保证：**

1. 所有处理在本地完成：无网络代码、无 KMS/Vault/远程密钥服务、
   无第三方 crate；随机数只来自内核 CSPRNG。
2. 任意 `k` 份不同索引、校验通过的 share，恢复结果与原始 secret
   **逐字节一致**；少于 `k` 份返回明确错误，绝不输出猜测结果。
3. 恢复全程 GF(2⁸) 精确运算，无浮点。
4. 检测：重复索引、跨拆分混用 share、share 内容损坏、整份伪造、
   版本不兼容、文件截断、参数不一致。
5. 日志（stderr）只打印索引、路径、字节数等元数据；`Share` 的
   `Debug` 实现对载荷与 nonce 打码；恢复出的 secret 缓冲为
   `ZeroizingBytes`（drop 时清零），并尽量避免不必要的复制。
6. 输出文件权限 `0600`，且拒绝覆盖已有 share。

**本工具不保证 / 需要使用者注意：**

1. **通道安全**：share 文件本身是敏感材料，需经由彼此独立的渠道
   分发与存放；工具不加密 share 文件本身（文件系统权限是第一道防线）。
2. **端点安全**：无法防御已经能读取进程内存或 `/dev/urandom`
   的本地攻击者；`ZeroizingBytes` 是尽力而为（不能清除分配器/编译器
   产生的全部临时副本）。
3. **非 VSS**：可检测“存在伪造/混用”并拒绝恢复，但不识别*哪一份*
   share 是恶意的；需要识别恶意方时应使用可验证秘密共享（VSS）方案。
4. **参数上限**：`n ≤ 255`（GF(2⁸) 的非零 x 坐标只有 255 个），
   secret ≤ 65 535 字节（约 64 KiB）。这是面向“小型敏感数据”的刻意限制。
5. **侧信道**：乘法采用查表/移位的清晰实现，未针对时序侧信道做
   恒定时间工程化；秘密恢复通常在离线本机进行。
6. **元数据可见**：share 头中的 `secret_len`、`k`、`n` 为明文，
   任何持有者可见（载荷不泄露内容）。

---

## 5. 项目结构

```
Cargo.toml
src/
  lib.rs       公共 API 与模块导出
  gf256.rs     GF(2^8) 算术 + 精确拉格朗日插值（无浮点）
  sha256.rs    FIPS 180-4 SHA-256（本地实现，无依赖）
  rng.rs       OS CSPRNG（/dev/urandom；Windows BCryptGenRandom）
  share.rs     share 格式、序列化/解析、校验、错误类型、ZeroizingBytes
  shamir.rs    split / combine 核心
  main.rs      命令行接口（split / combine）
  tests.rs     自动化测试
README.md
```

---

## 6. 测试

运行全部自动化测试：

```bash
cargo test
```

测试覆盖（见 `src/tests.rs` 及各模块内嵌单元测试）：

- 多种 `(k,n)`：`(2,2) (2,3) (3,5) (5,5) (2,10) (4,7) (2,255)`；
- `(3,5)` 下**全部 C(5,3)=10 种组合**恢复一致，且超过 `k` 份也可恢复；
- 包含全部 256 个字节值的二进制 secret、空 secret、随机 1000B 数据；
- 65 535 字节上限可通过、65 536 字节被拒绝；
- share 缺失 / 少于阈值（0、1、k−1 份）均返回 `TooFewShares`；
- 重复索引返回 `DuplicateIndex`；
- 载荷/头部单比特翻转、文件截断 → 解析期 checksum 失败；
- 攻击者重写载荷**并重算 checksum** → 承诺检查失败
  `CommitmentCheckFailed`；
- 不同秘密、不同参数的 share 混用 → `MixedShares`；
- 错误版本 → `VersionMismatch`；错误 magic / 随机垃圾 → `BadMagic`；
- 非法参数 `k<2`、`k>n`、`n=0` 等被拒；索引恰为 1..=n 且不重复；
- `Debug`/错误文本/日志不泄露 secret 明文，share 文件中不出现
  secret 连续子串；
- GF(2⁸) AES 标准向量、乘逆元、结合/分配律；SHA-256 FIPS 标准向量
  （空串、`abc`、56 字节边界）及流式分块一致性。

也可以先做无测试的检查：

```bash
cargo clippy --all-targets   # 静态检查（可选）
cargo build --release        # 发布构建
```
