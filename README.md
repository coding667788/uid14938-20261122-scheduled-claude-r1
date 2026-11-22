# boot_replay — 断电可重放的 A/B 启动验证器

纯文件模拟的设备更新与启动验证工具。设备的 A/B 分区、签署见证、单调计数器
全部是虚构的数据结构，**不接触任何真实固件或硬件**。所有状态都是普通 JSON 可
序列化的 Python 对象，每次状态转换都返回深拷贝快照，因此可以自由地枚举断电
前缀、回放轨迹和搜索修复序列。

在 Windows 原生 Python 3.12 上仅使用标准库与 CPU 运行。

---

## 1. 快速开始

```bat
:: 在仓库根目录（包含 boot_replay\ 的目录）执行
python -m boot_replay replay cases\generated\happy-16x64.json
python -m boot_replay check  cases\generated\revoke-race.json
python -m boot_replay repair cases\generated\half-each.json
```

- 标准输出是**可重现的 UTF-8 JSON**（键排序、固定缩进、`ensure_ascii=False`），
  同一案例两次运行字节级一致。
- 退出码：`0` 成功；`1` 案例错误/运行时错误/文件缺失；`2` 命令行用法错误。
- 案例错误以 JSON 文档返回，`path` 字段定位到具体 JSON 字段
  （如 `$.initial.slots.A.ready`）或事件（如 `$.events[3].manifest_id`）。

运行测试：

```bat
python -m unittest discover -t . -s tests
```

重新生成全部合成案例：

```bat
python -m boot_replay.cases.build_cases
```

---

## 2. 三个命令

| 命令 | 作用 |
| --- | --- |
| `replay` | 对确定轨迹完整回放，列出每个事件的原子微步、所有断电观察点的引导决策、最终可启动分区及其证据（页摘要、授权、计数器）。 |
| `check` | 在至多 `max_power_losses`（≤2）次断电下，枚举所有合法微步前缀恢复，验证对外服务前确认了所选镜像（P1），并在策略允许且存在仍可信正式旧镜像时维持可用（P2）。返回最短失败轨迹与页/授权/计数器见证。 |
| `repair` | 从批准的有限修复动作目录中，按「擦除扇区次数 → 动作数 → 动作 ID 序列」的字典序选出使 `check` 通过的固定动作序列。 |

### 2.1 replay 输出要点

- `summary`：事件数、原子微步数、应用/拒绝/断电计数、页编程次数、最终计数器、活动槽。
- `events[].micro_steps`：该宏事件展开的全部原子动作（每页写入、每个标记、计数器各自一个微步）。
- `boot_snapshots`：初始、每次显式 `power_loss` 之后、以及最终的引导决策。
- `final_bootable_partitions`：逐槽给出 `complete / ready / signed_current / trusted_complete / formally_bootable`，可启动槽附带证据。

### 2.2 check 的判定语义

枚举的每个场景在重启后由同一条引导规则裁决：

1. **正式可启动（formal_boot）**——槽同时满足：完整（全部页摘要与清单一致）、
   READY、签名目录在当前授权下有效、代次 ≥ 计数器下限、不在试运行中、未停留在
   candidate 标记。选择代次最高者，平票优先活动标记，再按槽 id。
2. **候选恢复发布**——若槽仍带 candidate 标记，但计数器下限已达其代次且健康已
   确认，重启时补齐唯一缺失的活动标记原子写并引导它（见证记为 `recovered_publish`）。
3. **安全停机（safe_halt）**——没有任何正式可启动副本。不完整区域永远不能作为
   回退目标；已吊销镜像永远不能对外服务。

两条性质：

- **P1（绝不服务未确认镜像）**：对外服务只可能来自 formal_boot，引擎在协议层
  保证该性质不可被违反。
- **P2（maintain 策略下的可用性）**：当存在仍可信但被搁浅在计数器下限之下的旧
  镜像、且无正式可启动副本时，判 `fail`（availability_violation）；若所有副本
  都不完整或已吊销，则安全停机是唯一安全正确结局，判通过。
  `halt_allowed` 策略下安全停机记为 `pass_with_halts`。

### 2.3 repair 的动作目录与优化

批准的动作（确定性 ID）：

- `erase:<slot>:<sector>`：擦除非活动槽的一个扇区并恢复其写预算；
- `abort_session:<slot>`：中止未完成写会话（清理其占用扇区）；
- `complete_update:<slot>:<manifest>`：在安全目标上执行完整更新协议
  （自带所需擦除 → update → 分批 program → verify → READY+签名目录 →
  隔离试运行 → 健康回执 → 关试运行 → candidate → 确认健康 → 计数器提升 →
  发布活动标记）；
- `complete_switch:<slot>:<manifest>`：对已是候选的槽补齐确认/提升/发布。

规划器是目标导向的有界 BFS：宏动作内嵌自身所需的全部擦除，内务动作（单扇区
擦除/中止）仅在宏动作无法推进时每次取一个确定性分支。代价排序为
`(sector_erases, action_count, action_id_sequence)`，输出最优解与前若干备选。

---

## 3. 设备与协议模型

### 3.1 持久化对象

- 两个槽 `A` / `B`，各维护：写入代次 `generation`、绑定清单 `manifest_id`、
  已写页 `written_pages`（page_id → 摘要）、`ready`、签名目录 `sig_entry`、
  `candidate` / `active` 标记、试运行 `trial`、健康回执 `health`、可恢复写会话
  `session`、已读回页 `readback_verified`、擦除计数。
- 全局：只增可信计数器 `counter`（版本下限）、吊销清单 `revoked_manifests`、
  按扇区的可写页预算 `sector_budgets`。
- **原子性边界**：计数器与每条标记各自是一个原子操作；不假设跨设备/跨标记原子。
  `program` 按页展开为独立微步，因此一次编程可以只完成声明的任意合法前缀。

### 3.2 更新协议的不变量

- 新页只能写到非活动分区；打开写会话即把槽提交到清单的授权代次，此后
  **任何已切换到新代次的分区都不得混用旧页**（不同代次复用必须先擦除）。
- READY 只能在全部页写完且逐页读回核对后，与签名目录一起原子发布。
- 切换严格拆成四步：写 candidate → 确认健康 → 提升计数器 → 发布 active。
- 计数器提升的前置条件：候选本身完整可信且达到新下限，**且提升前存在另一份
  独立的完整可信副本**（否则计数器写与活动标记写之间断电会使设备无回退）。
- 只有当前授权下有效的健康回执与签名目录才被接受；健康回执绑定试启代次，
  晚到的回执（试启已关闭或代次不符）被拒绝且不改变状态。
- 试运行只允许完整、已读回、当前获签的 READY 镜像进入隔离自检；允许健康确认前
  试启，期间 `external_service=false`，绝不切入对外服务。
- 重试同一申请要核对原清单、目标槽与槽代次；失败不推进已提交版本。
- 「已写完」与「未来能被可信启动」是两个不同结论：前者只看页，后者还要求
  READY、读回、当前签名、代次与计数器关系。

### 3.3 断电与恢复

- 一次编程可在任意微步边界断电（含事件第一个原子动作之前）。重启从持久标记
  读取恢复：写会话记录剩余页，分批写与恢复只能针对同一版本。
- 反复断电时，重启可回到当时仍满足计数器下限与现行授权的旧镜像；旧镜像被
  吊销则报告安全停机。
- `check` 枚举 0、1、2 次断电的全部有序切点组合，逐场景重放剩余序列并裁决。

---

## 4. CASE.json 格式

顶层字段：

```json
{
  "schema_version": 1,
  "case_id": "happy-16x64",
  "device_group": "grp-fleet-7",
  "policy": { "fallback": "maintain" },
  "max_power_losses": 2,
  "sectors": [ { "sector_id": "S0", "pages": ["p00", "..."], "capacity": 11 } ],
  "manifests": [ {
      "manifest_id": "M2", "version": 2, "device_group": "grp-fleet-7",
      "authorized_generation": 2,
      "pages": { "p00": "sha256:..." },
      "auth_id": "AUTH-2", "signer": "signer-AUTH-2"
  } ],
  "initial": {
      "counter": 1,
      "sector_budgets": { "S0": 11 },
      "revoked_manifests": [],
      "slots": { "A": { "...": "SlotState" }, "B": { "...": "SlotState" } }
  },
  "events": [ { "type": "program", "manifest_id": "M2", "slot": "B", "pages": ["p00"] } ]
}
```

事件类型：`update`、`program`、`verify`、`mark_ready`、`trial_start`、
`health`、`trial_end`、`switch_candidate`、`switch_confirm_health`、
`counter_raise`、`switch_publish_active`、`revoke`、`erase`、`power_loss`。

校验严格：未知事件类型、类型错误、重复 id、跨扇区重复页、READY 但不完整、
两个活动标记、负预算、未知吊销清单等都会抛出带字段路径的 `case_error`。

---

## 5. 交付的合成案例（`cases/generated/`）

| 案例 | 覆盖情形 |
| --- | --- |
| `happy-16x64` | **16 个动作、64 页**的完整成功更新（1 update + 6 批 program + 9 切换/试运行动作）。 |
| `counter-no-active` | 计数器已提升但活动标记未写；重启经候选恢复发布继续引导。 |
| `half-each` | 两分区各剩半份，任何不完整区域都不能回退；repair 重建非活动槽。 |
| `retry-mixed-pages` | 重试试图把旧代次页混入新代次槽，被拒绝且不推进已提交版本。 |
| `late-health` | 试运行关闭后才到的健康回执被拒（晚到回执只适用对应试启代次）。 |
| `revoke-race` | READY 后、切换前发生吊销竞态，确认健康与计数器提升被阻止，旧镜像继续服务。 |
| `revoked-old-halt` | 旧镜像被吊销且新镜像不完整，唯一安全结局是停机。 |
| `batch-resume` | 分批写入中反复断电，重启按持久会话恢复并完成同一版本。 |
| `stranded-floor` | maintain 策略下可信旧镜像被搁浅在计数器下限之下，check 判失败并给见证。 |
| `halt-allowed` | 同一搁浅状态在 halt_allowed 策略下为可接受停机。 |

---

## 6. 代码结构

```
boot_replay/
  errors.py        带字段路径的类型化错误
  model.py         Manifest / Sector / SlotState / DeviceState / 信任谓词
  loader.py        CASE.json 严格校验（字段级错误定位）
  engine.py        事件 -> 原子微步展开、全部协议门控、引导决策
  replay.py        完整回放、切点枚举、切点状态重建
  check.py         至多两次断电的前缀组合枚举与 P1/P2 裁决
  repair.py        批准动作目录 + 有界 BFS 规划与代价优化
  cli.py / __main__.py   命令行与确定性 JSON 输出
  cases/build_cases.py   合成案例生成器（确定性）
tests/             unittest：协议、回放/check、repair、加载器/CLI、小页穷举对拍
```

### 穷举对拍（differential testing）

`tests/test_exhaustive.py` 内置一份**独立的朴素参考实现**，直接从原始持久字段
重算信任与引导结论，不调用引擎的谓词方法；在小页数（2/3/4 页）设备的全部可达
断电前缀状态上，逐状态比对引擎 `boot_decision` 与参考实现，并校验：宏/微两条
驱动产出的规范化状态一致、计数器单调不减、页不越界、扇区预算恒等式成立。

---

## 7. 设计说明与边界

- 摘要、签名、计数器都是虚构见证：页摘要用对排序 `(page_id, digest)` 的
  SHA-256 表达，签名目录是记录授权 id、代次与摘要见证的字典；吊销即把
  manifest_id 加入吊销集合，签名当前性随之失效。
- `check` 的场景数随切点 `n` 增长为 `1 + n + C(n,2)`；64 页快乐案例约 149 个
  切点、约 1.1 万个场景，纯标准库秒级完成。
- repair 默认深度上限 12（`repair_depth` 可调）；当所有授权都被吊销时返回
  `no_repair`，因为不存在任何可合法重建的可信镜像。
