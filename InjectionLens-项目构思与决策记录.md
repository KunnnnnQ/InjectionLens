# InjectionLens：项目构思与决策记录

> 本文记录 InjectionLens 从选题到开赛构建的过程，并如实标注每一步用到的 AI 工具，以符合比赛的 “AI & External Tools Disclosure” 要求。
> 标有【待填】的地方需要本人用自己的话补充。评委很可能追问这几处，提前想清楚有好处。

---

## 1. 时间线

| 时间（UTC+8） | 阶段 | 我做了什么 / 我的决定 | AI 工具参与了什么 |
|---|---|---|---|
| 9/18（周五）14:24 | 赛前：找方向 | 还没有想法，请 AI 按比赛主题给出候选方向 | ChatGPT 给出三个方向：ScamLens Student（它推荐的）、InjectionLens、BeforeShare |
| 9/18 14:31 | 赛前：选题 | **没有采用 AI 推荐的 ScamLens，而是选了 InjectionLens**，并要求先做技术调研再定方案 | — |
| 9/18 15:15 | 赛前：调研 | 要求调研主流做法、学界讨论和现有解决方案 | ChatGPT 整理了威胁模型、防御路线、代表研究和现有产品，形成初版方案 |
| 9/18 15:18 | 赛前：质疑 | 对初版方案提出 10 条质疑（见第 3 节）【待填：这些质疑是我自己写的，还是借助某个工具整理的】 | 【待填】 |
| 9/18 19:53 | 赛前：修订 | 采用修订后的定位 | ChatGPT 根据质疑修订方案，并复核竞品（发现 BrowseSafe、Check Point 等） |
| 9/18 20:08 | 赛前：合规 | 查阅比赛规则和管理员澄清，确认开赛前只做研究和准备 | ChatGPT 给出赛前准备清单和 MVP 范围 |
| 9/19 22:00 | **开赛** | 开赛前没有写任何项目代码（项目文件最早创建于 22:07:19） | — |
| 9/19 22:07–22:37 | 构建 | 把赛前定好的 MVP 范围交给编码代理实现，并运行验证 | Kimi 编码代理生成 MVP 代码（实际发出的指令以 Kimi 会话记录为准） |
| 9/19 22:40 起 | 审计 | 用 2025–2026 年的真实攻击报告审计 MVP，找出误报、绕过和覆盖盲区 | Claude Code 检索真实案例并运行对抗测试 |

---

## 2. 决策一：选 InjectionLens，而不是 AI 推荐的 ScamLens

- **事实**：ChatGPT 推荐的是 ScamLens Student（面向学生的诈骗截图解释器），理由是用户具体、范围小、容易演示。
- **我的选择**：InjectionLens，也就是检测网页中针对 AI 的提示注入。
- **理由**：【待填，1–2 句。例如你当时看重的是什么：新颖性、与“AI 带来的新兴威胁”这个比赛方向的契合度，还是想挑战更难的技术问题】

---

## 3. 决策二：先调研，再定方案

赛前调研（ChatGPT 协助）得到的要点如下。

**问题界定**
- 需要区分三类问题：越狱（用户让模型违反安全规则）、直接提示注入（用户覆盖开发者指令）、间接提示注入（恶意指令藏在网页、邮件、文档或工具返回结果里）。
- 项目聚焦第三类。OWASP 把 Prompt Injection 列为 LLM01:2025。
- 风险大小取决于 Agent 的权限：只做摘要时，后果最多是结果被操纵；能访问邮箱、网盘或外网时，就可能导致数据外泄。

**主流防御路线**

| 路线 | 思路 | 主要问题 |
|---|---|---|
| 规则与结构扫描 | 找隐藏 DOM、零宽字符、编码文本 | 容易绕过，也容易误报 |
| 专用分类器 | 用小模型或 LLM 判断是否恶意 | 难以覆盖长文、跨段和新型攻击 |
| 来源标记（Spotlighting） | 标记“这是不可信数据” | 不构成真正的安全边界 |
| 模型训练（Instruction Hierarchy、StruQ） | 训练模型优先服从高权限指令 | 普通开发者难以自己实现 |
| 任务/动作检查（Task Shield） | 检查每个动作是否服务于用户目标 | 增加延迟和复杂度 |
| 权限隔离（CaMeL、沙箱、最小权限） | 限制注入成功后的后果 | 无法识别攻击本身 |

**现有产品**：Azure Prompt Shields、Google Model Armor、Amazon Bedrock Guardrails、Meta Prompt Guard 2 等。修订时又发现 Perplexity 已开源 BrowseSafe（网页注入分类），Check Point 已有 Agent 行为防护（检查工具调用是否偏离任务）。

**争议点**
1. 误报严重：安全教程本身就包含攻击语句。
2. 内容是否恶意取决于用户的任务。
3. 检测不等于保护。
4. 没有单一方案能保证安全。

**赛前判断 vs 开赛后的新证据**：赛前认为“现实中的攻击尚未成熟”。开赛后的审计发现，Unit 42、Google、Forcepoint 在 2026 年都报告了在真实网页上发现的攻击，所以问题陈述已更新为“已经发生、正在增长”（详见《InjectionLens-真实案例与调整方案.md》）。

---

## 4. 决策三：推翻初版方案的核心设计

初版方案是“单一 AI 视图 + 以隐藏内容为核心 + 乘法风险公式”。针对它提出的质疑【待填：来源】，以及因此做出的修改：

| 初版设计 | 问题 | 修改后 |
|---|---|---|
| 只有一个 “AI View” | 不同 Agent 读网页的方式不同，有的读原始 HTML，有的用 Readability，有的读无障碍树或截图 | **多摄入管线矩阵**：HTTP 源、渲染 DOM、Reader/Markdown、无障碍树 |
| 可疑度 × 隐蔽度 × 任务冲突 × 能力可达 | 乘法下隐蔽度为 0 时，可见的恶意指令会被直接放行 | 证据等级和影响等级分开计算，隐蔽度只加权、不设门槛 |
| 以“是否隐藏”为核心信号 | 隐藏不等于恶意（sr-only、SEO），可见也不等于安全（社会工程话术） | 看它是否在对 AI 说话、意图是什么、能否到达危险能力 |
| 由用户自己填写 Agent 的工具权限 | 普通用户填不出来 | 预设能力模板（仅摘要、浏览器代理、全权限） |
| 没有评估方案 | 无法证明有效 | 用攻击集加良性难例评估，重点报告误报率 |
| 检测器不在威胁模型里 | 用来判断的 LLM 本身也会被注入 | 把检测器纳入威胁模型 |
| 只比较同一份 HTML 的不同渲染结果 | 服务器可能按 User-Agent 给 AI 返回另一份内容 | 增加 UA 差异探针（只作为信号，不作为证明） |

**定位收窄**：既然 BrowseSafe 已经能做网页注入分类，Check Point 已经能做任务偏离检查，这两点都不能再作为核心创新。项目定位因此收窄为：

> **InjectionLens compares how different agent pipelines ingest the same webpage, highlights suspicious instructions, and shows what dangerous capabilities those instructions could reach.**

---

## 5. 决策四：赛前合规

- 看过管理员的澄清：开赛（9/19 10:00 AM EDT，即 22:00 UTC+8）前只允许头脑风暴、研究和熟悉工具；代码、项目骨架和 UI 设计都必须等开赛后才能开始。
- 执行情况：开赛前只做了研究和规划，没有写项目代码。项目文件最早创建于 22:07:19，已保留时间戳和 Kimi 会话记录备查。

---

## 6. 决策五：锁定 MVP 范围（开赛后交给 Kimi 实现）

**核心路径**：同一个网页 → 四种摄入结果不同 → 精确定位差异节点 → 切换 Agent 权限后风险等级随之变化。

**Must have**
- 只分析自己控制的 HTML 页面
- 四条摄入管线：HTTP Source、Rendered DOM、Reader/Markdown、Accessibility Tree
- 摄入矩阵，并能映射回具体 DOM 节点、在页面上高亮
- 能力模板，输出证据等级和影响等级，不输出虚假的“安全概率”
- 测试页：2 个可见攻击、2 个隐藏攻击、2 个良性难例、1 个 UA 条件响应

**Should have**：浏览器 UA 与 AI 抓取器 UA 的响应对比、简单的任务冲突分类、小型评估、导出 JSON 报告

**Won't have（留作 future work）**：PDF、截图和 OCR、任意公网 URL、精确模拟某个具体产品、训练模型、完整 AgentDojo、自动清洗内容

> 注：以上是赛前定好的范围；实际发给 Kimi 的指令以 Kimi 会话记录为准。

---

## 7. 开赛后：审计与下一步

MVP 用 30 分钟就跑通了。随后我用真实攻击报告审计了它，发现：普通句子被判为严重；隐藏的恶意指令加上 “for example” 就被降为低风险；真实攻击话术漏报；HTML 属性没有覆盖；SSRF 防护可以绕过。修复和评估计划见《InjectionLens-真实案例与调整方案.md》。

---

## 8. AI 使用披露（Devpost，英文）

> **AI & External Tools Disclosure**
> - **ChatGPT** — before the 10:00 AM EDT start (pre-event preparation, as permitted by the organizers): proposed three candidate directions (I chose InjectionLens over its recommended option), researched existing prompt-injection defenses and products, and revised the design after I challenged its first draft. No code.
> - **[Fill in, if applicable]** — helped me structure the 10-point critique of the first design.
> - **Kimi coding agent** — after the start (22:07–22:37 UTC+8), generated the initial MVP (four ingestion pipelines, React UI, first seven test pages) from the scope I had fixed before the event.
> - **Claude (Claude Code)** — researched 2025–2026 incident reports and ran adversarial tests against the MVP detector, surfacing false positives and a two-word bypass.
> - **[Fill in]** — how the fixes and the evaluation were implemented.
>
> The choice of problem, the scope, and the design trade-offs were my decisions. I reviewed the generated code and can explain every module.
