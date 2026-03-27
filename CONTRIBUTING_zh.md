# 为 Relink 贡献代码

感谢你对 Relink 的关注。无论是提交 bug、改进文档、补充示例、增加测试、做重构，还是实现新功能，我们都非常欢迎。

本文档说明本项目的通用贡献流程。

## 你可以如何参与

你可以通过以下方式帮助项目：

- 报告 bug 或不清晰的行为
- 改进文档或示例
- 增加测试或 benchmark
- 处理带有 `good first issue` 标签的问题
- 提议或实现新功能
- 改进可移植性、安全性或性能

## 开始之前

如果是较小的修复，欢迎直接提交 Pull Request。

如果是范围较大的改动，建议先开 issue 讨论需求和设计，再开始实现。以下情况尤其建议先讨论：

- 公共 API 变更
- loader 行为变更
- feature flag 变更
- 大规模重构
- 跨平台行为或 `no_std` 相关变更

在创建新 issue 或 PR 之前，请先确认相关内容是否已经被讨论过。

## 开发环境

Relink 日常开发基于稳定版 Rust。当前最低支持的 Rust 版本是 `1.93.0`。

常见的本地准备方式如下：

```bash
rustup toolchain install stable
cargo test
```

CI 中也会覆盖 nightly 和交叉目标，但除非你的改动直接涉及这些部分，一般不需要在本地完整复现所有 CI 环境。

## 推荐工作流

1. Fork 仓库，并从 `main` 分支切出自己的工作分支。
2. 尽量保持改动聚焦。我们更欢迎小而清晰、便于 review 的 PR。
3. 如果行为发生变化，请补充或更新测试。
4. 如果公共 API、示例或用户可见行为发生变化，请同步更新文档。
5. 在本地运行格式化和相关测试。
6. 提交 PR，并清楚说明改动内容以及这样做的原因。

## 本地检查

至少请运行以下命令：

```bash
cargo fmt --all
cargo test
```

如果你的改动涉及 feature-gated 代码，也请运行：

```bash
cargo test --features full
```

如果你修改了平台相关代码或 workspace 中的其他 crate，在条件允许的情况下补充运行更多检查会很有帮助。例如：

```bash
cargo run -p windows-elf-loader --example from_memory
```

补充说明：

- `mini-loader` crate 会在 CI 中通过 nightly 工具链和 `no_std` 目标进行验证。
- 交叉目标验证主要依赖 CI 完成。

## 编码建议

请尽量保持与现有代码风格一致：

- 优先提交聚焦的改动，不要夹带无关清理
- 保持公共 API 清晰，并在需要时补充文档
- 除非是有意调整行为，否则尽量保持现有行为不变
- 对 bug 修复和行为变化，尽可能补充测试
- 保持示例和文档与代码同步

本项目包含底层 loader 逻辑和 `unsafe` 代码。修改这类代码时，请尽量做到：

- 改动范围尽可能小
- 在必要时用注释说明关键不变量
- 在 PR 描述中说明安全性考虑

## Commit Message

推荐使用 Conventional Commit 风格，这也和当前仓库历史更一致。例如：

- `fix(loader): reject malformed program header tables`
- `refactor(elf): wrap ELF metadata with semantic types`
- `docs(readme): clarify lazy binding workflow`

这不是强制要求，但会让提交历史更易于维护和阅读。

## Pull Request 自查清单

在打开 Pull Request 之前，请尽量确认：

- 改动基于最新的 `main` 分支
- PR 标题和描述清晰明确
- 相关测试已在本地通过
- 如果需要，文档和示例已经同步更新
- 没有把无关格式化或重构混在同一个改动里

## Review 流程

Review 过程中，维护者可能会要求：

- 收窄改动范围
- 补充或澄清测试
- 更新文档
- 更谨慎地处理底层或平台相关逻辑

如果需要来回修改，请不用有压力，这属于正常协作流程的一部分。

## Bug 反馈建议

如果你要报告 bug，以下信息会很有帮助：

- 目标平台
- Rust 版本
- 启用的 feature flags
- 最小复现示例
- 预期行为和实际行为

## 许可证

向本仓库贡献代码即表示你同意：你的贡献将按项目当前相同的许可证授权，即 MIT OR Apache-2.0。
