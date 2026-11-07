# 为 Relink 贡献代码

欢迎提交问题反馈、文档、示例、测试和代码改进。小修复可以直接提交 Pull Request；
公共 API 变更、大规模重构或加载与平台行为变更，建议先开 issue 讨论范围和设计。
开始前请检查已有 issue 和 PR，避免重复工作。

## 开发与检查

使用 Rust 稳定版，最低版本为 1.93.0。在仓库根目录运行：

```sh
cargo fmt --all --check
cargo test
cargo test --doc --features "full version log portable-atomic"
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --features "full version log portable-atomic"
```

默认 feature 已包含 `full`。如果改动涉及以下配置，请补充检查：

```sh
cargo check --no-default-features
cargo check --no-default-features --features use-syscall
```

`use-syscall` 与 `std` 互斥，因此不能使用 `--all-features`。
测试夹具与准备步骤见[测试分层](tests/README.md)和[示例指南](examples/README.md)。
CI 覆盖交叉目标及需要 nightly 的 `mini-loader` 构建；修改相关组件时，可在本地运行对应检查。

## Pull Request

1. 从 `main` 创建工作分支，保持改动聚焦。
2. 行为变更需更新测试，公共 API 变更需同步文档。
3. 在 PR 描述中说明问题、改动后的行为和验证结果；涉及 unsafe 代码时，说明不变量和安全性依据。

遵循现有代码风格，避免夹带无关重构。欢迎使用 Conventional Commit 风格的提交信息，
例如 `fix(loader): reject malformed program header tables`。

## 问题反馈

请提供目标平台、Rust 版本、启用的 feature、最小复现，以及预期行为和实际行为。

## 许可证

贡献内容按项目的 MIT OR Apache-2.0 条款授权。
