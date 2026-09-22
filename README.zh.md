# groky

[English](README.md) · [中文](README.zh.md)

**groky** 是 [Grok Build](https://github.com/xai-org/grok-build)（`grok`）的产品 fork。
agent、tools、MCP、ACP、TUI 与官方同一套，额外支持第三方模型
（OpenAI、Anthropic、OpenRouter、自定义 OpenAI 兼容接口）以及 ChatGPT Codex OAuth。

命令行二进制是 **`groky`**，可以和官方 `grok` 并存。

最新版本：[v0.1.17](https://github.com/yuWorm/groky/releases/tag/v0.1.17)

## 安装

macOS / Linux：

```sh
curl -fsSL https://raw.githubusercontent.com/yuWorm/groky/main/scripts/install-groky.sh | bash
groky --version
```

二进制在 `~/.groky/bin/groky`。groky 自己的配置在 `~/.groky/`
（`config.toml`、`vendor-auth.json`）。第一次启动（以及之后缺文件的升级）
会从 `~/.grok/` 拷过来；会话、xAI 登录、记忆、技能、插件仍和官方 `grok`
共用 `~/.grok/`（目录软链 + `GROK_AUTH_PATH`）。`GROK_HOME` 可整棵隔离；
`GROKY_SKIP_HOME_MIGRATE=1` 跳过拷贝/链接。

- 指定版本：`bash -s 0.1.0`
- 升级：再跑一遍上面的 `curl | bash`
- **不要**跑 `curl https://x.ai/cli/install.sh` —— 那会装官方 `grok`

Windows 未包含在 v0.1.0 里（上游 `bin/protoc` 是 Unix 桩）。发版矩阵和后续
PowerShell 脚本见 [INSTALL.md](INSTALL.md)。

## 使用

```sh
cd your-project
groky
```

| 目的 | 做法 |
| --- | --- |
| xAI Grok | `/login` —— 与官方 Grok Build 相同 |
| OpenAI / Anthropic / OpenRouter API key | `/provider-login` 再选供应商 |
| ChatGPT Codex（Plus/Pro，不是 `sk-`） | `/provider-login openai-codex` |
| Claude Pro/Max（不是 `sk-ant-`） | `/provider-login anthropic-claude` |
| 自定义 OpenAI 兼容端点 | `/provider-login` → 自定义供应商 |
| 切换模型 | `/model` |
| Fast 模式（GPT，含自定义 OpenAI 兼容中转站） | `/fast` |
| 去掉供应商密钥 | `/provider-logout` |
| 刷新供应商模型列表 | `/sync-models-dev`（别名 `/refresh-models`）；供应商列表 `r`；自定义模型列表 `Ctrl+R` |
| 更新 groky | `groky update` 或 `groky update --version 0.1.17`（Welcome：ctrl+u） |

xAI 登录未改（`AuthManager`、`~/.grok/auth.json`，与官方 `grok` 共用）。
第三方密钥不进 `config.toml`，而在 `~/.groky/vendor-auth.json`。供应商
401 会提示 `/provider-login`，不会跳 `/login`。

## 相对官方改了什么

| 做了 | 没动 |
| --- | --- |
| 多供应商目录、自定义供应商 | agent 循环、tools、MCP、ACP |
| `/provider-login`、`/provider-logout`、`/sync-models-dev`、`/fast` | `/login`、Welcome、`auth.json` |
| ChatGPT Codex OAuth（`openai-codex`） | 官方 `grok` 的 CDN 安装和自更新 |
| Claude Pro/Max OAuth（`anthropic-claude`） | Anthropic 控制台 API key（`anthropic`） |
| models.dev 推理档 / 上下文窗口 overlay | 默认压缩阈值（85%） |
| 二进制名 `groky`（`~/.groky/bin`）和配置家目录 `~/.groky` | 把 TUI 重写成另一套产品 |

## 官方文档

仓库内用户指南仍写 `grok`。本 fork 里命令是 `groky`。
`/login` 仍是 xAI；第三方鉴权走 `/provider-login`。

- 上游 README：[xai-org/grok-build](https://github.com/xai-org/grok-build)
- 在线文档：[docs.x.ai/build/overview](https://docs.x.ai/build/overview)
- 本仓库用户指南：[`crates/codegen/xai-grok-pager/docs/user-guide/`](crates/codegen/xai-grok-pager/docs/user-guide/)

常用入口：

| 指南 | 内容 |
| --- | --- |
| [入门](crates/codegen/xai-grok-pager/docs/user-guide/01-getting-started.md) | 首次启动与概念 |
| [鉴权](crates/codegen/xai-grok-pager/docs/user-guide/02-authentication.md) | xAI `/login`（不是供应商登录） |
| [快捷键](crates/codegen/xai-grok-pager/docs/user-guide/03-keyboard-shortcuts.md) | 键盘与鼠标 |
| [斜杠命令](crates/codegen/xai-grok-pager/docs/user-guide/04-slash-commands.md) | `/` 命令 |
| [配置](crates/codegen/xai-grok-pager/docs/user-guide/05-configuration.md) | `config.toml`、环境变量、路径 |
| [MCP](crates/codegen/xai-grok-pager/docs/user-guide/07-mcp-servers.md) | MCP |
| [Skills](crates/codegen/xai-grok-pager/docs/user-guide/08-skills.md) | SKILL.md |
| [自定义模型](crates/codegen/xai-grok-pager/docs/user-guide/11-custom-models.md) | 上游 BYOK 说明（本 fork 另有 `/provider-login`） |

从源码构建的依赖（Rust、DotSlash、protoc）与
[上游 “Building from source”](https://github.com/xai-org/grok-build#building-from-source)
相同。

```sh
cargo run -p xai-grok-pager-bin --bin groky
# 或
./scripts/tui.sh
```

crate 仍叫 `xai-grok-pager-bin`，方便跟 xAI merge。产品入口是 `groky`。

## 和 Grok Build 的关系

本仓库是产品 fork。需要上游修复时再 merge
[xai-org/grok-build](https://github.com/xai-org/grok-build)，不是每天 rebase。
维护说明：[`crates/codegen/xai-grok-shell/src/compat/UPSTREAM.md`](crates/codegen/xai-grok-shell/src/compat/UPSTREAM.md)。

上游不接受外部贡献（[`CONTRIBUTING.md`](CONTRIBUTING.md)）。
**groky** 的 issue 和改动请开在本仓库。

## 许可

第一方代码为 **Apache License 2.0**，见 [`LICENSE`](LICENSE)。
第三方与 vendored 声明见 [`THIRD-PARTY-NOTICES`](THIRD-PARTY-NOTICES)。
