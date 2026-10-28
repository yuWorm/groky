# groky

[English](README.md) · [中文](README.zh.md)

**groky** 是 [Grok Build](https://github.com/xai-org/grok-build)（`grok`）的产品 fork。
agent、tools、MCP、ACP、TUI 与官方同一套，额外支持第三方模型
（OpenAI、Anthropic、OpenRouter、自定义 OpenAI 兼容接口）以及 ChatGPT Codex OAuth。

命令行二进制是 **`groky`**，可以和官方 `grok` 并存。

最新版本：[v0.1.25](https://github.com/yuWorm/groky/releases/tag/v0.1.25)

## 安装

macOS / Linux：

```sh
curl -fsSL https://raw.githubusercontent.com/yuWorm/groky/main/scripts/install-groky.sh | bash
groky --version
```

Windows x86_64（在 PowerShell 中运行）：

```powershell
irm https://raw.githubusercontent.com/yuWorm/groky/main/scripts/install-groky.ps1 | iex
groky --version
```

Windows 安装器会将 `groky.exe` 放到 `%USERPROFILE%\.groky\bin`，
并将该目录加入用户 `PATH`。如果提示找不到 `groky`，请重新打开 PowerShell。


macOS / Linux 二进制在 `~/.groky/bin/groky`。groky 自己的配置在 `~/.groky/`
（`config.toml`、`vendor-auth.json`）。第一次启动（以及之后缺文件的升级）
会从 `~/.grok/` 拷过来；会话、xAI 登录、记忆、技能、插件仍和官方 `grok`
共用 `~/.grok/`（目录软链 + `GROK_AUTH_PATH`）。`GROK_HOME` 可整棵隔离；
`GROKY_SKIP_HOME_MIGRATE=1` 跳过拷贝/链接。

- 指定版本：Bash 和 PowerShell 完整命令见 [INSTALL.md](INSTALL.md)
- 升级：重新运行对应平台的一键安装命令
- **不要**跑 `curl https://x.ai/cli/install.sh` —— 那会装官方 `grok`

从 v0.1.23 起提供 Windows x86_64 二进制。发版矩阵和指定版本安装命令见
[INSTALL.md](INSTALL.md)。

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
| 管理多个 ChatGPT Codex 账号 | `/provider-accounts` —— 添加、备注、选择或移除单个账号 |
| Claude Pro/Max（不是 `sk-ant-`） | `/provider-login anthropic-claude` |
| 自定义 OpenAI 兼容端点 | `/provider-login` → 自定义供应商 |
| 删除自定义供应商 | `/provider-login` → 选中供应商 → `d`（或 `Delete`）→ `Enter` 确认；`Esc` 取消 |
| 查询订阅 / 网关额度 | `/provider-usage`（别名 `/pusage`、`/usage providers`） |
| 切换模型 | `/model` |
| 接着其他 agent 的会话继续工作 | `/import-session` —— 自动发现当前目录的会话 |
| Fast 模式（GPT，含自定义 OpenAI 兼容中转站） | `/fast` |
| 退出供应商的所有账号 | `/provider-logout` |
| 刷新供应商模型列表 | `/sync-models-dev`（别名 `/refresh-models`）；供应商列表 `r`；自定义模型列表 `Ctrl+R` |
| 更新 groky | `groky update` 或 `groky update --version 0.1.25`（Welcome：ctrl+u） |

更新默认使用 `https://gh-proxy.com`，下载时显示进度条、速度和剩余时间；
服务端未提供文件大小时显示已下载字节数。
`groky update --mirrors https://your-mirror.example` 可为本次更新指定镜像，
`--mirros` 是同义参数；`--mirrors direct` 则直连 GitHub。
镜像同时用于最新版查询、二进制和校验文件下载，GitHub Token 不会发送给镜像。
只使用可信镜像；此参数不会保存，也不改变首次安装脚本。
详见[更新说明](INSTALL.md#update-mirrors-and-download-progress)。

xAI 登录未改（`AuthManager`、`~/.grok/auth.json`，与官方 `grok` 共用）。
第三方密钥不进 `config.toml`，而在 `~/.groky/vendor-auth.json`。供应商
401 会提示 `/provider-login`，不会跳 `/login`。

删除自定义供应商会一并移除其配置、模型和保存的凭据，并立即刷新供应商与模型列表。
内置供应商不能删除；`/provider-logout` 仅退出登录，保留自定义供应商配置供以后使用。

Codex 各账号分别保存凭据和模型目录。在 `/provider-accounts` 中（也可通过
`/provider-login openai-codex` 打开），按 `a` 添加登录、`Enter` 选择、
`r` 修改备注、`d` 确认后移除。选择账号会设置新会话的默认账号，并只切换当前会话；
正在执行的一轮会先完成，再应用切换。其他会话及恢复后的会话保留各自选择。
删除默认账号后须手动选择，不会自动改用另一个账号。旧版单账号登录会自动迁移。
不自动轮换账号，也不合并订阅额度。

新登录的 Codex 账号会优先用登录结果中的邮箱作为备注。旧账号重新登录时，仅补全
尚未修改的默认账号 ID 备注；已有邮箱备注、手动备注都会保留，刷新 token 也不会
改写备注。缺少邮箱或邮箱信息不可用不影响登录。同名账号在管理列表中单独展示
账号 ID 以便区分。邮箱仅用于显示，凭据、模型目录和额度仍按账号 ID 隔离。

### 导入会话

`/import-session` 自动发现 **omp、pi、Claude Code、Codex、OpenCode** 中工作目录
与当前目录匹配的会话，支持符号链接路径匹配。选择一条记录，按 **Enter** 查看
有效上下文条数和迁移警告，再按 **Enter** 确认导入；**Esc** 取消预览。
按 **f** 可在当前项目和全部项目之间切换。

导入会创建并打开新的 groky 原生会话，不自动发送消息，也不修改来源文件。
继续对话前会重建选定分支和压缩边界，历史工具调用不会重新执行。
新会话使用 groky 的模型、指令和权限，不继承来源 agent 的凭据、运行中任务或文件回滚状态。

命令行导入只操作本地文件，不要求登录：

```sh
groky sessions import --list
groky sessions import --from pi SESSION_ID
groky sessions import --from codex /path/to/rollout.jsonl
groky sessions import --from opencode /path/to/opencode.db --id SESSION_ID
groky --resume NEW_SESSION_ID
```

不指定 ID 或路径时只列出候选，不会批量导入。`--all` 扩大到其他目录，
`--json` 输出结构化结果。扫描尊重 `CODEX_HOME`、`CLAUDE_CONFIG_DIR`、
omp/pi 的目录设置及 OpenCode 的 XDG/`OPENCODE_DB` 路径。
供应商加密检查点无法解密；无法重建有效上下文时会报错，不会用编造的摘要代替。

### 供应商额度

`/provider-usage` 分别列出已保存的账号，标明默认账号和当前会话账号，按 `r`
刷新。刷新失败时，保留的旧数据会标记为过期快照；更换凭据或删除账号后，会丢弃
该账号尚未返回的旧请求结果。查询不会切换账号或合并额度。同一个网关有多个
API key 时，为每个 key 添加独立的自定义供应商。

自定义供应商可独立选择 **Platform**：Generic、Sub2API、One API、New API，
不影响推理协议。旧配置默认 Generic；通过 `/provider-login` 编辑，在模型列表
按 `Esc` 返回表单。可选的 **Usage base URL** 填网关服务根地址，不是完整用量接口，
且必须与推理地址同源。留空时仅去掉末尾 `/v1`，保留其他路径前缀。

| 来源 | 展示内容与限制 |
| --- | --- |
| Codex | 各账号的用量窗口、重置时间及服务端返回的 credits。使用 ChatGPT 内部接口，接口变化可能影响兼容性。 |
| Sub2API / New API | 网关返回的 key、订阅或钱包额度，不等同于上游订阅额度或本地 token 统计；缺少货币换算信息时保留网关额度单位。 |
| One API | 分别展示返回的上限和已用量。公开响应无法确定是 key 还是账号范围，因此不推算剩余额度。 |
| Claude 订阅 | 按 `o` 打开官方 Settings → Usage，不直接用 OAuth 查询额度；网页实际显示的是浏览器当前登录的账号。 |
| Generic | 选择兼容的平台类型后才能查询。 |

### SSH 项目与显式 SSH 工具

SSH 目标自动复用 `~/.ssh/config` 和系统 SSH 配置中的具体主机别名。
**已连接不等于已授权**，连接成功不会自动给 agent 开放访问权限。

```sh
groky ssh                                  # 独立 SSH 管理界面
groky ssh add                              # 交互式添加目标表单
groky ssh open                             # 选择服务器与远端目录
groky ssh open dev                         # 在 dev 上选择目录
groky ssh connect dev --interactive        # 处理主机信任、密码及私钥口令
groky ssh list
groky ssh add my-server --id dev --label "Development"
groky ssh open dev /srv/project
# 已有可用于非交互登录的认证方式时：
groky ssh connect dev
groky ssh disconnect dev
```

独立管理器复用 `/ssh` 的操作界面，不打开聊天，也不要求模型／供应商登录。
可以添加、编辑和删除手动目标，连接／断开、查看诊断和浏览远端目录。选择项目后，将已验证的主机身份和规范化目录
交给完整 TUI；访问授权与 worker 准备由最终项目会话完成。独立管理器不提供会话授权／默认授权控制。
关闭管理器不会断开显式保留的连接，需要时使用 `ssh disconnect`。
`Enter` 只连接选中的服务器，已连接时再次按下不会断开。普通 SSH 工具授权请在聊天内打开 `/ssh`；
`o open project (worker)` 是独立的显式入口，`ssh open ...` 仍直接进入远端项目流程。

两个管理界面均支持 `e` 编辑选中的手动目标，`x` 打开删除确认框，底部按钮也可点击。
编辑保留目标 ID 和表单未展示的设置。仅修改名称不会中断访问；修改连接或 worker 设置、
删除目标时，会断开该目标连接并撤销其授权。
导入的 OpenSSH 目标只读：请在界面显示的源文件中自行编辑或删除条目，
再进入高级页面，在未选中有效授权的目标上按 `r` 刷新。
刷新会重新读取外部配置；有效连接配置变化时，旧连接和授权不再复用。

交互式入口要求标准输入和标准输出均连接终端。`ssh list`、`ssh disconnect`、
`ssh add HOST ...` 及普通 `ssh connect TARGET` 保持原有文本／JSON 行为。
`--interactive` 与 `--json` 不能同时使用；`ssh add` 的目标字段及 `--json` 必须同时提供 `HOST`。

**显式 SSH 工具不需要在远端安装 groky 或 worker。** 它们直接复用已认证的原生
SSH 连接，通过 SFTP 操作文件、通过 POSIX shell 执行命令。SSH 服务端需启用 SFTP；
搜索还需要远端 `rg`。

**SSH 项目会自动管理匹配版本的远端 worker。** 打开或恢复项目时，groky 检测远端系统、
架构以及 worker 的产品版本和协议版本。缺失时自动安装；本机升级后，下次打开或恢复时
自动安装与本机完全一致的发布版本，不会擅自使用 `latest`。支持 Linux、macOS 的
x86_64、aarch64。

优先让远端下载对应发布产物及必需的 SHA-256 校验文件。远端下载失败时，界面展示完整错误，
询问是否改用**本机网络下载，再通过已认证的 SSH/SFTP 上传**。按 `Enter`/`y` 或点击底部
按钮同意，按 `n`/`Esc` 拒绝。下载、上传、校验和版本检查全部成功后，才发布到远端
`~/.groky/workers/<版本>/<系统>-<架构>/groky`；不需要 sudo，也不修改系统 `PATH`。
不同版本并存，使用独立守护进程；失败不会覆盖原 worker，也不会静默使用不兼容版本。

开发构建没有对应的发布下载：仅在本机与远端平台相同时，经明确同意上传本机可执行文件，
以 SHA-256 区分构建。跨平台请使用正式发布版本，或提供匹配的交叉编译 worker。
显式配置 `--worker-command '/absolute/path/groky worker --stdio'` 后，该命令由用户管理：
groky 仍检查兼容性，但不会覆盖或自动更新它。远端仍需自行提供 Git、ripgrep 及项目工具；
worker 不需要 xAI 登录，模型请求和供应商凭据都留在本地。

**为当前草稿选择 SSH 服务器**：打开 `/ssh`，选中服务器后按 `Enter` 或点击。
已连接的服务器直接回到输入框；未连接的才进入连接／认证流程。
所选目标显示为可删除的 SSH 标签，继续输入需求，准备好后再发送；**选择本身不会发送消息，
也不会启动 agent**。正常发送时，目标的精确 ID、地址与需求一起交给 agent。
已有文字、图片和粘贴块保留；重新选择服务器会替换目标标签。
选择目标不等于授权，不改变当前会话的默认授权，也不启动 worker 或切换项目。
agent 真正操作时缺少权限，才会申请授权；仍可用 `g` 主动授予访问权限。

输入 `/ssh `（或 `/remote `，末尾有空格）就会自动显示服务器候选，**不用先按回车**。
继续输入可按名称、host、地址或 ID 筛选；候选显示地址、配置来源和稳定 ID。
`↑`/`↓` 选择，`Tab` 补全精确 ID（不连接），`Enter` 确认选中服务器，`Esc` 收起候选。
离开再进入命令会重新读取配置；加载和筛选候选本身不连接、不授权、不启动 worker。

也可输入完整引用，例如 `/ssh xjsf-platform-ynnu` 或 `/ssh QA storage`，
按 `Esc` 收起候选后再按回车，按原文指定而不接受补全。名称带空格不用加引号。
匹配顺序为稳定 ID、精确 OpenSSH 别名、唯一显示名称／host。名称重复时只列出匹配候选；
同一服务器即使有多份授权，在草稿选择器里也只显示一次。找不到名称时保留列表，不猜测或连接相似目标。

**打开远端项目**：在管理器中选择 `o open project (worker)`。
目录选择器和授权框都会明确标注需要 worker；批准后准备匹配版本的 worker，
再打开单独的远端项目会话。Welcome 页的 `Ctrl+S` 没有当前聊天，默认 `Enter` 只连接服务器。

两种目录选择器均支持方向键或 `j`/`k` 选择、`Enter` 进入子目录、`Backspace` 返回上级、
`/` 输入远端路径。目录页的 `o` 按当前流程确认目录：用于会话授权，或用于打开项目。
仅浏览目录不会安装 worker，也不会给模型授予访问权限。

**Remember this project（记住此项目）** 默认不勾选。保存的权限仅适用于同一目标、
主机身份和完全相同的规范化远端目录，不受本机启动目录影响。已有权限不会自动扩大；
换目录、主机身份变化或请求更大权限时需要重新确认。不选择记住时，授权仅对当前获准会话有效。

`c` 连接／断开，`a` 添加目标，`d` 查看连接详情，`m` 打开高级权限管理。
基础页面也可用 `g` 申请会话授权；高级页面中尚无授权时的 `u` 会打开同一个授权目录选择器。
按 `o` 选择目录后，确认已验证的身份和权限；手动授权默认只读，可主动勾选写入／执行，
`u` 在批准后自动继续设置默认授权。未指定目录的外部授权请求也使用此选择器，权限不得超出原请求。
`Esc` 取消正在等待的请求；授权框中的 `n`、`Ctrl+d` 或拒绝按钮表示明确拒绝。
查找、连接和身份／目录检查失败会把真实错误交回原工具，不再误报为用户拒绝。
目录错误进入完整诊断，并保留上次有效目录供重试。
高级管理中每份有效授权单独占一行，`r` 仅撤销选中授权。目标行和底部按钮可点击，滚轮可滚动列表；
权限选项支持点击、`Tab`/`Space`，`PgUp`/`PgDn` 查看换行后的完整信息。

模型申请 SSH 访问权限时会自动弹出确认框，并等待你的实际决定。批准后，将实际获准的目录和权限
返回给原工具调用，直接继续任务，无需再发送“已授权”或“继续”。拒绝、取消、客户端断开或关闭会话
都会终止该请求；迟到的批准不能恢复已取消的请求。

每个 SSH 请求独立保留授权和认证状态；并发请求排队显示，不覆盖当前弹窗或已输入的内容。
当前请求完成、取消或过期后继续显示下一项；没有其他待办时，访问授权和命令审批成功后直接回到聊天，
不再停留在服务器列表。远端项目授权继续原有的项目打开流程；sudo 密码框只关联到已批准的那条命令，
处理完成后恢复被暂时打断的弹窗。

SSH 授权监听独立于工具调用运行。监听中断时会明确报错，恢复后与本地服务核对并补回仍有效的待办，
不会自动重放命令或授权决定。因客户端断开而取消的请求，需要明确重新发起。

SSH 文本输入框显示原生终端光标；密码、私钥口令和多步认证输入始终保持遮罩，
光标会跟随输入、左右移动和当前回答，并在需要时滚动到可见区域。

SSH 操作审批直接展示高亮的多行命令、完整文件内容或修改前后内容，不再以转义 JSON 作为主预览。
支持滚轮、方向键／`j`／`k`、`PgUp`／`PgDn`、`Home`／`End`；`d` 切换原始详情，`c` 复制原始命令。
审阅完整预览后，`y` 仅允许本次，`a` 允许当前 SSH 会话和当前授权内的同类操作，`n`／`Esc` 拒绝。
执行命令和写入文件分别记忆批准；规则不会继承到其他会话或其他授权，关闭会话、撤销授权或客户端
断开后失效。高级页面选中授权，按 `p`（ask each time）可恢复每次询问。
自动批准不会扩大访问权限，也不会跳过主机身份检查；远端命令默认具有 SSH 用户的权限，工作目录不是沙箱。

需要以 root 执行时，`ssh_run` 使用 `sudo: true`。审批会明确展示 SSH 登录身份、root 执行身份、
完整命令和工作目录。root 命令只能逐次批准，普通命令的会话批准不能覆盖提权。远端 sudo
确实要求密码时，在本地隐藏输入框输入该 SSH 账号的 sudo 密码；密码仅通过当前 SSH 连接发送，
不进入模型、工具参数或对话历史，也不保存。`NOPASSWD` 仍需审批，但不会索取密码；受管 sudo
不会复用缓存凭据。执行前取消、过期或撤销授权会终止命令，失败后不自动重放；执行开始后，
连接中断不代表远端命令已经停止。

服务器 sudo 策略必须允许运行 root shell 包装命令；仅允许指定命令的 sudoers 或强制 TTY
策略可能拒绝此路径。SFTP 读取、写入和编辑不会隐式提权。这不是 shell 沙箱：普通命令仍保有
SSH 账号原有的全部权限，包括服务器已配置的免密 sudo 权限。

支持密码、带口令私钥、ssh-agent 和 keyboard-interactive。主机信任确认与访问授权
分别处理。密码输入隐藏；只有主动选择记住时才使用系统凭据库，凭据库不可用时禁用
记住选项，不回退到明文文件。`ssh connect` 默认仍为非交互命令；需要输入密码或确认主机时，
使用 `ssh connect TARGET --interactive`、独立管理器或 `/ssh`。

`known_hosts` 检查按主机和端口隔离，允许同一目标保存多种密钥算法。已保存的密钥变化时，
`StrictHostKeyChecking` 允许询问（`ask`）时，`/ssh` 会展示新旧指纹和记录位置；
独立核实新指纹后，才可按 `r` 替换并保存。
替换前会生成 `.old`（或带编号的）备份，保留无关记录；确认期间文件变化，或记录存在歧义、
属于全局文件、使用通配符时，不自动覆盖，需手动核实处理。目标管理页按 `d` 查看所选目标的
配置、授权详情及最近的 SSH 错误。正常详情不再作为错误显示：已连接状态用绿色，仅真实错误用红色；
长诊断和主机密钥详情支持换行、滚动查看。不支持的转发指令
会明确报错，不会静默忽略：需要转发时请使用系统 OpenSSH，或将这些指令限定在单独的主机别名中。
目录选择和授权草稿可按 `Esc` 或点击关闭按钮取消。目录访问、授权或新增目标保存失败会自动打开完整诊断；
按 `Esc` 返回保留的目录或表单。目录跳转失败时恢复上一个有效目录，避免显示路径与实际打开目录不一致。
保存目标和打开项目期间会拦截重复提交；项目启动失败会回到
来源管理页展示错误，并允许重试。远端 worker 使用短路径、用户私有的 socket 目录，避免较长的
home 目录触发 Unix socket 路径长度限制。

两种执行方式：

- **SSH 项目：** 普通文件、编辑、搜索、命令和 Git 操作在远端 workspace 执行。
  项目指令、skills、hooks、MCP、LSP 跟随远端项目；TUI、模型请求、会话记录与供应商凭据留在本地。
  远端 hooks 收到已验证的远端 cwd/root，不会收到本地会话记录路径。
  指令与 skills 的发现范围限定在已授权根目录内，不加载父目录指令或指向根目录外的
  符号链接；skill 正文及斜杠 skill 命令通过远端 worker 读取，不读取本机同名路径。
- **任意会话中的显式 SSH 工具：** `ssh_read`、`ssh_write`、`ssh_edit`、
  `ssh_search`、`ssh_run` 可指定 `target`，显式目标优先；省略时必须已有用户选定的
  SSH 默认授权。这个默认值不会重定向普通本地工具。`ssh_targets` 列出已配置的手动目标和
  OpenSSH 候选的安全元数据，以及每个候选在当前会话中的授权；发现本身不授权，也不暴露凭据。
  优先使用返回的 `target_id`，也支持精确 OpenSSH 别名和唯一的精确显示名称／host。
  同名歧义会返回候选 ID，不会猜测相似服务器。`ssh_request_access` 等待用户批准后，
  将实际获准的授权交回原工具调用，不能自行授权。
  即使在 SSH 项目内，这些显式工具也不启动 worker，不加载远端项目指令、skills 或 hooks。
  文件读取支持 UTF-8 文本及行范围，不解码图片/PDF；读取输出以及覆盖/编辑已有文件时的
  原文快照有大小上限。覆盖已有文件要求 SFTP 支持 `posix-rename@openssh.com`，
  不支持时在写入前报错。编辑会在原子替换前复核原文，但不能提供跨客户端的并发 CAS 保证。
  `ssh_task_query`、`ssh_task_cancel` 只能操作所选授权范围内的任务。
  查询时用 `task_id` 读取任务输出，用 `operation_id` 检查已记录的操作，两者都省略
  则列出任务；这些 ID 不能交给本地任务工具使用。
  agent/会话的工具白名单、黑名单与能力限制仍然生效；关闭默认工具注入的自定义
  profile 保留其显式工具列表，不自动追加 SSH 工具。

授权包含远端根目录及读/写/执行能力，默认只对当前会话有效；保存为项目规则需要
主动选择，子 agent 只能继承已授权的子集。目标授权不会绕过具体操作审批。
**run 的工作目录不是沙箱：** 命令仍拥有远端 SSH 用户的系统权限。
撤权立即在本地阻止新调用。仅用于无 worker 工具的授权无需远端确认；曾交给项目 worker
的授权仍需 worker 确认，断线时显示远端确认待完成。已经启动的任务需要单独取消，
无 worker 任务在撤权后仍可用任务记录中的原授权 ID 取消。

无交互恢复可复用已有授权，但仍需可用的非交互 SSH 认证及普通工具权限。
需要 SSH 交互时会立即失败；`--always-approve` 不会代替远端操作审批。

SSH 恢复默认只恢复对话；加 `--restore-code` 后，请求批准在已验证的远端根目录
检出会话保存的 Git HEAD。切换 HEAD 前先 stash 当前 tracked/untracked 改动，
结果显示 stash 引用或保护失败原因。这里是 **HEAD 级恢复**，不是恢复历史暂存区、
未暂存或未跟踪文件快照，也不会检出本机同名目录。
使用 `--resume <会话ID> --worktree --restore-code` 时，原远端工作区保持不变；
新 worktree 的根目录需要单独授权，恢复只作用于该子工作区。不加 `--restore-code`
则保留普通 worktree 的复制行为。

持久覆盖写入用户级 `~/.groky/config.toml`：

```toml
[ssh.targets.dev]
host = "my-server" # 已有的 OpenSSH 别名
label = "Development"
user = "developer" # 可选覆盖
# 可选：自行管理 worker（关闭自动安装和更新）：
# worker_command = ["/usr/local/bin/groky", "worker", "--stdio"]
```

优先级为 groky 目标配置、用户 SSH 配置、系统 SSH 配置、默认值。匹配配置保留
first-value-wins 语义，`IdentityFile` 累积；仓库配置不能覆盖连接身份或凭据。
这不等于完整兼容 OpenSSH：生效但尚不支持的指令会明确报错，不会静默忽略，
例如 `Match exec`、GSSAPI 认证、ControlMaster 和 agent 转发。

连接池独立于单次工具调用，支持复用和持有。默认嵌入式 TUI 的连接池随该进程存活；
使用 `groky --leader` 可与其他 leader 模式 TUI 及 `groky ssh connect` 的手动持有共享
持久连接池，但授权仍按会话隔离。传输中断不会自动重放 write、edit 或 run。
无 worker 任务的 ID 和有界 stdout/stderr 历史由本地服务持有，不由远端守护进程持有；
应使用 `ssh_task_query` 查询，不承诺完成后自动唤醒。未确认退出就断线时，结果记为未知，
远端进程可能仍在运行；发送取消请求不等于已确认终止。
SSH 项目的 worker 则继续跨 channel 断线持有自己的任务；worker 自身退出时，
未完成结果同样记为未知，不能据此认定远端没有产生副作用。

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
