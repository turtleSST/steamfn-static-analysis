# 01 · 网站、安装链与样本身份

## 1. 公开说明与实际 HTTP 响应

[站点教程](https://help.steamfn.com/)将流程称为“Steam 活动渠道激活”，要求管理员终端运行远程 PowerShell 内容，随后在 Steam 激活界面输入产品码。教程还要求在游戏消失时重新运行安装步骤。这些文字说明其宣传方式，不作为安全性或官方授权的证据。

2026-09-30 保存的响应具有 User-Agent 差异：

| 请求 | 状态 | 返回内容 |
| --- | --- | --- |
| 普通请求 `https://steamfn.com/` | 302 | `Location: https://store.steampowered.com/` |
| 含 `WindowsPowerShell` 的 User-Agent | 200 | PowerShell 安装脚本文本 |

证据 **S-01**：[采集响应摘要](../evidence/metadata/http-observations.json)。浏览器跳转只能证明重定向行为，不能证明 Valve 所有权或授权关系。[Valve 产品激活说明](https://help.steampowered.com/en/faqs/view/2A12-9D79-C3D7-F870)提供客户端或浏览器登记密钥的操作流程。

## 2. 安装脚本的系统改动

以下为脚本文本中的实际逻辑，不是运行结果。精选原始行、行号和原文件 SHA-256 见 **S-02**：[安装脚本摘录](../evidence/installer-excerpts.txt)。ASCII 标志、显示颜色、下载缓冲区和终端倒计时等内容不影响下列结论，未纳入摘录。

| 阶段 | 确认的操作 | 影响 |
| --- | --- | --- |
| 权限 | 检查管理员角色；通过 `Start-Process powershell -Verb RunAs` 重新启动，参数包含 `ExecutionPolicy Bypass` | 请求提高脚本执行权限 |
| 定位 | 读取 `HKCU\Software\Valve\Steam` 的 `SteamPath` | 确定修改目标目录 |
| 停止/清理 | 强制停止 Steam；删除 `user32.dll`、`hid.dll`、`version.dll`、`steam.cfg`、`package\beta` 等 | 清理已有组件与配置 |
| 安全排除 | 调用 `Add-MpPreference -ExclusionPath`，目标包括 Steam 目录、两枚 DLL、临时 ZIP | 尝试降低这些路径的 Defender 扫描覆盖；错误被忽略 |
| 下载 | 获取 `http://update.steamdemo.com/res.zip` | 从第三方明文 HTTP 地址取得安装资源 |
| 写入 | 将 ZIP 条目覆盖解压到 Steam 目录 | 将第三方 DLL 布置到客户端目录 |
| 模式 | 在 `HKCU\Software\Valve\Steamtools` 移除若干模式项，写入字符串 `iscdkey="true"` | 设置工具卡密模式 |
| 启动 | 重新启动 Steam，输出激活服务器连接成功文字 | 启动安装后的客户端；输出文字不是许可证证明 |

`Get-FileFast` 仅检查下载方法是否返回成功、文件是否存在和长度是否大于零。脚本未校验资源包的预期哈希或签名。解压逻辑直接组合远程 ZIP 条目路径并覆盖写入目标目录；本次包中只有 `xinput1_4.dll` 与 `dwmapi.dll` 两个条目。

程序能否成功提权、Defender 是否接受排除、目标文件是否删除，取决于运行时权限与系统策略；本次未执行这些改动。

## 3. 资源与第二阶段配置

资源链为：

```text
steamfn.com 的安装脚本
  → http://update.steamdemo.com/res.zip
     ├─ xinput1_4.dll：更新/加载器
     └─ dwmapi.dll：缓存补丁

xinput1_4.dll
  → /version 数据
  → 解密/解压后的 JSON
  → WindowsFile64Stable 中指定的 Core
```

证据 **S-03**：[版本配置快照](../evidence/metadata/version-snapshot.json)。该 JSON 从保存的加密数据离线恢复，包含：

| 字段 | 本次值/作用 |
| --- | --- |
| `Version` / `VersionTxt` | `6` / `1.8 正式版` |
| `DownloadUrl` | `https://www.steamtools.net`，直接联系 SteamTools 品牌 |
| `urls` | `cdn-api.tnkjmec.com`、`cdn-api-v2b.tnkjmec.com` 两个 API base |
| `CardUrl` | 另行保存的卡密相关地址；不能据此认定 `CardActivate` 直接发往该字段 |
| `WindowsFile64Stable` | `http://update.steamdemo.com/Core`，缓存路径含 `<mCode>` |
| `WindowsFile64Beta` / `WindowsFileStable` | 其他分支的资源项；未作为本次 Core 分析对象 |
| `AllFile` | 包含 `default=-1` 的测试项；不应把“配置中存在”直接说成“实际下载” |

稳定版 Core 加密文件 MD5 为 `3c7b7eba52cfa28f15688d3b02b54843`，与该配置项的 `Hash` 一致。此核对把本次对象绑定到所保存配置；同源配置校验值并不能认证可信发布者。当前模块的代码与数据流见 [报告 03](03-core.md)。

配置将分发文件和工具 API 联系起来，但不足以确定相关域名的共同法律主体或经营者身份。

## 4. 样本身份与签名

证据 **S-04**：[样本元数据](../evidence/metadata/samples.json)，包括尺寸、SHA-256、PE 字段、节、入口和签名结果。

| 样本 | 入口 VA | PE 头时间字段（UTC） | 采集时 Authenticode 检查 |
| --- | --- | --- | --- |
| `xinput1_4.dll` | `0x1800440F4` | 2026-03-13 07:56:25 | `Valid` |
| `dwmapi.dll` | `0x1800014A4` | 2026-03-15 08:41:18 | `Valid` |
| 解密后的 Core | `0x180157BA0` | 2026-09-20 03:58:55 | `NotSigned` |

前两个文件签名主体为 **NewWnight Global Tech Co., Ltd**；证书标示湖南长沙，颁发者为 **GlobalSign GCC R45 EV CodeSigning CA 2020**。有效签名只用于识别签署主体与完整性，不证明无害或 Valve 授权。PE 时间字段可被修改，不能作为可靠发布时间。

Core 的 `.vmp0` 节及部分混淆提示分析覆盖存在限制；节名本身不能用于恶意定性。

## 5. 方法与结论范围

分析使用 Ghidra 11.4.1、PE 解析、Capstone 和独立数据解密/解压；方法范围统一见 [README](../README.md#分析方法与适用范围)。下载包、DLL 和 Core 均作为静态字节数据处理。

这条安装链确认了客户端修改、管理员安装与安全排除，以及服务器决定后续模块的设计。安装文本中的“连接激活服务器成功”不能证明实际网络验证，更不能证明账号获得 Valve 许可证。后续报告分别给出 DLL 的原始指令和 Core 的具体数据来源/发送方向。
