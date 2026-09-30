# 静态证据索引

所有地址均附属于指定模块，ImageBase 为 `0x180000000`。VA 是首选虚拟地址，RVA 为相对映像地址，二者均不代表运行时观测。正文中的语义伪代码、Ghidra 原始重构摘录与原始字节反汇编分别标注。

## 网站、安装链与样本

| 编号 | 支持的结论 | 文件 |
| --- | --- | --- |
| S-01 | User-Agent 响应差异、资源来源和采集时间 | [HTTP 观察摘要](metadata/http-observations.json) |
| S-02 | 提权、停止/删除、安全排除、HTTP 下载、覆盖解压、模式项与启动 | [带原始行号的安装脚本摘录](installer-excerpts.txt) |
| S-03 | API base、SteamTools 联系与稳定分支 Core 配置 | [解密配置快照](metadata/version-snapshot.json) |
| S-04 | 样本哈希、入口、架构、节、签名检查与加密 Core 标识 | [样本元数据](metadata/samples.json) |

脚本摘录中的行号和源 SHA-256 绑定到保存的响应正文；前后省略内容没有重新编号。HTTP 摘要仅保留与资源和结论有关的字段。

## xinput1_4.dll 与 dwmapi.dll

详见 [报告 02](../reports/02-dlls.md)。

| 编号 | 函数/数据位置（VA） | 主题 | 反编译 | 原始汇编 |
| --- | --- | --- | --- | --- |
| L-01、L-02 | xinput `0x180001080`、`0x180001320`、`0x180001220`、`0x180001610` | 隐藏模块名、初始化分支、加载钩子与返回值 | [摘录](decompiled/xinput-initialization.txt) | [指令](assembly/xinput-initialization.txt) |
| L-03、L-04 | xinput `0x1800039B0`、`0x180002D10`、`0x180084018..0x180084030` | 三项候选循环、第四项边界、hosts 读取 | [摘录](decompiled/xinput-coordinator-hosts.txt) | [指令/数据](assembly/xinput-coordinator-hosts.txt) |
| L-05 | xinput `0x1800026E0` | IV、AES-CBC 和压缩数据处理 | [摘录](decompiled/xinput-crypto.txt) | [指令](assembly/xinput-crypto.txt) |
| L-06 | xinput `0x1800028B0`、`0x180002F70`、`0x180003530` | 按配置更新文件与读取缓存 | [摘录](decompiled/xinput-update-files.txt) | [指令](assembly/xinput-update-files.txt) |
| L-07 | xinput `0x1800450A0`、`0x1800450F0` | PE 验证、内存映射、TLS 回调和入口调用 | [摘录](decompiled/xinput-memory-map.txt) | [指令](assembly/xinput-memory-map.txt) |
| L-08 | xinput `0x1800035B2`、`0x180002A43`、`0x180001E4D..0x180001E70` | 调用者标志与 HTTPS 两项验证关闭 | [摘录](decompiled/xinput-http-options.txt) | [指令](assembly/xinput-https-verification.txt) |
| L-09 | dwmapi `0x180001000`、`0x180001106`、`0x18000112F` | 首个匹配、固定四字节写入与返回 FALSE | [摘录](decompiled/dwmapi-cache-patch.txt) | [指令](assembly/dwmapi-cache-patch.txt) |
| L-10 | dwmapi 运行库帮助函数 | 动态 API 与 .fptable 内存保护的范围 | [摘录](decompiled/dwmapi-crt-api-boundary.txt) | [指令](assembly/dwmapi-crt-api-boundary.txt) |

## Core

详见 [报告 03](../reports/03-core.md)。同一分组覆盖调用链中的多个函数；汇编中的调用和字符串引用标注为静态解析结果。

| 主题与编号 | 主要函数（VA） | 反编译 | 原始汇编 |
| --- | --- | --- | --- |
| C-01—C-03：卡密捕获、第三方兑换、激活响应重构 | `0x18005F330`、`0x18005CEB0`、`0x1800320D0` | [摘录](decompiled/core-activation.txt) | [指令](assembly/core-activation.txt) |
| C-04—C-06、C-10：AppID 数组、Depot 密钥、Manifest 访问码和配置 | `0x18005B840`、`0x18005BC70`、`0x1800603F0`、`0x180050C70`、`0x18005C5A0`、`0x180051090` | [摘录](decompiled/core-appid-depot.txt) | [指令](assembly/core-appid-depot.txt) |
| C-07：PICS token 来源、保存与上传 | `0x18005F330`、`0x180050680`、`0x180053FD0`、`0x180046450` | [摘录](decompiled/core-tokens.txt) | [指令](assembly/core-tokens.txt) |
| C-08：远端开关、名单、多账号文件读取与票据上传 | `0x180053830`、`0x180055410`、`0x180057390`、`0x18004D4A0`、`0x180019320`、`0x180019340`、`0x180046450` | [摘录](decompiled/core-tickets.txt) | [指令](assembly/core-tickets.txt) |
| C-09：SteamID 报头与工具会话 | `0x18003F500`、`0x180044E70`、`0x1800454F0` | [摘录](decompiled/core-session.txt) | [指令](assembly/core-session.txt) |

补充触发条件、文件读取帮助函数和请求序列化以原始汇编附件为依据；不要求每个帮助函数都有独立 Ghidra 函数体。

## 证据解释

- 反编译类型、函数拆分和返回属性可能失真。Core 中内存复制/释放包装的错误“不返回”标记已在分析数据库中修正；样本字节未修改。争议的控制流、返回值和 TLS 设置以原始指令复核。
- 精选指令之间的省略区间不意味着未列出的代码不可达；摘录用于支撑明确的行为结论，不作为完整源代码或可运行程序。
- `packageid` 的字段解释依赖正常缓存格式；源码直接证明的是字节匹配和写入。方法名也不单独决定数据类型或发送方向。
- 能力、条件和实际发生需分开：静态代码可证明上传路径，但不能证明某次运行启用了收集、服务器如何使用数据或票据是否有效。
