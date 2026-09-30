# 02 · 两枚安装 DLL 的静态逻辑

`xinput1_4.dll` 是远程配置、文件更新和第二阶段内存加载器；`dwmapi.dll` 是对 Steam 本地软件包缓存实施固定字节替换的补丁。两者都不提供其文件名对应的正常 Windows API。真正的激活、游戏列表修改和数据上传功能属于后续 Core，见 [03 · Core 业务逻辑](03-core.md)。

分析对象以 [样本元数据](../evidence/metadata/samples.json) 中的 SHA-256 为准。下文地址使用 PE 的首选 VA；两枚 DLL 的 ImageBase 均为 `0x180000000`，`RVA = VA − ImageBase`。每条主要结论对应 `L-01` 至 `L-10` 文本证据，原始汇编附件同时保留 VA、RVA、机器码和解析出的 IAT 名称。

## 1. 样本结构与职责

| 项目 | xinput1_4.dll | dwmapi.dll |
| --- | --- | --- |
| 大小 | 673,720 字节 | 136,120 字节 |
| PE 架构 | AMD64 / x64 | AMD64 / x64 |
| PE 入口 VA / RVA | `0x1800440F4` / `0x440F4` | `0x1800014A4` / `0x14A4` |
| 自定义 DllMain VA / RVA | `0x180001610` / `0x1610` | `0x180001000` / `0x1000` |
| 导出 | 78 个 `cJSON_*` 名称，没有 XInput API | 没有导出表，也没有 `Dwm*` API |
| 主要作用 | 获取更新配置、替换指定文件、解码并内存映射 Core | 搜索 `packageinfo.vdf` 的固定字节并覆盖四字节 |

仅凭 DLL 文件名不能确定加载进程或具体 DLL 搜索顺序。以下调用链确认的是文件中实现的逻辑，网站安装步骤及分发来源另见 [01 · 网站与安装链](01-site-and-installer.md)。

## 2. xinput1_4.dll 的触发与模块名隐藏

### 2.1 初始化和 LdrLoadDll 挂钩 — L-01

自定义 DllMain `0x180001610` 在 `DLL_PROCESS_ATTACH` 时调用 `0x180001320`。初始化读取自身模块路径，建立含当前 PID 的命名事件，检查相关 Steam 模块，再选择直接进入更新流程或安装加载回调。

对模块检查分支逐条核对后，行为如下。表中“已加载”指 `GetModuleHandleW` 返回非空：

| steamclient.dll | SteamUI.dll | 该分支的结果 |
| --- | --- | --- |
| 任意 | 已加载 | 调用更新协调函数 `0x1800039B0` |
| 未加载 | 未加载 | 尝试挂钩 `ntdll!LdrLoadDll` |
| 已加载 | 未加载 | 退出该初始化分支 |

挂钩路径在 `0x180001544` 解析 `LdrLoadDll`，依次经过 `0x18000ECE0` 初始化、`0x18000EA30` 创建挂钩、`0x18000ECD0` 启用挂钩。目标回调为 `0x180001220`，原始函数地址保存到 `0x1800A07C0`。

回调先调用原始 `LdrLoadDll`。返回状态非负且传入的 Unicode 模块名有效时，复制并规范化名字，查找 `crashhandler.dll`。匹配后，在相应状态允许时撤销挂钩并进入 `0x1800039B0`；另有只清除状态的分支。因此它不是每次 DLL 加载都无条件更新。

语义伪代码省略资源清理和错误分支：

```text
DllMain(module, PROCESS_ATTACH):
    initialize(module)
    return FALSE

initialize(module):
    create process-scoped named event
    if event already exists:
        close event and stop this branch
    steamclient = module_is_loaded(decode_name(...))
    steamui = module_is_loaded(decode_name(...))
    if steamui:
        coordinate_update_and_load()
    else if not steamclient:
        optionally wait for Valve_SteamIPC_Class when -startupwait is present
        install LdrLoadDll hook(callback)

callback(..., module_name, ...):
    status = original_LdrLoadDll(...)
    if status >= 0 and module_name contains crashhandler.dll:
        if triggering state allows:
            disable/remove hook
            coordinate_update_and_load()
    return original status
```

原始 DllMain 的 `0x18000161E` 为 `xor eax,eax`，即初始化后返回 FALSE。正常 Windows 加载路径会把 PROCESS_ATTACH 返回 FALSE 视为加载失败；这个返回值不能否定此前已经发生的同步副作用，也不能证明挂钩在普通加载失败后仍能长期存活。相应行为需要保留这个加载条件，而不能叙述为“DLL 必然成功驻留”。

精选原始指令（完整字节窗口见附件）：

```asm
0x180001544  FF 15 1E CC 06 00                 call      qword ptr [rip + 0x6cc1e] ; IAT GetProcAddress @ 0x18006E168
0x180001556  E8 85 D7 00 00                    call      0x18000ece0
0x18000156D  48 8D 15 AC FC FF FF              lea       rdx, [rip - 0x354]
0x180001574  E8 B7 D4 00 00                    call      0x18000ea30
0x180001580  E8 4B D7 00 00                    call      0x18000ecd0
0x180001619  E8 02 FD FF FF                    call      0x180001320
0x18000161E  33 C0                             xor       eax, eax
```

相关挂钩表结构、线程冻结和补丁方式与 [MinHook 官方实现](https://github.com/TsudaKageyu/minhook/blob/master/src/hook.c)吻合。其线程枚举按当前 PID 过滤；这一功能属于当前进程内挂钩，不能仅凭 `SuspendThread`、`GetThreadContext` 或 `VirtualProtect` 推断为跨进程注入。

证据：[L-01 反编译](../evidence/decompiled/xinput-initialization.txt)、[L-01 原始汇编](../evidence/assembly/xinput-initialization.txt)。

### 2.2 模块名的位反转编码 — L-02

`0x180001080`（RVA `0x1080`）处理调用点传入的 64 位常量。它使用 `0xAAAAAAAAAAAAAAAA`、`0xCCCCCCCCCCCCCCCC`、`0xF0F0F0F0F0F0F0F0` 掩码，交换每个字节中的相邻位、两位组和四位组，再按高字节到低字节的顺序写为 UTF-16 字符，并补零终止符。

该方式是可逆字符串编码，不能视为密码保护。其等价还原步骤为：

```text
for each 64-bit constant:
    for byte in constant represented in big-endian byte order:
        output UTF-16 character whose value is reverse_bits_8(byte)
append UTF-16 NUL
```

| 调用点用途 | 第一常量 | 第二常量 | 静态还原文本 |
| --- | --- | --- | --- |
| 加载回调的匹配对象 | `C64E86CE16168676` | `2636A64E74263636` | `crashhandler.dll` |
| Steam 模块检查 | `CE2EA686B6C63696` | `A6762E7426363600` | `steamclient.dll` |
| Steam 界面检查 | `CA2EA686B6AA9274` | `2636360000000000` | `SteamUI.dll` |
| 解析 LdrLoadDll 所在模块 | `762E263636742636` | `3600000000000000` | `ntdll.dll` |

证据：[L-02 编码函数及调用常量](../evidence/decompiled/xinput-initialization.txt)、[L-02 对应机器码](../evidence/assembly/xinput-initialization.txt)。

## 3. 更新协调、hosts 检查与实际服务器循环

### 3.1 hosts 只读检查 — L-03

更新协调函数 `0x1800039B0`（RVA `0x39B0`）首先从备用 URL 去除 `http://` / `https://` 前缀，提取域名，并交给 `0x180002D10`（RVA `0x2D10`）。

`0x180002D10` 从 `SystemRoot` 构造 `System32\drivers\etc\hosts` 路径，以文本模式 `r` 打开。它逐行读取，跳过首个非空白字符为 `#`、空行等情况，规范化大小写，再检查该行是否同时含目标域名与 `127.0.0.1` 或 `0.0.0.0`。这是字符串检查，不是完整的 hosts 语法解析。

若此检查报告阻断，调用者记录相关提示并跳到流程结尾；它并非“发现一个域名被挡后自动换下一个”。已识别逻辑没有以写模式打开 hosts，也没有 hosts 覆盖调用。

通过预检查后，协调函数获取用户目录和 CPU 信息，使用 `cpuid`、系统处理器数量、`"version"` 异或、摘要/64 位迭代计算派生缓存标识。`0x180002C00`（RVA `0x2C00`）据此构造：

```text
<current working directory>\appcache\httpcache\3b\<mCode>
```

这里的 `<mCode>` 是该工具的机器相关缓存名。CPU 派生名称本身不能证明在此处上传了硬件信息；它在已确认路径中的用途是文件定位。

证据：[L-03 hosts 与缓存协调反编译](../evidence/decompiled/xinput-coordinator-hosts.txt)、[L-03 原始汇编及 IAT 标注](../evidence/assembly/xinput-coordinator-hosts.txt)。

### 3.2 三个实际备用项，第四个字符串未入循环 — L-04

PE 数据中四个相邻指针如下：

| 指针 VA / RVA | 指向的字符串 | 是否处于已识别循环范围 |
| --- | --- | --- |
| `0x180084018` / `0x84018` | `https://update.aaasn.com/version` | 是 |
| `0x180084020` / `0x84020` | `https://update.tnkjmec.com/version` | 是 |
| `0x180084028` / `0x84028` | `http://update.wudrm.com/version` | 是 |
| `0x180084030` / `0x84030` | `http://update.steamcdn.com/version` | 否，位于结束边界 |

hosts 预检查循环与获取配置的备用循环均从 `0x180084018` 开始，每步加 8，继续条件为指针 **小于** `0x180084030`。因此观察到的循环有三项，不能把数据中的四个域名全称为实际访问列表。

配置获取循环在 `0x180003DA0` 调用 `0x180003530`；前一项成功后，在 `0x180003D93` 提前跳出，所以正常获取行为也是条件触发的备用访问，而非每次访问全部三项。

```text
begin = address 0x180084018
end   = address 0x180084030

for p from begin to end exclusive, step 8:
    if hosts_check(host(*p)) reports a blocking entry:
        stop coordinator

success = false
for p from begin to end exclusive, step 8:
    if success:
        break
    success = fetch_and_process_version(*p)
```

循环边界的机器码：

```asm
0x1800039F4  4C 8D 3D 1D 06 08 00              lea       r15, [rip + 0x8061d]
0x180003A01  4C 8D 25 28 06 08 00              lea       r12, [rip + 0x80628]
0x180003AB5  48 83 C6 08                       add       rsi, 8
0x180003AB9  49 3B F4                          cmp       rsi, r12
0x180003ABC  0F 8C 4E FF FF FF                 jl        0x180003a10
0x180003D88  48 8D 3D A1 02 08 00              lea       rdi, [rip + 0x802a1]
0x180003DA0  E8 8B F7 FF FF                    call      0x180003530
0x180003DA7  49 83 C7 08                       add       r15, 8
0x180003DAB  4C 3B FF                          cmp       r15, rdi
0x180003DAE  7C E1                             jl        0x180003d91
```

本次恢复的版本配置为 `Version = 6`、`VersionTxt = "1.8 正式版"`；其 `WindowsFile64Stable` 项指定明文 HTTP 的 `http://update.steamdemo.com/Core`。`DownloadUrl` 指向 SteamTools 网站，`CardUrl` 指向第三方卡密页。配置的完整快照见 [版本配置 JSON](../evidence/metadata/version-snapshot.json)。这些值是采集时的数据，不是所有未来版本的常量。

证据：[L-04 两个循环的反编译](../evidence/decompiled/xinput-coordinator-hosts.txt)、[L-04 原始指令及指针表原字节](../evidence/assembly/xinput-coordinator-hosts.txt)。

## 4. 解密、更新与第二阶段加载

### 4.1 AES-256-CBC 与 zlib 数据格式 — L-05

`0x1800026E0`（RVA `0x26E0`）是版本配置及主模块数据共同使用的解码函数。静态代码和对公开下载数据的独立离线解码相互印证：

```text
外层数据：IV[16] || AES-CBC ciphertext
解密明文：decoded_size_le32 || zlib_stream || padding
解压结果：UTF-8 配置 JSON，或待映射的 PE 字节
```

| 步骤 | 关键 VA / RVA | 静态依据 |
| --- | --- | --- |
| 从输入开头取得 IV | `0x18000272C`、`0x180002741` / `0x272C`、`0x2741` | 前 16 字节复制到局部 IV，密文从输入 `+0x10` 起 |
| 配置 256 位 AES 密钥 | `0x180002768`、`0x180002776` / `0x2768`、`0x2776` | 参数 `0x100`，调用密钥设置函数 `0x18000CD70` |
| CBC 解密 | `0x1800027A3` / `0x27A3` | 调用 `0x18000CB90`，模式参数为 0，传入 IV 与剩余密文 |
| 取末尾 padding 长度 | `0x1800027CC` / `0x27CC` | 读取解密数据最后一字节，检查上限 16 及相对长度 |
| 读取声明的解压长度 | `0x1800027E5` / `0x27E5` | 首四字节小端整数，要求非零且不超过 `0xA00000` |
| zlib 解压与输出验证 | `0x180002828`、`0x18000283F` / `0x2828`、`0x283F` | 调用 `0x180008A90`，检查成功返回及实际输出长度一致 |
| 返回输出缓冲区/长度 | `0x18000284A`、`0x180002853` / `0x284A`、`0x2853` | 写出长度和指针，然后返回 1 |

版本配置调用使用内嵌密钥地址 `0x180083FF8`（RVA `0x83FF8`），主模块使用 `0x180083FD8`（RVA `0x83FD8`）。两种数据并非共用同一密钥地址。

语义伪代码：

```text
decode(input, size, embedded_key, out):
    require input != NULL and size >= 16 and key != NULL
    iv = input[0:16]
    plain = AES_256_CBC_decrypt(key, iv, input[16:])
    pad = plain[last]
    require pad <= 16 and pad < len(plain)
    expected = uint32_le(plain[0:4])
    require 0 < expected <= 0xA00000
    result = zlib_uncompress(plain[4:len(plain)-pad], expected)
    require decompressor succeeded and len(result) == expected
    out = {buffer: result, length: expected}
    return success
```

原始函数没有表现出验证每个 padding 字节均等于长度值的循环；不能把它描述为完整严格的 PKCS#7 校验。已识别格式也没有独立 MAC / AEAD 认证标签。AES-CBC 与内嵌密钥负责恢复数据格式，不能单独认证发布者。

解压返回与输出写入的关键指令：

```asm
0x180002824  44 8D 4B FC                       lea       r9d, [rbx - 4]
0x180002828  E8 63 62 00 00                    call      0x180008a90
0x180002837  85 DB                             test      ebx, ebx
0x18000283B  8B 44 24 30                       mov       eax, dword ptr [rsp + 0x30]
0x18000283F  3B C6                             cmp       eax, esi
0x180002841  75 15                             jne       0x180002858
0x18000284A  49 89 47 08                       mov       qword ptr [r15 + 8], rax
0x18000284E  B8 01 00 00 00                    mov       eax, 1
0x180002853  49 89 2F                          mov       qword ptr [r15], rbp
```

证据：[L-05 解码反编译](../evidence/decompiled/xinput-crypto.txt)、[L-05 原始汇编](../evidence/assembly/xinput-crypto.txt)。

### 4.2 配置控制的文件更新与自重启 — L-06

`0x180003530`（RVA `0x3530`）获取加密版本数据，调用上述解码函数，用 `cJSON_Parse` 处理 JSON，并把原始加密版本缓存到 `appcache\version`。

随后，它读取 `package/branch`；默认分支名为 `Stable`，存在分支文件时采用文件中的分支文本。拼接 `WindowsFile64` 与分支名，从配置取相应数组交给 `0x180002F70`，再处理 `AllFile` 数组。

`0x180002F70`（RVA `0x2F70`）逐项处理 `FileName`、`URL`、`Hash`、`default`：

- 类型不合要求的项目不进入更新；`default = -1` 的项目跳过。
- 文件名允许替换 `%USERPROFILE%` 和 `<mCode>`；未含盘符分隔符 `:` 的名字按当前目录组合为路径。因此其写入范围不只固定为一个 Core 文件名，而是受远程文件列表控制。
- 若目标已存在，读取其内容并计算 16 字节摘要，转为十六进制字符串，与配置中的 `Hash` 比较。原始 `0x1800034AE` 的比较和 `0x1800034B5` 的跳转确认：相等则跳过，不同则进入下载。
- 下载函数 `0x1800028B0`（RVA `0x28B0`）创建需要的目录，使用公共 HTTP 包装函数 `0x180001B00`，最终把收到的数据写入目标路径。
- 更新成功且 `default = 1` 等条件成立时，使用 `GetModuleFileNameW(NULL)` 得到当前可执行文件，使用 `GetCommandLineW()` 得到原命令行，`CreateProcessW` 启动相同程序。启动成功后结束当前进程。这是自重启路径，不能从此推导出“启动 cmd / PowerShell 执行任意命令”。

```text
for item in selected_branch_files, then AllFile:
    validate FileName, URL, Hash types
    if default == -1: continue
    path = expand_USERPROFILE_and_mCode(item.FileName)
    path = resolve_relative_path_against_current_directory(path)
    if file exists and local_digest_hex == item.Hash:
        continue
    if download(item.URL, path) succeeded:
        if default == 1 and restart_conditions_met:
            start current executable with current command line and directory
            terminate current process
```

`Hash` 来自同一远程配置，能说明内容是否与该配置预期一致，不能为配置本身提供独立可信的发布者认证。当前稳定版 Core 配置的哈希与实际取得的加密对象相符，但这不等于该对象获得 Valve 授权。

证据：[L-06 配置/文件更新反编译](../evidence/decompiled/xinput-update-files.txt)、[L-06 哈希比较、下载及自重启原始汇编](../evidence/assembly/xinput-update-files.txt)。

### 4.3 内存 PE 映射及入口调用 — L-07

`0x1800039B0` 在完成更新尝试后，打开机器相关的主模块缓存。如果缓存尚未出现，有状态检查及最多 3000 次、每次 `Sleep(10)` 的等待分支。取得全部字节后，`0x180003EB5` 解码，成功时 `0x180003EC6` 把解码后的缓冲区和长度交给 `0x1800450A0`。

`0x1800450A0`（RVA `0x450A0`）为 `0x1800450F0`（RVA `0x450F0`）提供分配、释放、加载依赖、解析导入和释放依赖的回调。对应包装位于 `0x180044F30` 至 `0x180044F70`，原始 IAT 标注确认其 API 为 `VirtualAlloc`、`VirtualFree`、`LoadLibraryA`、`GetProcAddress`、`FreeLibrary`。

实际映射步骤：

| 阶段 | 关键 VA / RVA | 作用 |
| --- | --- | --- |
| PE 检查 | `0x180045119`–`0x180045174` / `0x45119`–`0x45174` | 长度、MZ、PE 签名、AMD64 `0x8664` 等检查 |
| 分配与头部/节复制 | `0x180045209` 后 / `0x45209` 后 | 尝试首选基址，否则另址分配；按节 RVA 复制原始数据，零填充相应区域 |
| 基址重定位 | `0x1800455B0`–`0x1800455EA` / `0x455B0`–`0x455EA` | 处理类型 3 / 10，给 32 / 64 位目标加基址差 |
| 导入解析 | `0x18004560A → 0x180044AB0` / `0x4560A → 0x44AB0` | 加载依赖，按序号或名字解析，填入 IAT |
| 节保护 | `0x18004561A → 0x180044D20` / `0x4561A → 0x44D20` | 根据节属性设置权限；原始 `0x180044F15` 调用 VirtualProtect |
| TLS 回调 | `0x180045650`–`0x180045668` / `0x45650`–`0x45668` | 逐项调用 `(image_base, DLL_PROCESS_ATTACH, NULL)` |
| DLL 入口 | `0x18004567F`–`0x18004568A` / `0x4567F`–`0x4568A` | 调用 `image_base + AddressOfEntryPoint`，事件值为 1；失败时释放映像 |

因此，“内存加载器”的判断来自真实 PE 映射、IAT/重定位处理和函数指针调用，超出了仅看到 `HttpLoadDLL` 名字或 `VirtualAlloc` 导入的证据强度。

```text
decoded_PE = decode(main_cache_bytes, embedded_main_key)
image = allocate_and_copy_PE(decoded_PE)
apply_relocations(image)
resolve_imports(image)
set_section_protections(image)
for callback in image.TLS_callbacks:
    callback(image.base, PROCESS_ATTACH, NULL)
if image is DLL and has entrypoint:
    require entrypoint(image.base, PROCESS_ATTACH, NULL) != FALSE
return mapped_module
```

实际入口调用的机器码：

```asm
0x18004566D  8B 48 28                          mov       ecx, dword ptr [rax + 0x28]
0x180045674  41 83 7E 20 00                    cmp       dword ptr [r14 + 0x20], 0
0x180045679  4D 8D 0C 0F                       lea       r9, [r15 + rcx]
0x18004567D  74 3A                             je        0x1800456b9
0x18004567F  45 33 C0                          xor       r8d, r8d
0x180045682  BA 01 00 00 00                    mov       edx, 1
0x180045687  49 8B CF                          mov       rcx, r15
0x18004568A  41 FF D1                          call      r9
```

映射对象运行在调用进程自己的地址空间。此处没有远程进程句柄、远程内存写入或远程线程创建的数据流，不应将本调用链直接称为跨进程注入。已识别加载链也没有对解码后的 Core 进行 Authenticode 验证的步骤。

证据：[L-07 内存映射反编译](../evidence/decompiled/xinput-memory-map.txt)、[L-07 映射、导入、页保护、TLS 和入口原始汇编](../evidence/assembly/xinput-memory-map.txt)，调用侧见 [L-03/L-04 协调汇编](../evidence/assembly/xinput-coordinator-hosts.txt)。

## 5. HTTPS 身份验证关闭的完整参数链 — L-08

公共 HTTP 包装函数 `0x180001B00`（RVA `0x1B00`）有启用与关闭 TLS 校验的两条分支。风险结论不是“程序含有关闭选项”这一字符串观察，而是两个实际相关调用者都设置了会选中关闭分支的字段。

| 链中位置 | 原始指令与地址 | 解释 |
| --- | --- | --- |
| 配置获取 `0x180003530` | `0x1800035B2` 写 `[rbp+0xC0] = 1`；`0x1800035BC` 传 `[rbp+0x70]` | 选项结构偏移 `+0x50` 等于 1 |
| 文件下载 `0x1800028B0` | `0x180002A43` 写 `[rbp+0xC0] = 1`；`0x180002A24` 传 `[rbp+0x70]` | 同一个选项字段等于 1 |
| HTTP 包装 `0x180001B00` | `0x180001E4D` 比较 `[r14+0x50]` 与 1 | 选中关闭验证分支 |
| libcurl 选项调用 | `0x180001E60`–`0x180001E7B` | 两次以 `r8 = 0` 传给选项号 `0x40` 和 `0x51` |

在 [curl 7.68.0 官方头文件](https://github.com/curl/curl/blob/curl-7_68_0/include/curl/curl.h)中，64（`0x40`）对应 `CURLOPT_SSL_VERIFYPEER`，81（`0x51`）对应 `CURLOPT_SSL_VERIFYHOST`。两者设为 0 分别关闭证书信任验证和证书与主机名的对应检查，参数含义见 [证书验证文档](https://curl.se/libcurl/c/CURLOPT_SSL_VERIFYPEER.html)与[主机名验证文档](https://curl.se/libcurl/c/CURLOPT_SSL_VERIFYHOST.html)。

```asm
0x1800035B2  C7 85 C0 00 00 00 01 00 00 00     mov       dword ptr [rbp + 0xc0], 1
0x1800035BC  4C 8D 45 70                       lea       r8, [rbp + 0x70]
0x1800035C0  E8 3B E5 FF FF                    call      0x180001b00
0x180002A24  4C 8D 45 70                       lea       r8, [rbp + 0x70]
0x180002A43  C7 85 C0 00 00 00 01 00 00 00     mov       dword ptr [rbp + 0xc0], 1
0x180002A4D  E8 AE F0 FF FF                    call      0x180001b00
0x180001E4D  41 83 7E 50 01                    cmp       dword ptr [r14 + 0x50], 1
0x180001E52  75 2E                             jne       0x180001e82
0x180001E60  45 33 C0                          xor       r8d, r8d
0x180001E63  BA 40 00 00 00                    mov       edx, 0x40
0x180001E6B  E8 70 1A 01 00                    call      0x1800138e0
0x180001E70  45 33 C0                          xor       r8d, r8d
0x180001E73  BA 51 00 00 00                    mov       edx, 0x51
0x180001E7B  E8 60 1A 01 00                    call      0x1800138e0
```

反编译器对调用者的栈结构产生重叠变量，若只看自动生成的 `local_*` 名字容易漏掉这条链。原始的 `0xC0 − 0x70 = 0x50` 偏移关系消除了该歧义。

该样本具有可开启正常验证的另一分支，但已核实的配置获取/文件下载路径采用关闭分支。HTTPS 地址在这些调用中不能提供正常的服务器身份验证保证；明文 HTTP 地址进一步缺少传输加密。内置 AES 和远端提供的哈希不能弥补更新发布者认证缺口。

证据：[L-08 HTTP 包装反编译](../evidence/decompiled/xinput-http-options.txt)、[L-08 两个调用者及关闭参数的原始汇编](../evidence/assembly/xinput-https-verification.txt)。

## 6. dwmapi.dll：固定字节缓存补丁 — L-09

### 6.1 文件读写调用链

PE 入口 `0x1800014A4`（RVA `0x14A4`）进入 CRT 包装 `0x18000137C`（RVA `0x137C`），后者调用自定义 DllMain `0x180001000`（RVA `0x1000`）。PE 没有导出表、TLS 目录或延迟导入。

| 步骤 | VA / RVA | 结果 |
| --- | --- | --- |
| 判断事件 | `0x180001013` / `0x1013` | 只对事件 1（PROCESS_ATTACH）进入补丁分支 |
| 打开缓存 | `0x180001057 → 0x180004DF0` / `0x1057 → 0x4DF0` | `appcache\packageinfo.vdf`，模式 `r+b` |
| 获取大小并读全文件 | `0x180001082`、`0x18000108A`、`0x1800010B8` / `0x1082`、`0x108A`、`0x10B8` | seek 到末尾、取长、rewind、malloc、fread |
| 搜索固定模式 | `0x1800010D0`–`0x1800010E4` / `0x10D0`–`0x10E4` | 每步增一，以两个 8 字节比较匹配 16 字节 |
| 定位并写入 | `0x1800010EE`、`0x180001106` / `0x10EE`、`0x1106` | seek 到首个匹配起点，fwrite 四字节，退出扫描 |
| 释放并关闭 | `0x18000110E`、`0x180001116` / `0x110E`、`0x1116` | free、fclose |
| 返回值 | `0x18000112F` / `0x112F` | `xor eax,eax`，PROCESS_ATTACH 返回 FALSE |

路径相对进程当前工作目录，而非通过 DLL 所在目录自动计算。`r+b` 打开现有文件、允许读写、不会创建或截断文件。目标打不开、内存分配失败或没有匹配时均不会获得预期字节修改。

### 6.2 改的是匹配起点的整数，不是 billingtype 的值

扫描模式与替换值：

```text
原始匹配 16 字节：
E8 4E 00 00 02 62 69 6C 6C 69 6E 67 74 79 70 65
| 20200 LE |02| b  i  l  l  i  n  g  t  y  p  e |

仅覆盖起点四字节：
20 20 01 00  ->  小端整数 73760
```

`02` 是二进制 KeyValues 中与整数项相符的标签，`billingtype` 是用来定位的相邻字段名。代码没有跨过该字段名寻找其数值，也没有向 `billingtype` 值所在位置写入。

[ValvePython/steam 作者的 packageinfo 格式示例](https://steam.readthedocs.io/en/stable/api/steam.utils.html#utils-appache)展示了内部 `packageid` 后接 `billingtype`。在正常的这一字段布局下，上述四字节高度符合把内部 `packageid` 从 20200 改为 73760；确切字节改动已确定，具体字段归属则依赖正常布局。两个包编号的具体业务目的尚未证实，不能由编号推测游戏名称。

```text
DllMain(reason):
    if reason != PROCESS_ATTACH:
        return TRUE
    fp = fopen("appcache\\packageinfo.vdf", "r+b")
    if fp exists:
        buffer = read_entire_file(fp)
        for offset in 0 .. size-16 inclusive:
            if buffer[offset:offset+16] == fixed_pattern:
                seek(fp, offset)
                fwrite(bytes 20 20 01 00, size=1, count=4, fp)
                break
        free buffer
        fclose(fp)
    return FALSE
```

精选原始机器码同时证明原值、替换值、写入大小和最终返回值：

```asm
0x18000102F  C7 44 24 20 E8 4E 00 00           mov       dword ptr [rsp + 0x20], 0x4ee8
0x180001037  C7 44 24 24 02 62 69 6C           mov       dword ptr [rsp + 0x24], 0x6c696202
0x18000103F  C7 44 24 28 6C 69 6E 67           mov       dword ptr [rsp + 0x28], 0x676e696c
0x180001047  C7 44 24 2C 74 79 70 65           mov       dword ptr [rsp + 0x2c], 0x65707974
0x18000104F  C7 44 24 30 20 20 01 00           mov       dword ptr [rsp + 0x30], 0x12020
0x1800010F6  48 8D 4C 24 30                    lea       rcx, [rsp + 0x30]
0x1800010FB  BA 01 00 00 00                    mov       edx, 1
0x180001100  41 B8 04 00 00 00                 mov       r8d, 4
0x180001106  E8 B5 46 00 00                    call      0x1800057c0
0x18000112F  33 C0                             xor       eax, eax
```

PROCESS_ATTACH 路径先尝试产生文件修改副作用，再返回 FALSE；其他事件返回 TRUE。“固定字节补丁”指每次触发扫描的机制，不表示整个安装生命周期只会运行一次。每次扫描最多替换第一个匹配。

该函数不验证 VDF 文件头、记录结构或匹配位置前是否确有 `packageid` 名称；也不重算 SHA1 等记录校验值。读取、定位及写入返回值未逐项校验，因此“走到写入调用”与“缓存一定已成功修改”需要区分。它没有更新 Valve 服务器许可证的逻辑。`dwmapi.dll` 无 DWM 导出，也没有实现或转发 DWM 的业务函数。

证据：[L-09 正确提取的 DllMain/入口反编译](../evidence/decompiled/dwmapi-cache-patch.txt)、[L-09 固定模式、fwrite 参数与返回 FALSE 的原始汇编](../evidence/assembly/dwmapi-cache-patch.txt)。

## 7. 运行库 API 的解释边界 — L-10

`dwmapi.dll` 的常规导入只有 KERNEL32.dll。导入表中存在 `IsDebuggerPresent`、异常展开、`GetProcAddress`、`LoadLibraryExW`、`VirtualProtect`，但已核查它们在对应运行库支持代码中的作用，不能把 API 名称本身当作反调试、下载或注入的证明。

动态函数解析辅助位于 `0x180002BE0`（RVA `0x2BE0`）和 `0x18000C828`（RVA `0xC828`）。它们加载 api-ms/ext-ms 或系统运行库模块，解析函数并缓存地址。后者对自己的 `.fptable` 地址 `0x180021000`（RVA `0x21000`）、长度 `0x100` 做临时 PAGE_READWRITE（4）和 PAGE_READONLY（2）切换，写入系统函数指针。

原始 `0x18000C92B` 取得该表地址，`0x18000C932` 设置长度；`0x18000C945` 与 `0x18000C976` 调用 `VirtualProtect`。保护对象是自身函数指针缓存，权限不含执行，不能解释为已经发现可执行代码补丁或远程注入。

同样，xinput 中大范围 HTTP/FTP/proxy、Cookie/Netscape、Schannel 证书错误文本与静态链接的 libcurl 网络库一致。证书覆盖区的 GlobalSign / DigiCert OCSP、CRL 地址属于签名链元数据；这些字符串不是业务更新服务器或 C2 证据。关于 Cookie 或登录材料的结论，应以 Core 的具体数据流另行判断。

证据：[L-10 精选 CRT 解析函数](../evidence/decompiled/dwmapi-crt-api-boundary.txt)、[L-10 `.fptable` 保护和缓存写入机器码](../evidence/assembly/dwmapi-crt-api-boundary.txt)。

## 8. 本节结论及证据口径

已确认的第一阶段行为是：当前进程内加载回调、远程配置控制的文件更新、AES-CBC/zlib 解码、第二阶段 PE 内存映射与入口调用，以及本地 packageinfo 固定字节修改。配置获取和文件下载关闭两项 HTTPS 身份验证，当前配置还包含明文 HTTP Core 地址，形成明确的更新信任风险。

分析采用 PE 字节读取、Ghidra 反编译、Capstone 原始反汇编及独立离线数据解码，没有执行安装脚本、加载目标 DLL 或调用目标解密/入口函数。Ghidra 对部分函数切分、返回类型及栈参数的推断不完整：例如解码函数的输出指针和返回值、文件摘要比较分支、两个 DllMain 的 FALSE 返回都以原始指令补充核实。附件不保留误导性的自动 SIZE 元数据，语义伪代码也不冒充原始源码。

本节不能证明某次运行实际完成了更新、挂钩或数据上传，不能验证特定 Steam 版本下的授权/联机结果；不能用第一阶段未见凭据获取来替代对 Core 的审查。所有结论仅适用于记录哈希的采集样本，服务器配置和后续载荷可改变。

## 9. 证据映射

| 编号 | 结论 | 精选反编译 | 原始汇编/字节 |
| --- | --- | --- | --- |
| L-01 | 初始化分支、LdrLoadDll 挂钩、PROCESS_ATTACH 返回 FALSE | [initialization](../evidence/decompiled/xinput-initialization.txt) | [initialization](../evidence/assembly/xinput-initialization.txt) |
| L-02 | 位反转模块名编码与调用常量 | [initialization](../evidence/decompiled/xinput-initialization.txt) | [initialization](../evidence/assembly/xinput-initialization.txt) |
| L-03 | hosts 只读检查、缓存路径、CPU 派生缓存名 | [coordinator-hosts](../evidence/decompiled/xinput-coordinator-hosts.txt) | [coordinator-hosts](../evidence/assembly/xinput-coordinator-hosts.txt) |
| L-04 | 三项备用循环、第四项在边界之外 | [coordinator-hosts](../evidence/decompiled/xinput-coordinator-hosts.txt) | [coordinator-hosts，含指针原字节](../evidence/assembly/xinput-coordinator-hosts.txt) |
| L-05 | AES-256-CBC、长度头、zlib 及输出验证 | [crypto](../evidence/decompiled/xinput-crypto.txt) | [crypto](../evidence/assembly/xinput-crypto.txt) |
| L-06 | 远程文件列表、摘要比较、下载与自重启 | [update-files](../evidence/decompiled/xinput-update-files.txt) | [update-files](../evidence/assembly/xinput-update-files.txt) |
| L-07 | PE 复制、重定位、IAT、保护、TLS 与 DLL 入口 | [memory-map](../evidence/decompiled/xinput-memory-map.txt) | [memory-map](../evidence/assembly/xinput-memory-map.txt) |
| L-08 | 两个相关调用者关闭 HTTPS 两项验证 | [http-options](../evidence/decompiled/xinput-http-options.txt) | [https-verification](../evidence/assembly/xinput-https-verification.txt) |
| L-09 | DWM 固定字节四字节修改与 FALSE 返回 | [cache-patch](../evidence/decompiled/dwmapi-cache-patch.txt) | [cache-patch](../evidence/assembly/dwmapi-cache-patch.txt) |
| L-10 | DWM 的 CRT 动态解析和 `.fptable` 保护 | [crt-api-boundary](../evidence/decompiled/dwmapi-crt-api-boundary.txt) | [crt-api-boundary](../evidence/assembly/dwmapi-crt-api-boundary.txt) |
