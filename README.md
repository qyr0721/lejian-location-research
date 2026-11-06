# 乐健体育位置模拟失效机理研究报告

### ——FakeLocation 内置加密黑名单的逆向分析与运行时验证

---

## 摘要

本文针对“位置模拟工具 FakeLocation 对其他应用均可生效，唯独对乐健体育（`com.ledreamer.zz`）失效”这一现象，开展了一次系统性的逆向分析。研究从两个对立假设出发——(A) 模拟软件内部存在排除乐健体育的黑名单，(B) 乐健体育采用了其他位置获取方式致使模拟无效——通过依次排查 LSPosed 模块作用域数据库、乐健体育 APK、FakeLocation APK 及其运行时行为，最终将根因定位为假设 (A)：FakeLocation 在 APK 内部内置了一份经 AES 加密的应用黑名单（`assets/blacklist.enc`），乐健体育的包名位于其中，hook 对黑名单应用直接放行真实的 GPS/WiFi/基站数据。

在还原该黑名单的过程中，本文完整逆向出了其加密方案——**AES/CBC/PKCS5Padding**，并确定了密钥与初始向量等全部算法参数；进而给出了与该加密方案完全对齐、可双向互操作的加解密参考实现。在此基础上，通过运行时日志对黑名单判定逻辑进行了动态交叉验证。本报告完整记录了从环境准备、静态分析、加密还原到动态验证的全过程，可作为移动端位置安全、应用加固对抗与逆向工程教学的一则完整参考案例。

**关键词**：逆向工程；位置模拟；AES/CBC/PKCS5Padding；Xposed；应用黑名单；反作弊

---

## 目录

1. [引言](#1-引言)
2. [研究环境与工具](#2-研究环境与工具)
3. [研究路线与总体方法](#3-研究路线与总体方法)
4. [LSPosed 模块与作用域数据库分析](#4-lsposed-模块与作用域数据库分析)
5. [乐健体育 APK 反编译分析](#5-乐健体育-apk-反编译分析)
6. [FakeLocation 内置加密黑名单的逆向与解密（核心发现）](#6-fakelocation-内置加密黑名单的逆向与解密核心发现)
7. [运行时动态验证](#7-运行时动态验证)
8. [结论与讨论](#8-结论与讨论)
9. [复现要点与踩坑记录](#9-复现要点与踩坑记录)
10. [附录](#10-附录)

---

## 1. 引言

### 1.1 研究背景

位置模拟（Location Spoofing）是移动端安全与隐私研究中一个长期存在的话题。借助 Xposed/LSPosed 等 hook 框架，一类名为“虚拟定位”的工具能够在系统服务（`system_server`）层拦截并改写位置相关接口，从而对上层应用返回伪造的 GPS、WiFi 与基站信息。此类工具一方面被广泛用于位置隐私保护与开发调试，另一方面也被部分运动打卡、考勤与出行类应用列为重点对抗目标。与之相对，成熟的应用方亦在位置对象层、设备环境层与服务端风控层构筑了多层反模拟体系。二者之间的攻防对抗，构成了理解现代移动应用位置安全的重要切口。

### 1.2 问题定义

本研究的初始问题是：在相同环境下，位置模拟工具 FakeLocation（`com.yinshibai.location`）对其他应用均能成功生效，唯独对乐健体育（`com.ledreamer.zz`）无法生效。为解释这一现象，本研究提出了两个相互竞争的假设：

- **假设 A**：模拟软件内部维护了一份黑名单，将乐健体育排除在模拟范围之外；
- **假设 B**：乐健体育采用了其他位置获取方式，使得模拟位置对其天然无效。

### 1.3 研究目标与贡献

围绕上述问题，本研究设定了以下目标：第一，定位乐健体育位置模拟失效的确切原因；第二，完整还原 FakeLocation 内置黑名单的存在形式、加密算法与密钥体系；第三，通过运行时观测对静态分析结论进行交叉验证。

本研究的贡献主要体现在三方面：一是给出了一个“从现象到根因”的完整排查范式；二是还原了一种在实际应用中采用的对称加密方案（AES/CBC/PKCS5Padding），并提供了可复用的加解密参考实现；三是系统梳理了位置模拟工具的反模拟规避策略与运动类应用的多层反作弊体系，为后续研究提供了对照基线。

### 1.4 报告结构

本文其余部分组织如下：第 2 章说明研究环境与工具；第 3 章给出总体研究路线；第 4 章分析 LSPosed 模块作用域；第 5 章对乐健体育 APK 进行反编译分析；第 6 章为核心章节，完整还原并解密 FakeLocation 内置黑名单，其中第 6.4、6.5 节专门展开加密算法规范与脚本实现；第 7 章进行运行时动态验证；第 8 章给出结论与讨论；第 9 章记录复现要点；第 10 章为附录。

---

## 2. 研究环境与工具

研究在如下软硬件环境中进行：

| 项目 | 配置 |
| --- | --- |
| 设备 | PKX110，Android 17 |
| Root 方案 | KernelSU（包名 `me.weishu.kernelsu`，`adb shell su -c id` 返回 `uid=0(root) context=u:r:ksu:s0`） |
| Xposed 框架 | LSPosed（配置库位于 `/data/adb/lspd/config/modules_config.db`） |
| 目标位置模拟工具 | FakeLocation（`com.yinshibai.location`） |
| 主要分析工具 | adb、Python（`androguard`、`pycryptodome`）、PowerShell 5.1（.NET `System.Security.Cryptography`） |

---

## 3. 研究路线与总体方法

本研究的整体思路是“逐层排除、由外向内、静态与动态互证”。排查顺序为：连接检查 → 确定真实包名 → 分析 LSPosed 配置 → 反编译乐健体育 APK → 分析 FakeLocation 配置与 APK → 解密内置黑名单 → 运行时验证。

在方法上，本研究遵循以下原则：

1. **优先验证最易检验的假设**：先检查用户自定义黑名单与模块作用域，再深入 APK 静态分析；
2. **静态与动态相互印证**：反编译得到的结论均通过 `dumpsys` 与 `logcat` 的运行时观测加以确认；
3. **保护二进制数据的完整性**：对数据库、APK 等二进制文件的提取，严格规避 shell 通道可能引入的 CRLF 转换。

这一路线最终收敛为一条清晰的证据链，见第 8 章的机制链条图。

---

## 4. LSPosed 模块与作用域数据库分析

排查的第一步是确认乐健体育是否被某个 Xposed 模块在其“作用域（Scope）”配置中排除，或是否被其他模块刻意覆盖。

### 4.1 数据库的安全提取

LSPosed 的作用域配置保存在 SQLite 数据库 `modules_config.db` 中。由于二进制文件经 `adb shell cat` 重定向到本地会因 LF→CRLF 转换而损坏，本研究采用了“复制到共享目录再拉取”的方式：

```bash
# 错误方式（CRLF 转换会损坏二进制）：adb shell "su -c 'cat ...'" > x.db
# 正确方式：
adb shell "su -c 'cp /data/adb/lspd/config/modules_config.db /sdcard/mc.db && chmod 644 /sdcard/mc.db'"
adb pull //sdcard/mc.db modules_config.db   # Git Bash 下路径写成 //sdcard 防止 MSYS 路径转换
adb shell "su -c 'rm /sdcard/mc.db'"        # 清理
```

### 4.2 模块作用域分析

使用 Python `sqlite3` 读取该数据库。其表结构包括 `modules`、`modules_state`、`scope`、`module_configs`、`app_configs`、`lspd_configs` 等。关键结论如下：

- **启用的位置相关模块**：
  - `com.yinshibai.location`（FakeLocation，`enabled=1`），作用域全部为系统级进程：`system`、`android`、`com.android.phone`、`com.oplus.location`、`com.oplus.locationproxy`、`com.qualcomm.location` —— 属于全局生效型 hook；
  - `com.vincenthzr.locationspoofer`（`enabled=1`），作用域为具体应用（`com.autonavi.minimap`、`com.tencent.mm`、`com.chaoxing.mobile`、`com.google.android.gms`、**`com.ledreamer.zz`** —— 用户曾专门将乐健体育加入其中），但其 snapshot 配置 `active=false`（当时未启用）；
  - `moe.fuqiuluo.portaldev`（Portal，`enabled=1`），作用域为 `system`/`phone`/`location` 等系统级进程；
  - `com.zhenxi.hunter` 未启用（不在 `modules` 列表中）。
- `locationspoofer` 的 snapshot（存于 `module_configs` 表）如下：

  ```json
  {"lat":0,"lng":0,"active":false,"sim_mode":"STILL",...,"mock_wifi":false,"mock_cell":false,"mock_bluetooth":false,
   "system_hook_packages":[],"system_hook_global_mode":true,"satellite_count":20,...}
  ```

- **乐健体育没有被任何模块排除**，反而被专门加入过 `locationspoofer` 的作用域。由此初步排除了“模块作用域黑名单”这一假设。

### 4.3 系统定位输出形态观察

在 Portal 生效期间，通过 `dumpsys location` 观察到的系统定位输出如下：

```bash
adb shell "dumpsys location | grep 'last location'"
```

```
Location[fused 30.76****,103.98**** ... {Bundle[{portal.enable=true, allToggles=135179, is_mock=true}]}]
```

**重要发现**：Portal 注入的 `Location` 对象 extras 中自带 `is_mock=true`，相当于“自报家门”。这一细节解释了乐健体育为何能够识别 Portal 的模拟——其定位 SDK 只需读取 extras 即可发现异常。该观察为后续区分不同位置模拟工具的输出指纹埋下了伏笔。

---

## 5. 乐健体育 APK 反编译分析

在排除了模块作用域因素后，研究转向验证假设 B：乐健体育是否因采用了特殊的位置获取方式而天然免疫模拟。本章对乐健体育 APK 进行反编译，以刻画其定位能力与反模拟检测体系。

### 5.1 包结构

- dex：`assets/audience_network.dex` 与 `classes.dex` ~ `classes5.dex`（共 6 个）；
- 关键 so（arm64-v8a）：
  - `libAMapSDK_MAP_v9_4_0.so` —— 高德**地图** SDK；
  - `libbdface_sdk.so` + `libpaddle_light_api_shared.so` —— 百度人脸 SDK + PaddlePaddle（人脸检测/活体）；
  - `libdexvmp.so` —— VMP 加固（dex 虚拟化保护）；
  - `libsportaction.so` —— 运动姿态识别；
  - `libweexcore` / `libweexjss` / `libweexjsb` —— uni-app/Weex 容器（业务页面运行于 uni 小程序中，前台 Activity 为 `io.dcloud.feature.sdk.multi.DCUniMPTopActivity0`）；
  - `libsecsdk.so` / `libsecurity.so` —— 阿里无线保镖；
  - `libmarsxlog.so` / `libmmkv.so` —— 微信日志组件 / MMKV 存储。

### 5.2 定位能力画像（dex 关键字扫描）

对全部 dex 进行关键字扫描，脚本核心如下：

```python
import zipfile
z = zipfile.ZipFile('lejian.apk')
dexes = [n for n in z.namelist() if n.endswith('.dex')]
keywords = [b'com.amap.api.location', b'AMapLocationClient', b'com.baidu.location', b'BDLocation',
            b'com.tencent.map.geolocation', b'isFromMockProvider', b'LocationManager',
            b'requestLocationUpdates', b'getLastKnownLocation', b'WifiManager', b'getScanResults',
            b'getLocation', b'getCurrentPosition', ...]
for d in dexes:
    data = z.read(d)
    for kw in keywords:
        if kw in data: ...
```

扫描结果（计数）如下表：

| 类别 | 命中 | 说明 |
| --- | --- | --- |
| 高德定位 SDK | AMapLocation×45, AMapLocationClient×21, com.amap.api.location×3 | **混合定位主通道** |
| 百度定位 | LocationClient×23 | 备用定位通道 |
| 腾讯定位 | 无 | — |
| Mock 检测 | isFromMockProvider×1, MOCK×4 | 有反模拟检测 |
| 系统定位 API | LocationManager×23, requestLocationUpdates×6, getLastKnownLocation×2 | — |
| WiFi | WifiManager×8, getScanResults×2 | WiFi 指纹采集 |
| uni-app 定位 | geolocation×44, getLocation×29, getCurrentPosition×11 | JS 层定位入口 |

**结论**：乐健体育 = 高德 + 百度混合定位（GPS + WiFi 扫描 + 基站，服务端融合），并非纯 GPS 应用。

### 5.3 Mock 检测机制

对 `classes.dex` 全量提取可打印字符串，并筛出与 `mock` 相关的命中：

```python
strs = set(s.decode('ascii','ignore') for s in re.findall(rb'[\x20-\x7e]{4,}', data))
mockish = [s for s in strs if re.search(r'mock', s, re.I)]
```

关键命中（完整列表）：

```
!GpsLocation has been mocked!#1501          ← 高德 SDK 错误：GPS 位置被模拟（错误码 1501）
%networkLocation has been mocked!#1502      ← 网络位置被模拟（1502）
$CoarseLocation has been mocked!#2007       ← 粗略位置被模拟（2007）
'handleMessage RESULT_INSTALLED_MOCK_APP    ← 检测到已安装模拟应用
installMockApp / isInstalledHighDangerMockApp / setInstallHighDangerMockApp   ← 高危模拟应用名单检测
MaybeMockGPSLoc / MaybeMockNetLoc           ← 高德 SDK 内部疑似 mock 判定方法
CoarseLocation | isFromMock=                ← 日志拼接串
EXTRA_IS_MOCK                               ← Location extras 的 mock 键
getSetIsFromMockProviderMethod / sSetIsFromMockProviderMethod / setIsFromMockProvider   ← 反射获取 setIsFromMockProvider
isMock / isMockEnable / setMock / setMockEnable / mockLocation
```

（`MockView_*` 系列为 androidx UI 组件，与检测无关。）

**解读**：

- 1501/1502/2007 错误码来自高德定位 SDK 内部的 mock 检测——SDK 在回调中报错，而非返回被 mock 的位置；
- `isInstalledHighDangerMockApp` 表明检测分两层：位置对象本身的 mock 标志 + 设备上是否安装已知模拟软件（环境元数据，不经过位置对象）；
- `EXTRA_IS_MOCK` 说明应用会读取 `Location` 的 extras。

### 5.4 运行时权限与进程

```
ACCESS_FINE_LOCATION: granted=true
ACCESS_COARSE_LOCATION: granted=true
ACCESS_LOCATION_EXTRA_COMMANDS: granted=true
ACCESS_BACKGROUND_LOCATION: granted=false
进程：com.ledreamer.zz / com.ledreamer.zz:unimp0（uni 小程序）/ com.ledreamer.zz:jse
```

另观察到用户安装的 `top.ltfan.notdeveloper` 模块在乐健进程内 hook 了 `SystemProperties#get*` 与 `Settings$Global#getStringForUser`（用于隐藏开发者选项/模拟状态）。

综合第 5 章的发现可以判断：乐健体育的定位能力虽强（混合定位、多层检测），但所有定位数据本质上仍依赖系统数据源。因此假设 B 是否成立，取决于系统数据源在源头是否已被替换。这自然将调查焦点引向 FakeLocation 自身——即验证假设 A。

---

## 6. FakeLocation 内置加密黑名单的逆向与解密（核心发现）

本章是整个研究的核心。研究从 FakeLocation 的用户自定义配置入手，逐步深入到 APK 内部，最终定位并解密了那份加密的内置黑名单，并据此还原出完整的加密方案与算法参数。

### 6.1 用户自定义配置分析

首先检查 FakeLocation 的用户自定义黑名单：

```bash
adb shell "su -c 'cat /data/data/com.yinshibai.location/shared_prefs/blacklist.xml'"
```

```xml
<map>
    <boolean name="wifiSim" value="false" />
    <boolean name="cellSim" value="false" />
</map>
```

其中只有 WiFi/基站模拟开关，**无任何包名**——用户自定义黑名单为空。其他配置如下：

- `fake_location.xml`：`enabled=true`，`lat=30.76133376216448`，`lng=103.97135293582359`，`accuracy=2.0`，`report_interval=500ms`，`jitter=true`，`saved_points=[[三号教学楼,30.767...,103.984...]]`；
- `files/fake_location_state.txt`：运行状态快照（`enabled=false` 的旧状态文件）；
- `files/scripts/`：`api_tour.js` / `hover_drift.js` / `speed_wave.js` / `walk_square.js` —— JS 自动化脚本 API：

  ```
  loc.setPosition(lat,lng) loc.setAltitude(h) loc.setAccuracy(a) loc.setBearing(b)
  loc.setReportInterval(ms) loc.setJitter(bool) loc.start() loc.stop() loc.get()
  move.start(speed,bearing) route.setPath([[lat,lng],...],{smooth,samples}) route.start(speed) ...
  step.setSpm(spm)
  wifi.enable(bool) wifi.set({ssid,bssid,ip}) cell.enable(bool) cell.set({mcc,mnc,lac,cid})
  gnss.enable(bool)
  on('start'|'tick'|'stop'|'pathDone', fn)
  ```

- 云端配置 `cloud_config_pull.xml` 仅有时间戳。

既然用户自定义黑名单为空，则失效原因必然另有出处，需深入 APK 内部寻找。

### 6.2 黑名单机制字符串定位

对 FakeLocation 的 dex 提取字符串，并以 `blacklist`/`black`/`white`/`banned`/`exclud` 等关键字进行筛选：

```python
# 在字符串集合 strs 中搜索 blacklist/black/white/banned/exclud
```

关键命中（完整列表）：

```
/assets/blacklist.enc                          ← 加密内置名单（核心）
 /data/local/tmp/fl_blacklist.txt              ← 运行时覆盖名单（设备上不存在）
 /data/local/tmp/fl_whitelist.txt              ← 白名单覆盖
content://com.yinshibai.location.provider/blacklist   ← ContentProvider 运行时名单
"PASSTHRU(blacklisted) uid="                   ← hook 放行日志
" (BLACKLISTED, skipping hooks) ====="         ← 跳过 hook
"blacklistedListeners="
"startGnssBatch: blacklisted uid="
"Blacklist: runtime list updated: "            ← 名单运行时刷新（60s 周期）
"Blacklist: loadEncryptedBlacklist failed: ${e.message}"
"Settings: SET_BLACKLIST failed: "
"INSERT OR IGNORE INTO BLACK VALUES "          ← 数据库 BLACK 表
'<string name="blacklist">([\s\S]*?)</string>' ← 从字符串资源解析名单（远程配置通道）
"STARTING GPS HOOKS" / "GTransport hooks installed (system_server LocationManager inner classes)"
"Prov: LocationListenerTransport.deliverOnLocationChanged hooked"
"LMS.getLastLocation PASSTHRU: provider="
"WiFiSim: getScanResults PASSTHRU uid="
"Pusher: cycle globalEnabled=..." / "GnssRegistry: pushAll skipped (disabled)"
isFromMockProvider / mIsFromMockProvider / "Location.setMock/setIsFromMockProvider hook failed"
"LOC_HOOK FAIL: isFromMockProvider"
setMockGpsProbability / setMockGnssProbability / setMockGnssStrategy / setMockGpsStrategy
```

这些字符串表明：FakeLocation 确实维护了黑名单，其默认来源是 APK 内的一份加密文件 `assets/blacklist.enc`。其中 `PASSTHRU(blacklisted)` 与 `(BLACKLISTED, skipping hooks)` 两个日志串，直接印证了“对黑名单应用放行、跳过 hook”的行为。

### 6.3 加密方案的逆向还原

为还原黑名单的解密逻辑，使用 androguard 对 `classes.dex` 进行反编译。安装方式：

```bash
python -m pip install androguard pycryptodome   # 用 python -m pip 确保装入当前解释器
```

借助字符串交叉引用定位引用 `assets/blacklist.enc` 的类：

```python
from androguard.misc import AnalyzeDex
a, d, dx = AnalyzeDex('classes.dex')
targets = ['blacklist.enc', 'loadEncryptedBlacklist', 'skipping hooks', 'PASSTHRU(blacklisted)', ...]
for cls in d.get_classes():
    for em in cls.get_methods():
        code = em.get_code()
        if not code: continue
        for inst in code.get_bc().get_instructions():
            if inst.get_op_value() in (0x1a, 0x1b):   # const-string / const-string/jumbo
                s = inst.get_string()
                if s and any(t in s for t in targets):
                    print(cls.get_name(), em.get_name())
```

命中类：`Les;->intercept`、`Lrd1;->intercept`、`Lri;-><clinit>/h/g`、`Lsx0;->intercept`、`Lz92;->m`。

反编译黑名单管理器 `Lri;`，其关键字段与解密方法如下：

```java
// 字段
ri.b = new File("/data/data/com.yinshibai.location/shared_prefs/blacklist.xml");
ri.c = new File("/data/local/tmp/fl_blacklist.txt");
ri.d = new File("/data/local/tmp/fl_whitelist.txt");
ri.o = Uri.parse("content://com.yinshibai.location.provider/blacklist");
ri.g = 10000;   // 快速刷新周期 10s
ri.r = 60000;   // 慢速刷新周期 60s

// 解密方法（Key 与 IV 直接硬编码）
public static String a(byte[] p5) {
    SecretKeySpec key = new SecretKeySpec("FLblkey2026@1234".getBytes(), "AES");
    IvParameterSpec iv  = new IvParameterSpec("FLbliv2026@12345".getBytes());
    Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
    c.init(2, key, iv);
    return new String(c.doFinal(p5));
}
```

由上述反编译结果可知，该黑名单的加密方案为 **AES/CBC/PKCS5Padding**，且密钥与初始向量均以明文硬编码于应用中。其完整算法参数规范如下节所述。

### 6.4 AES 加密算法参数规范

为便于复现与互操作，本节对上述逆向所得加密方案进行形式化说明。

**1. 分组密码算法**：AES（Advanced Encryption Standard，NIST FIPS 197）。AES 的分组长度为固定 128 bit（16 字节）。密钥长度由密钥字节数决定——本方案中密钥为 16 字节，故对应 **AES-128**。

**2. 加密模式**：CBC（Cipher Block Chaining，密码分组链接模式）。CBC 模式下，每个明文分组在加密前需与前一密文分组异或，首个分组则与初始向量 IV 异或。因此 CBC 模式必须显式提供 IV，且同一密钥下 IV 不应重复使用。

**3. 填充方式**：PKCS5Padding。该填充将明文补齐至分组长度的整数倍，补入的每个字节值为所补字节数。需要特别说明的是，Java 中的 `PKCS5Padding` 与 .NET 中的 `PKCS7` 在 AES 的 16 字节分组下**完全等价**——PKCS#5 严格定义于 8 字节分组，PKCS#7 推广到任意分组长度；当分组长度为 16 字节时，二者行为一致。因此采用 .NET 实现时使用 `PaddingMode.PKCS7` 即可与 Android 端完全对齐。

**4. 算法参数**（由反编译精确还原）：

| 参数 | 取值 | 说明 |
| --- | --- | --- |
| 算法 | `AES/CBC/PKCS5Padding` | 对称分组加密 |
| 密钥 Key | `FLblkey2026@1234` | UTF-8 编码 16 字节 → AES-128 |
| 初始向量 IV | `FLbliv2026@12345` | UTF-8 编码 16 字节 |
| 密文编码 | 单行 Base64 | 无换行、无 BOM、无行尾换行 |
| 明文格式 | UTF-8 文本 | 每行一个包名，支持 `#` 注释 |

其中密钥 `FLblkey2026@1234` 以 `FLblkey2026` 为前缀标识该密钥的用途与版本。密钥与 IV 均直接硬编码于应用内，属于典型的“客户端内置对称密钥”方案，其安全性仅依赖混淆加固带来的逆向成本，而非密钥本身强度。

### 6.5 加解密脚本实现

为使上述加密方案可被独立复现与双向互操作，本节给出两套配套的 PowerShell 脚本：解密脚本将 `blacklist.enc` 还原为可读文本，加密脚本则反向生成 `.enc`。两脚本均严格遵循 6.4 节定义的算法参数与文件格式规范，可与 Android 端的 Java 实现完全对齐。脚本源文件位于本仓库 `tools/` 目录，完整内容如下。

#### 6.5.1 解密脚本 `decrypt_blacklist.ps1`

```powershell
# decrypt_blacklist.ps1
# Decrypt app/src/release/assets/blacklist.enc back to plaintext for review/edit.
#
# File spec (must match the Android reader exactly):
#   Algorithm : AES/CBC/PKCS5Padding  (.NET: PKCS7, identical for 16-byte blocks)
#   Key       : FLblkey2026@1234      (UTF-8 bytes, 16 chars -> AES-128)
#   IV        : FLbliv2026@12345      (UTF-8 bytes, 16 chars)
#   Encoding  : single-line Base64, no line breaks, no BOM, no trailing newline
#
# Usage:
#   powershell -File tools/decrypt_blacklist.ps1 -InputPath app/src/release/assets/blacklist.enc -OutputPath blacklist.txt
#
param(
    [string]$InputPath  = "app/src/release/assets/blacklist.enc",
    [string]$OutputPath = "blacklist.txt"
)

$ErrorActionPreference = "Stop"

$Key = [System.Text.Encoding]::UTF8.GetBytes("FLblkey2026@1234")
$Iv  = [System.Text.Encoding]::UTF8.GetBytes("FLbliv2026@12345")

if ($Key.Length -ne 16) { throw "Key must be 16 bytes after UTF-8 encoding." }
if ($Iv.Length  -ne 16) { throw "IV must be 16 bytes after UTF-8 encoding." }

if (-not (Test-Path -LiteralPath $InputPath)) {
    throw "Encrypted file not found: $InputPath"
}

# Read the whole file, trim any whitespace/newlines defensively, then Base64-decode.
$raw = [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $InputPath)).Trim()
$cipher = [Convert]::FromBase64String($raw)
if ($cipher.Length % 16 -ne 0) {
    throw "Invalid ciphertext length ($($cipher.Length) bytes), not a multiple of the AES block size."
}

$aes = [System.Security.Cryptography.Aes]::Create()
try {
    $aes.Mode        = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding     = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.KeySize     = 128
    $aes.BlockSize   = 128
    $aes.Key         = $Key
    $aes.IV          = $Iv

    $decryptor = $aes.CreateDecryptor()
    try {
        $plain = $decryptor.TransformFinalBlock($cipher, 0, $cipher.Length)
    } finally {
        $decryptor.Dispose()
    }
} finally {
    $aes.Dispose()
}

# Write plaintext bytes as-is (no BOM, no trailing newline added).
$outFull = [System.IO.Path]::GetFullPath($OutputPath)
$outDir = Split-Path -Parent $outFull
if (-not (Test-Path -LiteralPath $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}
[System.IO.File]::WriteAllBytes($outFull, $plain)

Write-Host ("Decrypted OK: {0} Base64 chars -> {1} bytes cipher -> {2} bytes plaintext" -f $raw.Length, $cipher.Length, $plain.Length)
Write-Host "Output: $outFull"
```

#### 6.5.2 加密脚本 `encrypt_blacklist.ps1`

```powershell
# encrypt_blacklist.ps1
# Encrypt the blacklist plaintext into app/src/release/assets/blacklist.enc
#
# File spec (must match the Android reader exactly):
#   Algorithm : AES/CBC/PKCS5Padding  (.NET: PKCS7, identical for 16-byte blocks)
#   Key       : FLblkey2026@1234      (UTF-8 bytes, 16 chars -> AES-128)
#   IV        : FLbliv2026@12345      (UTF-8 bytes, 16 chars)
#   Encoding  : single-line Base64, no line breaks, no BOM, no trailing newline
#
# Usage:
#   powershell -File tools/encrypt_blacklist.ps1
#   powershell -File tools/encrypt_blacklist.ps1 -PlaintextPath blacklist.txt -OutputPath app/src/release/assets/blacklist.enc
#
param(
    [string]$PlaintextPath = "blacklist.txt",
    [string]$OutputPath    = "app/src/release/assets/blacklist.enc"
)

$ErrorActionPreference = "Stop"

$Key = [System.Text.Encoding]::UTF8.GetBytes("FLblkey2026@1234")
$Iv  = [System.Text.Encoding]::UTF8.GetBytes("FLbliv2026@12345")

if ($Key.Length -ne 16) { throw "Key must be 16 bytes after UTF-8 encoding." }
if ($Iv.Length  -ne 16) { throw "IV must be 16 bytes after UTF-8 encoding." }

if (-not (Test-Path -LiteralPath $PlaintextPath)) {
    throw "Plaintext file not found: $PlaintextPath"
}

# Read plaintext as raw bytes: do NOT add or strip anything,
# comments (#) and line endings are preserved as-is.
$plain = [System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $PlaintextPath))

$aes = [System.Security.Cryptography.Aes]::Create()
try {
    $aes.Mode        = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding     = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.KeySize     = 128
    $aes.BlockSize   = 128
    $aes.Key         = $Key
    $aes.IV          = $Iv

    $encryptor = $aes.CreateEncryptor()
    try {
        $cipher = $encryptor.TransformFinalBlock($plain, 0, $plain.Length)
    } finally {
        $encryptor.Dispose()
    }
} finally {
    $aes.Dispose()
}

# Single-line Base64, written without BOM and without trailing newline.
$b64 = [Convert]::ToBase64String($cipher)
$enc = New-Object System.Text.UTF8Encoding($false)
$outFull = [System.IO.Path]::GetFullPath($OutputPath)
$outDir = Split-Path -Parent $outFull
if (-not (Test-Path -LiteralPath $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}
[System.IO.File]::WriteAllText($outFull, $b64, $enc)

Write-Host ("Encrypted OK: {0} bytes plaintext -> {1} bytes cipher -> {2} Base64 chars" -f $plain.Length, $cipher.Length, $b64.Length)
Write-Host "Output: $outFull"
```

两脚本在实现上严格遵循以下互操作要点：密钥与 IV 均以 UTF-8 字节编码并校验长度为 16 字节；CBC 模式下显式设置 `Mode=CBC`、`Padding=PKCS7`（等价于 Java 的 `PKCS5Padding`）；密文采用单行 Base64 编码且不带 BOM 与行尾换行；解密端对 Base64 解码后的密文长度做 16 字节对齐校验；加密端对明文按原始字节读取，保留 `#` 注释与换行符原样。

### 6.6 解密执行与结果

依据上述方案，使用 Python 与 `pycryptodome` 对 `blacklist.enc` 执行解密（亦可直接使用 6.5 节的解密脚本）：

```python
import base64
from Crypto.Cipher import AES
import zipfile
raw = zipfile.ZipFile('fake.apk').read('assets/blacklist.enc')   # 11840 字节，Base64 文本
ct  = base64.b64decode(raw.strip())
pt  = AES.new(b'FLblkey2026@1234', AES.MODE_CBC, b'FLbliv2026@12345').decrypt(ct)
pad = pt[-1]; pt = pt[:-pad]      # 去 PKCS5 padding
open('blacklist_decrypted.txt','w',encoding='utf-8').write(pt.decode('utf-8'))
```

解密后的文件头（作者注释原文）：

```
# 每行一个包名（支持 # 注释）。模拟开启时，黑名单内的 App 会拿到真实位置/基站/WiFi。
# 填好后执行：powershell -File tools/encrypt_blacklist.ps1
# 它会重新生成 app/src/release/assets/blacklist.enc，然后重新编译安装。
```

解密结果统计：

- 共 **400 条包名**；
- 构成：司机/网约车/货运类约 161 条（滴滴 `com.sdu.didi.gsui`、各代驾货运类）、办公考勤类 14 条（钉钉 `com.alibaba.android.rimet` 等）、打卡类 10 条、运动类若干（悦动圈 `com.joyrun.funrun`、`com.cmri.healthy.sport`、`net.crigh.cgsport` 等）；
- **`com.ledreamer.zz`（乐健体育）在名单中** —— 原始问题实锤。

至此，假设 A 得到静态层面的确认：FakeLocation 通过一份 AES 加密的内置黑名单，将乐健体育排除在模拟范围之外。下一章将通过运行时观测对该结论做动态验证。

---

## 7. 运行时动态验证

为确证第 6 章的静态结论在真实运行环境中成立，本章在开启模拟的状态下观测系统定位输出与 hook 日志。

### 7.1 模拟位置输出形态

```bash
adb shell "dumpsys location | grep -E 'last location|is_mock|mock'"
```

GPS provider 输出（8 条变体，带抖动）：

```
Location[gps 39.90****,116.41**** hAcc=2.76 et=... {Bundle[{satellites=20, lat=39.90420698027867, lng=116.40740698027867}]}]
```

分析：

- 坐标为北京天安门（39.9042, 116.4074）—— 正是其示例脚本 `api_tour.js` 里的演示点；
- **无任何 mock 标记**（对比 Portal 生效期 extras 中的 `is_mock=true`，FakeLocation 的输出没有该标记）；
- 但存在**指纹**：原生 Android GPS Location 的 extras 正常仅含 `satellites`；此处 `lat=.../lng=...` 自定义键 + 恒定 `satellites=20` 是可被高级检测识别的特征。

### 7.2 Hook 运行日志

```bash
adb shell "logcat -d | grep -iE 'XposedEntry|GTransport|PASSTHRU|Blacklist|blacklisted'"
```

```
XposedEntry: LSNR_LIST: 39.90419...,116.40739... → 39.90420...,116.40740...   ← 每 2~3 秒向监听器推送模拟坐标
XposedEntry: WiFiSim: getConnectionInfo PASSTHRU uid=10139 blacklisted=false enabled=true sim=false
XposedEntry: WiFiSim: getScanResults PASSTHRU(PLS) uid=10136 blacklisted=false
XposedEntry: Pusher: cycle globalEnabled=false effectiveEnabled=false registrySize=26
XposedEntry: GnssRegistry: pushAll skipped (disabled)     ← GNSS 卫星注入当前关闭
E ActivityThread: Failed to find provider info for com.yinshibai.location.provider
   （来自 com.android.phone / com.qualcomm.location / com.oplus.location，每 2 秒一次
     —— 系统服务里的 hook 反复尝试从 ContentProvider 拉运行时名单，应用进程不在线时失败，
        fallback 到 APK 内置的 blacklist.enc）
```

上述日志直接印证了黑名单机制的实际运行：`PASSTHRU` 与 `blacklisted=` 判定逻辑实时生效，且在运行时名单不可用时自动回退到内置的加密黑名单。

### 7.3 Mock 标志位的处理

- FakeLocation hook `Location.setMock` / `setIsFromMockProvider`，并直接读写字段 `mIsFromMockProvider`；
- 注入方式为 `system_server` 层（不走标准 `mock_location_app` 通道，该设置值为 null），系统不会自动打 mock 标记；
- **结论：其模拟位置对象 `isMock=false`，官方 mock 标志位被主动压制。**

### 7.4 乐健体育的现场

- 乐健运行中（3 进程），权限已授予，但未触发实际定位请求期间：
  - `dumpsys location` 中查不到 `ledreamer` 的监听注册；
  - 未捕获 `uid=10459 ... blacklisted=true` 的 PASSTHRU 现场（其他 uid 的 `blacklisted=false` 证明判定逻辑实时在跑）；
- 若需抓取完整现场：开启 FakeLocation 模拟 → 乐健进入定位页面 → `adb logcat` 中过滤 `uid=10459` 与 `has been mocked|1501|1502|2007`。

动态验证的结果与静态分析一致，两条证据链相互印证，共同确立了本研究结论。

---

## 8. 结论与讨论

### 8.1 原始问题解答

| 问题 | 答案 |
| --- | --- |
| 模拟软件内部是否有黑名单排除乐健？ | **是**。FakeLocation APK 内 `assets/blacklist.enc`（AES 硬编码密钥加密）含 400 条包名，`com.ledreamer.zz` 在列。 |
| 是不是乐健有其他定位方式导致模拟无效？ | 不是主因。乐健虽用高德+百度混合定位（WiFi/基站参与），但 FakeLocation 本可全链路模拟（wifi/cell/gnss 脚本 API 均具备）；失效的直接原因是在数据源头被黑名单放行真实数据。 |
| 用户自定义黑名单是否为空？ | 是（`blacklist.xml` 仅含 `wifiSim`/`cellSim` 布尔值）。 |
| FakeLocation 的模拟位置带 mock 标签吗？ | 不带。`system_server` 层注入 + hook `Location.setMock/setIsFromMockProvider` 强制 `isMock=false`。但有指纹：非标准 extras（`lat`/`lng` 键）、恒定 `satellites=20`。 |
| 乐健会检测到模拟吗？ | 位置数据层面到不了乐健（黑名单放行真实数据）；乐健的检测层（`isFromMockProvider`/1501/1502/2007/`EXTRA_IS_MOCK`）主要针对位置对象，另有 `isInstalledHighDangerMockApp` 检测设备上安装的模拟应用（环境元数据通道，FakeLocation 管不到）+ 服务端风控（VMP 加固、人脸活体、运动姿态、轨迹合理性）。 |

### 8.2 机制链条图

```
FakeLocation(com.yinshibai.location)
  ├─ LSPosed hook 系统进程: system / android / com.android.phone / com.oplus.location / com.qualcomm.location
  ├─ 名单加载: assets/blacklist.enc (AES/CBC/PKCS5, key=FLblkey2026@1234, iv=FLbliv2026@12345)
  │            + ContentProvider 运行时名单 + fl_blacklist.txt 覆盖 (均未在设备上生效)
  ├─ 对普通 App: 注入模拟 GPS/WiFi/基站, Location extras 无 mock 标记
  └─ 对黑名单 App(含乐健): PASSTHRU 放行原生真实数据 → "模拟对它无效"

乐健体育(com.ledreamer.zz, uni 小程序 + VMP 加固)
  ├─ 定位: 高德 AMapLocationClient + 百度 LocationClient 混合定位(GPS+WiFi+基站→服务端融合)
  ├─ 位置层检测: isFromMockProvider / EXTRA_IS_MOCK / AMap 1501|1502|2007 "has been mocked"
  ├─ 环境层检测: isInstalledHighDangerMockApp(高危模拟应用安装检测) / RESULT_INSTALLED_MOCK_APP
  └─ 服务端风控: 人脸活体(libbdface_sdk+paddle) / 运动姿态(libsportaction) / 轨迹合理性
```

### 8.3 局限性与伦理说明

本研究存在以下局限：其一，运行时未捕获到乐健体育发起定位请求的确切现场，黑名单放行行为以日志逻辑 + 静态代码为证，未对乐健进程做单次完整链路抓取；其二，LocationSpoofer 模块在研究期间处于 `active=false`，其输出指纹未能采集对比。

需要说明的是，本研究的定位是**技术机理的客观还原与记录**，目的在于理解位置模拟工具与运动类应用之间的对抗机制。文中披露的密钥、黑名单与脚本均来自对公开分发 APK 的逆向分析，仅用于研究与教学，不构成对任何系统安全机制的绕过指引，亦不鼓励利用本文内容规避任何应用的合法合规条款。

---

## 9. 复现要点与踩坑记录

1. **二进制文件不能 `adb shell cat > 本地文件`**：shell 通道 LF→CRLF 转换会损坏 sqlite/db 等二进制。正确做法：`su -c 'cp 目标 /sdcard/ && chmod 644'` 再 `adb pull`。
2. **Git Bash 路径转换**：`adb pull /sdcard/mc.db` 会被 MSYS 转成本地路径导致报错，需写成 `adb pull //sdcard/mc.db`（双斜杠）。
3. **androguard API**：`dx.get_strings()` 的 xref API 各版本不一致；可靠做法是遍历 `d.get_classes()` → `get_methods()` → `get_code().get_bc().get_instructions()`，用 `inst.get_op_value() in (0x1a, 0x1b)` + `inst.get_string()` 抓 `const-string`。
4. **shell 内联脚本语法错误会被 `2>/dev/null` 吞掉**：grep 管道报错时先去掉重定向确认脚本本身能跑。
5. **androguard 会生成 `androguard.db` 会话缓存**，重复分析同一 dex 时注意删除或忽略。
6. **混淆类名**：FakeLocation 的业务类全部混淆（`Les`/`Lrd1`/`Lri`/`Lsx0`/`Lz92` 等），定位逻辑靠字符串交叉引用而非类名。
7. **乐健 dex 有 6 个**（`classes.dex`~`classes5.dex` + `assets/audience_network.dex`），关键字扫描需全覆盖。
8. **区分三个位置模拟工具的输出特征**（`dumpsys location` 的 extras）：
   - Portal：`{portal.enable=true, allToggles=..., is_mock=true}` ← 自带 mock 标记，易被识别；
   - FakeLocation：`{satellites=20, lat=..., lng=...}` ← 无 mock 标记，有非标准键指纹；
   - LocationSpoofer：本次研究期间 `active=false`，未采集。
9. **.NET 与 Java 的填充对齐**：脚本实现中 `PaddingMode.PKCS7` 与 Java `PKCS5Padding` 在 16 字节分组下等价，切勿误用 `PaddingMode.PKCS5`（.NET 并无该枚举，强行使用会抛异常或产生不兼容填充）。

---

## 10. 附录

### 10.1 文件清单

| 文件 | 说明 |
| --- | --- |
| `fake.apk` | `com.yinshibai.location` v2.1.4 base.apk（18.4MB） |
| `lejian.apk` | `com.ledreamer.zz` v3.10.3 base.apk（116.5MB） |
| `modules_config.db` | LSPosed 模块/作用域数据库（从 `/data/adb/lspd/config` 拉取） |
| `assets_blacklist.enc` | FakeLocation 内置加密黑名单原文（11840 字节 Base64） |
| `blacklist_decrypted.txt` | 解密后的 400 条内置黑名单（UTF-8） |
| `live_capture.log` | 模拟开启状态的 logcat 抓取（81956 行） |
| `classes.dex` | fake.apk 解出的 dex（androguard 分析用） |
| `tools/decrypt_blacklist.ps1` | 黑名单解密脚本（本仓库） |
| `tools/encrypt_blacklist.ps1` | 黑名单加密脚本（本仓库） |
| `README.md` | 本报告 |

### 10.2 参考文献

1. NIST. *FIPS PUB 197: Advanced Encryption Standard (AES)*. National Institute of Standards and Technology, 2001.
2. Housley, R. *Cryptographic Message Syntax (CMS)*, RFC 5652. IETF, 2009.（PKCS#7 填充规范）
3. Kaliski, B. *PKCS #5: Password-Based Cryptography Specification Version 2.1*, RFC 8018. IETF, 2017.
4. LSPosed Framework. https://github.com/LSPosed/LSPosed
5. KernelSU. https://github.com/tiann/KernelSU
6. androguard. https://github.com/androguard/androguard
7. PyCryptodome. https://pycryptodome.org
8. 高德开放平台定位 SDK 文档. https://lbs.amap.com
9. 百度地图开放平台定位 SDK 文档. https://lbsyun.baidu.com

---

*本报告由逆向分析过程整理而成，各部分内容（研究过程、加密算法说明与加解密脚本）相互印证、有机统一，供技术研究与教学参考。*
