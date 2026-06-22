# 动态行为监测清单

本文档记录 payload 当前已实现的所有 Hook 点，供日常维护和新增参考。

**维护规则**
- 新增 hook：在 `HookerBridge.java` 添加备份字段 + 回调方法，在 `hooks.cpp` 添加 `hook_one` 调用，并在本文档对应分类下补充一行。
- 修改/删除 hook：同步更新代码和本文档。
- 日志格式统一为：`{"type":"behavior","method":"<method>","data":"<data>","stack":"<frame1>|<frame2>|...","timestamp":<ms>}`，tag = `payload`。
- `stack` 字段：跳过 `com.pecker.payload.*`、`java.lang.Thread`、`java.lang.reflect.*` 等框架帧，保留最多 12 个应用侧帧，格式为 `类名.方法名:行号|...`。

---

## 分类一：设备标识

| # | Java API | JNI 签名 | 静态 | 捕获内容 | 日志 method 字段 |
|---|----------|---------|------|---------|-----------------|
| 1 | `android.telephony.TelephonyManager.getDeviceId()` | `()Ljava/lang/String;` | 否 | IMEI | `TelephonyManager.getDeviceId` |
| 2 | `android.telephony.TelephonyManager.getSubscriberId()` | `()Ljava/lang/String;` | 否 | IMSI | `TelephonyManager.getSubscriberId` |
| 3 | `android.telephony.TelephonyManager.getSimSerialNumber()` | `()Ljava/lang/String;` | 否 | ICCID | `TelephonyManager.getSimSerialNumber` |
| 4 | `android.telephony.TelephonyManager.getLine1Number()` | `()Ljava/lang/String;` | 否 | 手机号 | `TelephonyManager.getLine1Number` |
| 5 | `android.provider.Settings.Secure.getString(ContentResolver, String)` | `(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;` | 是 | android_id 等系统值（key 嵌入 method 字段） | `Settings.Secure.getString[<key>]` |
| 6 | `android.net.wifi.WifiInfo.getMacAddress()` | `()Ljava/lang/String;` | 否 | WiFi MAC 地址 | `WifiInfo.getMacAddress` |
| 7 | `java.net.NetworkInterface.getHardwareAddress()` | `()[B` | 否 | 网卡 MAC 地址（hex 格式） | `NetworkInterface.getHardwareAddress` |
| 8 | `android.app.Activity.onCreate(Bundle)` | `(Landroid/os/Bundle;)V` | 否 | Activity 类名（启动探针） | `Activity.onCreate` |

---

## 分类二：位置信息

| # | Java API | JNI 签名 | 静态 | 捕获内容 | 日志 method 字段 |
|---|----------|---------|------|---------|-----------------|
| 9 | `android.location.LocationManager.getLastKnownLocation(String)` | `(Ljava/lang/String;)Landroid/location/Location;` | 否 | 经纬度 + provider | `LocationManager.getLastKnownLocation[<provider>]` |
| 10 | `android.location.Location.getLatitude()` | `()D` | 否 | 纬度（double） | `Location.getLatitude` |
| 11 | `android.location.Location.getLongitude()` | `()D` | 否 | 经度（double） | `Location.getLongitude` |
| 12 | `android.location.LocationManager.requestLocationUpdates(String, long, float, LocationListener)` | `(Ljava/lang/String;JFLandroid/location/LocationListener;)V` | 否 | provider + minTime(ms) + minDist(m) | `LocationManager.requestLocationUpdates` |
| 13 | `android.location.LocationManager.requestLocationUpdates(String, long, float, LocationListener, Looper)` | `(Ljava/lang/String;JFLandroid/location/LocationListener;Landroid/os/Looper;)V` | 否 | provider + minTime + minDist | `LocationManager.requestLocationUpdates` |
| 14 | `android.location.LocationManager.requestLocationUpdates(Criteria, long, float, LocationListener)` | `(Landroid/location/Criteria;JFLandroid/location/LocationListener;)V` | 否 | Criteria(FINE/COARSE) + minTime + minDist | `LocationManager.requestLocationUpdates` |
| 15 | `android.location.LocationManager.requestLocationUpdates(Criteria, long, float, LocationListener, Looper)` | `(Landroid/location/Criteria;JFLandroid/location/LocationListener;Landroid/os/Looper;)V` | 否 | Criteria(FINE/COARSE) + minTime + minDist | `LocationManager.requestLocationUpdates` |

---

## 分类三：敏感数据访问

| # | Java API | JNI 签名 | 静态 | 捕获内容 | 日志 method 字段 |
|---|----------|---------|------|---------|-----------------|
| 12 | `android.content.ContentResolver.query(Uri, String[], Bundle, CancellationSignal)` | `(Landroid/net/Uri;[Ljava/lang/String;Landroid/os/Bundle;Landroid/os/CancellationSignal;)Landroid/database/Cursor;` | 否 | 联系人 / 短信 / 通话记录 / 日历 / 媒体库 URI（仅记录含敏感关键词的 URI） | `ContentResolver.query` |
| 13 | `android.hardware.camera2.CameraManager.openCamera(String, StateCallback, Handler)` | `(Ljava/lang/String;Landroid/hardware/camera2/CameraDevice$StateCallback;Landroid/os/Handler;)V` | 否 | 摄像头 ID | `CameraManager.openCamera` |
| 14 | `android.media.MediaRecorder.setAudioSource(int)` | `(I)V` | 否 | 音频来源编号（1=MIC, 5=CAMCORDER 等） | `MediaRecorder.setAudioSource` |
| 15 | `android.content.ClipboardManager.getPrimaryClip()` | `()Landroid/content/ClipData;` | 否 | 剪贴板第一条文本内容 | `ClipboardManager.getPrimaryClip` |
| 16 | `android.hardware.Camera.open()` | `()Landroid/hardware/Camera;` | 是 | 旧版摄像头 API（默认摄像头） | `Camera.open` |
| 17 | `android.hardware.Camera.open(int)` | `(I)Landroid/hardware/Camera;` | 是 | 旧版摄像头 API（指定 ID） | `Camera.open` |
| 18 | `android.media.AudioRecord.startRecording()` | `()V` | 否 | 录音开始事件 | `AudioRecord.startRecording` |
| 19 | `android.app.ActivityManager.getRunningAppProcesses()` | `()Ljava/util/List;` | 否 | 运行进程列表（返回数量） | `ActivityManager.getRunningAppProcesses` |
| 20 | `java.lang.Runtime.exec(String)` | `(Ljava/lang/String;)Ljava/lang/Process;` | 否 | 执行的 shell 命令字符串 | `Runtime.exec` |
| 21 | `java.lang.Runtime.exec(String[])` | `([Ljava/lang/String;)Ljava/lang/Process;` | 否 | 执行的 shell 命令数组（空格拼接） | `Runtime.exec[]` |
| 22 | `java.lang.ProcessBuilder.start()` | `()Ljava/lang/Process;` | 否 | 执行的命令（command() 列表） | `ProcessBuilder.start` |
| 23 | `android.app.Activity.startActivity(Intent)` | `(Landroid/content/Intent;)V` | 否 | Intent action 字符串 | `Activity.startActivity` |
| 24 | `android.app.Activity.startActivityForResult(Intent, int)` | `(Landroid/content/Intent;I)V` | 否 | Intent action + requestCode | `Activity.startActivityForResult` |
| 25 | `android.media.MediaRecorder.start()` | `()V` | 否 | 录制开始事件 | `MediaRecorder.start` |
| 26 | `android.content.BroadcastReceiver.onReceive(Context, Intent)` | `(Landroid/content/Context;Landroid/content/Intent;)V` | 否 | Intent action（开机广播等）⚠️ 抽象方法，部分机型生效 | `BroadcastReceiver.onReceive` |

---

## 分类四：网络请求

| # | Java API | JNI 签名 | 静态 | 捕获内容 | 日志 method 字段 |
|---|----------|---------|------|---------|-----------------|
| 24 | `java.net.URL.openConnection()` | `()Ljava/net/URLConnection;` | 否 | 请求 URL 字符串 | `URL.openConnection` |
| 25 | `okhttp3.OkHttpClient.newCall(Request)` | `(Lokhttp3/Request;)Lokhttp3/Call;` | 否 | OkHttp 请求 URL（App 未打包 OkHttp3 时自动跳过） | `OkHttpClient.newCall` |
| 26 | `okhttp3.RealCall.execute()` | `()Lokhttp3/Response;` | 否 | OkHttp 同步请求 URL + 响应状态码 | `OkHttp3.RealCall.execute` |
| 27 | `okhttp3.RealCall.enqueue(Callback)` | `(Lokhttp3/Callback;)V` | 否 | OkHttp 异步请求 URL + 响应状态码（通过 Callback Proxy 拦截） | `OkHttp3.RealCall.enqueue` |
| 28 | `com.android.volley.toolbox.StringRequest.deliverResponse(String)` | `(Ljava/lang/String;)V` | 否 | Volley 响应体前 256 字符（App 未打包 Volley 时自动跳过） | `Volley.StringRequest.deliverResponse` |
| 29 | `libssl.so SSL_write(SSL*, const void*, int)` | native | — | SNI host + 明文长度 + 前128字节预览（文本/hex） | `SSL_write` |
| 30 | `libssl.so SSL_read(SSL*, void*, int)` | native | — | SNI host + 明文长度 + 前128字节预览（文本/hex） | `SSL_read` |

---

## 分类五：传感器

采样率常量：`0`=NORMAL, `1`=UI, `2`=GAME, `3`=FASTEST，或具体微秒数。

| # | Java API | JNI 签名 | 静态 | 捕获内容 | 日志 method 字段 |
|---|----------|---------|------|---------|-----------------|
| 31 | `android.hardware.SensorManager.registerListener(SensorEventListener, Sensor, int)` | `(Landroid/hardware/SensorEventListener;Landroid/hardware/Sensor;I)Z` | 否 | 传感器类型编号 + 类型名 + 硬件名称 + 采样率 | `SensorManager.registerListener` |
| 32 | `android.hardware.SensorManager.registerListener(SensorEventListener, Sensor, int, int)` | `(Landroid/hardware/SensorEventListener;Landroid/hardware/Sensor;II)Z` | 否 | 同上 + 最大延迟（maxLatency） | `SensorManager.registerListener` |
| 33 | `android.hardware.SensorManager.registerListener(SensorEventListener, Sensor, int, Handler)` | `(Landroid/hardware/SensorEventListener;Landroid/hardware/Sensor;ILandroid/os/Handler;)Z` | 否 | 同上 + Handler | `SensorManager.registerListener` |

---

## 分类六：权限申请

| # | Java API | JNI 签名 | 静态 | 捕获内容 | 日志 method 字段 |
|---|----------|---------|------|---------|-----------------|
| 34 | `android.app.Activity.requestPermissions(String[], int)` | `([Ljava/lang/String;I)V` | 否 | 申请的权限列表（逗号分隔） | `Activity.requestPermissions` |
| 35 | `android.app.Activity.checkSelfPermission(String)` | `(Ljava/lang/String;)I` | 否 | 被查询的权限名（仅记录结果为 DENIED 的） | `Activity.checkSelfPermission` |
| 36 | `androidx.core.app.ActivityCompat.requestPermissions(Activity, String[], int)` | `(Landroid/app/Activity;[Ljava/lang/String;I)V` | 是 | 申请的权限列表（App 未打包 androidx 时自动跳过） | `ActivityCompat.requestPermissions` |

---

## 分类七：SSL Pinning 绕过

日志 type 为 `behavior`，method 统一为 `SSLPinning.bypass`，data 说明具体绕过点。

| # | Java API | JNI 签名 | 静态 | 捕获内容 | 日志 method 字段 |
|---|----------|---------|------|---------|-----------------|
| 37 | `okhttp3.CertificatePinner.check(String, List)` | `(Ljava/lang/String;Ljava/util/List;)V` | 否 | 被绕过的域名（App 未打包 OkHttp3 时跳过） | `SSLPinning.bypass` |
| 38 | `javax.net.ssl.SSLContext.init(KeyManager[], TrustManager[], SecureRandom)` | `([Ljavax/net/ssl/KeyManager;[Ljavax/net/ssl/TrustManager;Ljava/security/SecureRandom;)V` | 否 | TrustManager 替换为 trust-all | `SSLPinning.bypass` |
| 39 | `javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier(HostnameVerifier)` | `(Ljavax/net/ssl/HostnameVerifier;)V` | 是 | HostnameVerifier 替换为 always-true | `SSLPinning.bypass` |

---

## 分类八：界面文字采集（ui_text）

与上述 behavior hook 不同，本项不挂某个 API，而是借 `Activity.onCreate`（分类一 #8）作触发器，在页面布局完成后扫描**当前进程全部窗口**的可见文字并整页上报，供**服务端**比对 `dim_ui_keyword`（敏感个人信息字段名）。payload 侧只采集、不匹配、不打 flag。

- **日志格式**：`{"type":"ui_text","activity":"<Activity类名>","text":"<行1>\n<行2>...","timestamp":<ms>}`，tag = `payload`。
- **触发 / 去重**：每次 `Activity.onCreate` 后延迟 `UI_TEXT_SCAN_DELAY_MS`（默认 1000ms）单次扫描；仅主进程（子进程跳过）；按 `activity+内容hash` 去重，同页同内容每进程只发一次。
- **文本来源**：
  - 原生视图：`WindowManagerGlobal.mViews` 全窗口根 → 递归取 `TextView.getText()` / `View.getContentDescription()`（含本进程的 Dialog/Popup，不含系统弹窗及其它进程）。
  - WebView：反射「鸭子类型」——对声明了 `evaluateJavascript(String, <ValueCallback>)` 的 View，动态 `Proxy` 其回调读 `document.body.innerText`，**一套覆盖** `android.webkit.WebView` / X5 `com.tencent.smtt.sdk.WebView` / xweb `com.tencent.xweb.WebView`；异步回调各自补发一条 `ui_text`。**不新增任何 lsplant hook**（纯反射调用），对注入成功率无影响。
- **编译期开关**（`HookerBridge.java`，编译前启/关；关闭则该路径为死代码、零开销、无 @pecker 流量）：

| 开关 | 作用 |
|------|------|
| `UI_TEXT_ENABLED` | 整个 ui_text 采集总闸 |
| `WEBVIEW_TEXT_ENABLED` | 仅 WebView/X5/xweb 抽取，可独立关闭、保留原生文本 |

- **相关方法**：`scheduleUiTextScan` / `scanUiTextOnce` / `collectUiText` / `looksLikeWebView` / `extractWebViewText` / `unquoteJsString` / `emitUiText`。
- **后端链路**：pecker-agent 收到 `ui_text` → 原样 `POST /external/data/uiText`（不匹配、不打 flag）→ 后端比对 `dim_ui_keyword`。
- **已知盲区**：系统权限弹窗 / 其它进程窗口（纯进程内采集看不到）；JS 关闭或跨域 iframe 的 WebView 取不全。

---

## 传感器类型编号映射

| 编号 | 常量名 | 说明 |
|------|--------|------|
| 1 | ACCELEROMETER | 加速度计 |
| 2 | MAGNETIC_FIELD | 磁力计 |
| 3 | ORIENTATION | 方向传感器（已废弃） |
| 4 | GYROSCOPE | 陀螺仪 |
| 5 | LIGHT | 光线传感器 |
| 6 | PRESSURE | 气压计 |
| 7 | TEMPERATURE | 温度传感器（已废弃） |
| 8 | PROXIMITY | 距离传感器 |
| 9 | GRAVITY | 重力传感器 |
| 10 | LINEAR_ACCELERATION | 线性加速度 |
| 11 | ROTATION_VECTOR | 旋转矢量 |
| 12 | RELATIVE_HUMIDITY | 相对湿度 |
| 13 | AMBIENT_TEMPERATURE | 环境温度 |
| 14 | MAGNETIC_FIELD_UNCALIBRATED | 未校准磁力计 |
| 15 | GAME_ROTATION_VECTOR | 游戏旋转矢量 |
| 16 | GYROSCOPE_UNCALIBRATED | 未校准陀螺仪 |
| 17 | SIGNIFICANT_MOTION | 重大运动 |
| 18 | STEP_DETECTOR | 步伐检测 |
| 19 | STEP_COUNTER | 步数计数 |
| 20 | GEOMAGNETIC_ROTATION_VECTOR | 地磁旋转矢量 |
| 21 | HEART_RATE | 心率 |
| 28 | POSE_6DOF | 6 自由度姿态 |
| 29 | STATIONARY_DETECT | 静止检测 |
| 30 | MOTION_DETECT | 运动检测 |
| 31 | HEART_BEAT | 心跳 |
| 34 | LOW_LATENCY_OFFBODY_DETECT | 低延迟离体检测 |
| 35 | ACCELEROMETER_UNCALIBRATED | 未校准加速度计 |
| 36 | HINGE_ANGLE | 折叠屏铰链角度 |
