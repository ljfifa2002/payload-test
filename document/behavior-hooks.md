# 动态行为监测清单

本文档记录 payload 当前已实现的所有 Hook 点，供日常维护和新增参考。

**维护规则**
- 新增 hook：在 `HookerBridge.java` 添加备份字段 + 回调方法，在 `hooks.cpp` 添加 `hook_one` 调用，并在本文档对应分类下补充一行。
- 修改/删除 hook：同步更新代码和本文档。
- 日志格式统一为：`{"type":"behavior","method":"<method>","data":"<data>","timestamp":<ms>}`，tag = `payload`。

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
| 9 | `android.location.LocationManager.getLastKnownLocation(String)` | `(Ljava/lang/String;)Landroid/location/Location;` | 否 | 经纬度 + provider（provider 嵌入 method 字段） | `LocationManager.getLastKnownLocation[<provider>]` |
| 10 | `android.location.Location.getLatitude()` | `()D` | 否 | 纬度（double） | `Location.getLatitude` |
| 11 | `android.location.Location.getLongitude()` | `()D` | 否 | 经度（double） | `Location.getLongitude` |

---

## 分类三：敏感数据访问

| # | Java API | JNI 签名 | 静态 | 捕获内容 | 日志 method 字段 |
|---|----------|---------|------|---------|-----------------|
| 12 | `android.content.ContentResolver.query(Uri, String[], Bundle, CancellationSignal)` | `(Landroid/net/Uri;[Ljava/lang/String;Landroid/os/Bundle;Landroid/os/CancellationSignal;)Landroid/database/Cursor;` | 否 | 联系人 / 短信 / 通话记录 / 日历 / 媒体库 URI（仅记录含敏感关键词的 URI） | `ContentResolver.query` |
| 13 | `android.hardware.camera2.CameraManager.openCamera(String, StateCallback, Handler)` | `(Ljava/lang/String;Landroid/hardware/camera2/CameraDevice$StateCallback;Landroid/os/Handler;)V` | 否 | 摄像头 ID | `CameraManager.openCamera` |
| 14 | `android.media.MediaRecorder.setAudioSource(int)` | `(I)V` | 否 | 音频来源编号（1=MIC, 5=CAMCORDER 等） | `MediaRecorder.setAudioSource` |

---

## 分类四：网络请求

| # | Java API | JNI 签名 | 静态 | 捕获内容 | 日志 method 字段 |
|---|----------|---------|------|---------|-----------------|
| 15 | `java.net.URL.openConnection()` | `()Ljava/net/URLConnection;` | 否 | 请求 URL 字符串 | `URL.openConnection` |
| 16 | `okhttp3.OkHttpClient.newCall(Request)` | `(Lokhttp3/Request;)Lokhttp3/Call;` | 否 | OkHttp 请求 URL（App 未打包 OkHttp3 时自动跳过） | `OkHttpClient.newCall` |
| 17 | `libssl.so SSL_write(SSL*, const void*, int)` | native | — | SNI host + 明文长度 + 前128字节预览（文本/hex） | `SSL_write` |
| 18 | `libssl.so SSL_read(SSL*, void*, int)` | native | — | SNI host + 明文长度 + 前128字节预览（文本/hex） | `SSL_read` |

---

## 分类五：传感器

采样率常量：`0`=NORMAL, `1`=UI, `2`=GAME, `3`=FASTEST，或具体微秒数。

| # | Java API | JNI 签名 | 静态 | 捕获内容 | 日志 method 字段 |
|---|----------|---------|------|---------|-----------------|
| 19 | `android.hardware.SensorManager.registerListener(SensorEventListener, Sensor, int)` | `(Landroid/hardware/SensorEventListener;Landroid/hardware/Sensor;I)Z` | 否 | 传感器类型编号 + 类型名 + 硬件名称 + 采样率 | `SensorManager.registerListener` |
| 20 | `android.hardware.SensorManager.registerListener(SensorEventListener, Sensor, int, int)` | `(Landroid/hardware/SensorEventListener;Landroid/hardware/Sensor;II)Z` | 否 | 同上 + 最大延迟（maxLatency） | `SensorManager.registerListener` |
| 21 | `android.hardware.SensorManager.registerListener(SensorEventListener, Sensor, int, Handler)` | `(Landroid/hardware/SensorEventListener;Landroid/hardware/Sensor;ILandroid/os/Handler;)Z` | 否 | 同上 + Handler | `SensorManager.registerListener` |

---

## 分类六：权限申请

| # | Java API | JNI 签名 | 静态 | 捕获内容 | 日志 method 字段 |
|---|----------|---------|------|---------|-----------------|
| 22 | `android.app.Activity.requestPermissions(String[], int)` | `([Ljava/lang/String;I)V` | 否 | 申请的权限列表（逗号分隔） | `Activity.requestPermissions` |
| 23 | `android.app.Activity.checkSelfPermission(String)` | `(Ljava/lang/String;)I` | 否 | 被查询的权限名（仅记录结果为 DENIED 的） | `Activity.checkSelfPermission` |
| 24 | `androidx.core.app.ActivityCompat.requestPermissions(Activity, String[], int)` | `(Landroid/app/Activity;[Ljava/lang/String;I)V` | 是 | 申请的权限列表（App 未打包 androidx 时自动跳过） | `ActivityCompat.requestPermissions` |

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
