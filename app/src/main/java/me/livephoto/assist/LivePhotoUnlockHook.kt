package me.livephoto.assist

import android.app.Application
import android.content.Context
import android.content.SharedPreferences
import android.database.Cursor
import android.net.Uri
import android.provider.MediaStore
import android.util.Log
import io.github.libxposed.api.XposedModule
import io.github.libxposed.api.XposedModuleInterface.ModuleLoadedParam
import io.github.libxposed.api.XposedModuleInterface.PackageReadyParam
import java.io.File
import java.io.RandomAccessFile

/**
 * 微信实况照片解锁（libxposed 102，纯 Kotlin）。
 *
 * 核心模型（逆向结论）：
 *   - 所有官方 APK/补丁里的 com.motion.core.LivePhotoCore 都是桩类：
 *     initCore/exportLivePhoto 返回 -1000，isLivePhoto 返回空表，
 *     且判定语义是【返回 0 才算成功】→ 纯 APK 在任何机型上都没有完整实况能力。
 *   - 厂商白名单（小米/OV/荣耀等）只决定是否创建核心实例（wp.b.b），
 *     不提供实现本身；能用的设备必然运行着带真核心的构建。
 *   - 聊天查看门控 nm5/f.a() = RepairerConfig_Chatting_C2C_Live_Preview_V2==1 && wp.b.e
 *
 * 实现要点：
 *   1. hook 注册时机：Instrumentation.callApplicationOnCreate 之后（Tinker 补丁
 *      已挂载），用 app.classLoader 解析类——否则 hook 挂在原版类上全部失效。
 *   2. 桩类接管：
 *        initCore → 0、isSupport → true、getCoreMetaData → ""
 *        isLivePhoto → 真实识别（MediaStore 解析 + 文件尾 ftyp 扫描）
 *        getVideoMetaData → 提取内嵌 MP4 + mvhd 时长，返回微信约定 JSON
 *        exportLivePhoto → 图+视频合成动态 JPEG（保存到相册带 LIVE 标记）
 *   3. 配置写入持久收敛：写后读回校验；MMKV.initialize/mmkvWithID 双钩子对齐
 *      微信生命周期；补丁版 MMKV 需先 initialize（幂等），有重入保护防递归。
 *   4. 补丁自退位：检测到已安装补丁时自动放行原生实现。
 *
 * 风控面：只写微信官方 MMKV 本地配置，hook 只覆盖腾讯无功能的桩类与 MMKV 观察点，
 *   不触碰网络层与消息内容上报。
 */
class LivePhotoUnlockHook : XposedModule() {

    /** 已解析的实况包装类（多版本自适应匹配结果） */
    private var wrapperClass: Class<*>? = null

    /** 真补丁已安装时置 true：所有核心方法 hook 自动放行原生实现（模块退位） */
    @Volatile
    private var nativePatchMode = false

    /** 模块加载时由框架告知的当前进程名（PackageReadyParam 不带 processName，只能从这里取） */
    @Volatile
    private var sProcessName: String? = null

    override fun onModuleLoaded(param: ModuleLoadedParam) {
        sProcessName = param.processName
    }

    override fun onPackageReady(param: PackageReadyParam) {
        if (param.packageName != PKG_WECHAT) return

        if (!isMainProcess()) return

        // ===== 1. 等 Application 创建完成（Tinker 补丁已挂载）后，用最终 classloader 注册全部 hook =====
        try {
            val ins = Class.forName("android.app.Instrumentation", false, param.classLoader)
            val m = ins.getDeclaredMethod(
                "callApplicationOnCreate", Application::class.java
            )
            hook(m)
                .setPriority(PRIORITY_HIGHEST)
                .intercept { chain ->
                    val result = chain.proceed()
                    val app = chain.getArgs()[0] as? Application
                    if (app != null) {
                        try {
                            sAppContext = app.baseContext ?: app.applicationContext
                            registerAllHooks(app.classLoader)
                            scheduleConfigWrites()
                        } catch (t: Throwable) {
                            log(Log.ERROR, TAG, "appOnCreate failed", t)
                        }
                    }
                    result
                }
        } catch (t: Throwable) {
            log(Log.ERROR, TAG, "Instrumentation hook setup failed", t)
        }

        // ===== 2. 每次 Activity onResume 兜底重试 =====
        try {
            val ins = Class.forName("android.app.Instrumentation", false, param.classLoader)
            val m = ins.getDeclaredMethod("callActivityOnResume", android.app.Activity::class.java)
            hook(m)
                .intercept { chain ->
                    val result = chain.proceed()
                    if (!allWritesDone()) {
                        try { attemptConfigWrites() } catch (_: Throwable) {}
                    }
                    result
                }
        } catch (t: Throwable) {
            log(Log.WARN, TAG, "onResume hook setup failed (non-fatal)", t)
        }
    }

    /** 多版本自适应：名单快路径 → dex 结构探测兜底（内含 LivePhotoCore 类型字段的类） */
    private fun findLivePhotoWrapper(loader: ClassLoader): Class<*>? {
        for (name in WRAPPER_CANDIDATES) {
            try {
                val cls = Class.forName(name, false, loader)
                if (findCoreField(cls) != null) return cls
            } catch (_: Throwable) {}
        }
        // 兜底：扫 APK field_ids，找「持有 LivePhotoCore 类型字段的类」
        val probed = runCatching { DexProbe.findWrapper(appApkPath()) }.getOrNull() ?: return null
        return try { Class.forName(probed, false, loader) } catch (_: Throwable) { null }
    }

    /** 找到 LivePhotoCore 类型的字段（类型匹配，不依赖字段名） */
    private fun findCoreField(wrapper: Class<*>): java.lang.reflect.Field? {
        return runCatching { wrapper.getDeclaredField("b") }.getOrNull()?.takeIf { it.type.name == CLS_CORE }
            ?: wrapper.declaredFields.firstOrNull { it.type.name == CLS_CORE }
    }

    /** 在补丁已加载的最终 classloader 上注册所有 hook */
    private fun registerAllHooks(loader: ClassLoader) {
        // ----- 实况包装类 <clinit> 后：e=true + 创建核心实例 b -----
        try {
            val wpb = findLivePhotoWrapper(loader) ?: throw ClassNotFoundException("no wrapper found for candidates $WRAPPER_CANDIDATES")
            wrapperClass = wpb
            hookClassInitializer(wpb)
                .setPriority(PRIORITY_HIGHEST)
                .intercept { chain ->
                    // 桩类 <clinit> 若因缺 native 库等原因抛出，先留下可读日志再原样抛出，
                    // 避免崩溃堆栈全指向本模块，掩盖真实原因
                    val result = try {
                        chain.proceed()
                    } catch (t: Throwable) {
                        log(Log.WARN, TAG, "${wpb.name}.<clinit> threw (not module-caused), rethrowing", t)
                        throw t
                    }
                    if (nativePatchMode) {
                        log(Log.INFO, TAG, "stage-1: native patch active, ${wpb.name} untouched")
                        return@intercept result
                    }
                    val eOk = setStaticBool(wpb, "e", true)
                    val bOk = installCoreInstance(wpb, loader)
                    log(
                        Log.INFO, TAG,
                        "stage-1: ${wpb.name} clinit done, e=$eOk, b-installed=$bOk"
                    )
                    result
                }
            log(Log.INFO, TAG, "stage-1 hook registered on ${wpb.name}")
        } catch (t: Throwable) {
            log(Log.ERROR, TAG, "wrapper hook setup failed (version changed?)", t)
        }

        // ----- LivePhotoCore 桩方法接管 -----
        try {
            val core = Class.forName(CLS_CORE, false, loader)

            hook(core.getDeclaredMethod("initCore", Context::class.java))
                .setPriority(PRIORITY_HIGHEST)
                .intercept { chain ->
                    if (nativePatchMode) { chain.proceed() } else {
                        log(Log.INFO, TAG, "core.initCore(${argsString(chain.getArgs())}) -> 0"); 0
                    }
                }

            hook(core.getDeclaredMethod("isSupport"))
                .setPriority(PRIORITY_HIGHEST)
                .intercept { chain -> if (nativePatchMode) chain.proceed() else true }

            hook(core.getDeclaredMethod("getCoreMetaData"))
                .setPriority(PRIORITY_HIGHEST)
                .intercept { chain ->
                    if (nativePatchMode) chain.proceed() else {
                        log(Log.INFO, TAG, "core.getCoreMetaData() probed -> \"\""); ""
                    }
                }

            hook(core.getDeclaredMethod("getVideoMetaData", Long::class.javaPrimitiveType, String::class.java))
                .setPriority(PRIORITY_HIGHEST)
                .intercept { chain ->
                    if (nativePatchMode) chain.proceed() else {
                        val mediaId = (chain.getArgs()[0] as? Number)?.toLong() ?: -1L
                        val savePath = chain.getArgs()[1] as? String ?: ""
                        log(Log.INFO, TAG, "core.getVideoMetaData(mediaId=$mediaId, savePath=$savePath)")
                        val json = tryExtractVideo(mediaId, savePath)
                        if (json != null) { log(Log.INFO, TAG, "core.getVideoMetaData -> $json"); json }
                        else { log(Log.WARN, TAG, "core.getVideoMetaData -> \"\""); "" }
                    }
                }

            hook(core.getDeclaredMethod("isLivePhoto", List::class.java))
                .setPriority(PRIORITY_HIGHEST)
                .intercept { chain ->
                    if (nativePatchMode) chain.proceed() else {
                        val ids = (chain.getArgs()[0] as? List<Long>) ?: emptyList()
                        val map = detectLivePhotos(ids)
                        log(Log.INFO, TAG, "core.isLivePhoto(${ids.size} ids) -> ${map.count { it.value }} live")
                        map
                    }
                }

            hook(core.getDeclaredMethod("exportLivePhoto", String::class.java))
                .setPriority(PRIORITY_HIGHEST)
                .intercept { chain ->
                    if (nativePatchMode) chain.proceed() else {
                        val json = chain.getArgs()[0] as? String ?: ""
                        val ok = tryExportLivePhoto(json)
                        log(Log.INFO, TAG, "core.exportLivePhoto -> ${if (ok) 0 else -1000}")
                        if (ok) 0 else chain.proceed()
                    }
                }

            log(Log.INFO, TAG, "core hooks registered on $CLS_CORE")
        } catch (t: Throwable) {
            log(Log.ERROR, TAG, "core hook setup failed", t)
        }

        // ----- 包装类 b() 校验放行（放行 ratio error / 格式不兼容等所有校验） -----
        try {
            val wpb = wrapperClass ?: throw IllegalStateException("wrapper class not resolved")
            val bMethod = wpb.getDeclaredMethod(
                "b", Long::class.javaPrimitiveType, String::class.java,
                String::class.java, Long::class.javaPrimitiveType
            )
            hook(bMethod)
                .setPriority(PRIORITY_HIGHEST)
                .intercept { chain ->
                    val result = chain.proceed()
                    if (result != null) {
                        try {
                            val cls = result.javaClass
                            val t0 = cls.getDeclaredField("a").apply { isAccessible = true }.get(result)
                            if (t0 != null) {
                                val t0Cls = t0.javaClass
                                val successField = t0Cls.getDeclaredField("a").apply { isAccessible = true }
                                val origSuccess = successField.getBoolean(t0)
                                successField.setBoolean(t0, true)
                                val errField = t0Cls.getDeclaredField("b").apply { isAccessible = true }
                                val origErr = errField.getInt(t0)
                                if (!origSuccess) {
                                    errField.setInt(t0, 0)
                                }
                                if (!origSuccess) {
                                    val mediaId = (chain.getArgs().firstOrNull() as? Number)?.toLong() ?: -1L
                                    log(Log.INFO, TAG, "wp/b.b forced: origSuccess=false origErr=$origErr -> true id=$mediaId")
                                }
                            }
                        } catch (t: Throwable) {
                            log(Log.WARN, TAG, "wp/b.b force success failed", t)
                        }
                    }
                    result
                }
        } catch (_: Throwable) {}

        // ----- 强制聊天实况查看门控（结构：a()Z 总开关 × b(msg)Z 单条消息；两处缺一不可） -----
        // 3141 真门控 = lo5.f（a()= rj(Preview)==1 && vq.b.e；b(msg)= 伴生文件检查），nm5.f 只是对话框回调类，hook 它无效。
        // 3180 真门控 = mq5.f（同构，类名漂移）。修法三层：Preview 默认值 -> 1（根因，白名单绕过）+
        // 门控 a() -> true（结构扫描定位，不依赖类名）+ b(msg) 失败时放行（伴生文件缺失兜底）。
        // ponytail: 只扫 dex 内 a()Z+b(msg)Z 同构类；若以后门控改签名，加候选再扫。
        try {
            runCatching {
                val cfg = Class.forName("com.tencent.mm.repairer.config.chatting.RepairerConfigC2CLiveImagePreview", false, loader)
                // 无参名 c 即唯一；但强制返回 1 前校验返回类型，返回类型不兼容时跳过，
                // 避免调用点 ClassCastException 直接打崩微信
                val c = cfg.declaredMethods.firstOrNull {
                    it.name == "c" && it.parameterTypes.isEmpty()
                } ?: error("c() not found")
                val rt = c.returnType
                val ok = rt == Int::class.javaPrimitiveType || rt == java.lang.Integer::class.java ||
                    rt == Any::class.java || rt == java.lang.Object::class.java
                if (ok) {
                    hook(c).setPriority(PRIORITY_HIGHEST).intercept { _ -> 1 }
                    log(Log.INFO, TAG, "preview config default forced: ${cfg.simpleName}.c() -> 1")
                } else {
                    log(Log.WARN, TAG, "preview config c() returns $rt, skip force (avoid ClassCastException)")
                }
            }.onFailure { log(Log.WARN, TAG, "preview config hook failed", it) }
            // 门控 a()：先按结构找（a()Z + b(msg)Z 同类），找不到再回退旧名单
            val gate = runCatching { DexProbe.findViewGate(appApkPath())?.let { Class.forName(it, false, loader) } }.getOrNull()
            if (gate != null) {
                runCatching {
                    hook(gate.getDeclaredMethod("a")).setPriority(PRIORITY_HIGHEST).intercept { _ -> true }
                    log(Log.INFO, TAG, "preview gate: ${gate.name}.a() -> true")
                }.onFailure { log(Log.WARN, TAG, "preview gate a() hook failed on ${gate.name}", it) }
                // b(msg)：返回 true=已过期不可播；只把过期放行为未过期（true->false），未过期保持 false 让 K() 继续验 XML
                runCatching {
                    val bmp = gate.declaredMethods.firstOrNull { m ->
                        m.name == "b" && m.parameterTypes.size == 1 &&
                            m.parameterTypes[0].name == "com.tencent.mm.storage.e9" &&
                            m.returnType == Boolean::class.javaPrimitiveType
                    } ?: error("b(msg) not found on ${gate.name}")
                    hook(bmp).setPriority(PRIORITY_HIGHEST).intercept { chain ->
                        val msg = chain.getArgs().firstOrNull()
                        val orig = (chain.proceed() as? Boolean) ?: false
                        val out = if (orig) false else orig
                        // ponytail: 只打 true->false 那条，正常 false 不刷屏。
                        if (orig) {
                            val id = runCatching {
                                msg!!.javaClass.getMethod("getMsgId").invoke(msg)
                            }.getOrNull()
                            log(Log.INFO, TAG, "preview gate: ${gate.name}.b(msgId=$id) $orig->$out")
                        }
                        out
                    }
                    log(Log.INFO, TAG, "preview gate: ${gate.name}.b(msg) expired->false")
                }.onFailure { log(Log.WARN, TAG, "preview gate b(msg) hook skipped", it) }
                // K() 最终判定 iu.l1.b(xml, isSend)：消息 XML 无实况附件即 false。
                // 若门控全放行仍无按钮，说明消息体本身没带实况数据——打一条区分责任。
                runCatching {
                    val l1 = Class.forName("iu.l1", false, loader)
                    val b = l1.declaredMethods.firstOrNull { m ->
                        m.name == "b" && m.parameterTypes.size == 2 &&
                            m.returnType == Boolean::class.javaPrimitiveType
                    } ?: error("iu.l1.b not found")
                    hook(b).setPriority(PRIORITY_HIGHEST).intercept { chain ->
                        val r = (chain.proceed() as? Boolean) ?: false
                        if (!r) log(Log.INFO, TAG, "preview gate: iu.l1.b(xml)->false (msg has no live attach?)")
                        r
                    }
                    log(Log.INFO, TAG, "preview gate: iu.l1.b(xml) traced")
                }.onFailure { log(Log.WARN, TAG, "iu.l1 trace skipped", it) }
                // q1.B 静态总开关：画廊构造时 B = gate.a() 赋值一次；若构造时序早于 hook 就恒 false。
                // 直接置 true，不等构造赋值（ponytail：字段名 B 单字母，混淆后稳定因为是 q1 内唯一 static boolean？否——按类型+static 找，找不到就跳过）。
                runCatching {
                    val q1 = Class.forName("com.tencent.mm.ui.chatting.gallery.q1", false, loader)
                    val f = q1.declaredFields.firstOrNull {
                        java.lang.reflect.Modifier.isStatic(it.modifiers) && it.type == Boolean::class.javaPrimitiveType
                    } ?: error("q1 static boolean not found")
                    f.isAccessible = true
                    f.setBoolean(null, true)
                    log(Log.INFO, TAG, "preview gate: q1.${f.name}=true (static B)")
                }.onFailure { log(Log.WARN, TAG, "q1.B force skipped", it) }
            } else {
                for (gateName in arrayOf("nm5.f", "mq5.f", "lo5.f")) {
                    runCatching {
                        val g = Class.forName(gateName, false, loader)
                        hook(g.getDeclaredMethod("a")).setPriority(PRIORITY_HIGHEST).intercept { _ -> true }
                        log(Log.INFO, TAG, "preview gate: $gateName.a() -> true")
                    }
                }
            }
        } catch (t: Throwable) {
            log(Log.WARN, TAG, "preview gate hook failed", t)
        }

        // ----- 3180 共享设备断言（根因：mq5/bk4/jw3/og3 等 4+ 处由直读 wp.b.e 改为 ss/v.c()，hook 一处全通；旧版无此方法则跳过） -----
        runCatching {
            val v = Class.forName("ss.v", false, loader)
            val c = v.getDeclaredMethod("c")
            val rt = c.returnType
            if (rt == Boolean::class.javaPrimitiveType || rt == java.lang.Boolean::class.java) {
                hook(c).setPriority(PRIORITY_HIGHEST).intercept { _ -> true }
                log(Log.INFO, TAG, "os-support gate: ss.v.c() -> true")
            } else {
                log(Log.WARN, TAG, "os-support gate: ss.v.c() returns ${rt.name}, skip force (avoid ClassCastException)")
            }
        }.onFailure { log(Log.WARN, TAG, "ss.v.c hook skipped (pre-3180?)", it) }

        // ----- 设备 HEVC 硬件编码能力放行（让 Pixel 走硬件编码器，不卡软编） -----
        try {
            val checkerCls = Class.forName("px3.n", false, loader)
            for (m in checkerCls.methods) {
                if (m.name == "c" && m.parameterTypes.size == 1 && m.returnType == Boolean::class.javaPrimitiveType) {
                    hook(m)
                        .setPriority(PRIORITY_HIGHEST)
                        .intercept { _ -> true }
                    break
                }
            }
        } catch (_: Throwable) {}

        // ----- 直通 Remux 转码：跳过软/硬编直接复制目标文件（解决聊天与朋友圈转码卡死/降级/发表失败） -----
        // 结构探测：同类含「三 String 挂起」+「RecordConfigProvider 挂起」= remux worker（三版验证）
        try {
            val probed = DexProbe.findRemux(appApkPath())
            val remuxCls = probed?.let { p ->
                runCatching { Class.forName(p.worker, false, loader) }.getOrNull().also {
                    if (it != null) log(Log.INFO, TAG, "dex-probe remux: ${p.worker}.${p.chat}/${p.sns} -> ${p.result}")
                }
            } ?: throw ClassNotFoundException("no remux class (dex-probe failed)")
            for (m in remuxCls.methods) {
                // 1. 聊天 C2C 实况转码直通（签名特征：3+ 参且前 3 参均为 String；src,dst,thumb）
                if (m.name == probed?.chat || (probed == null && m.parameterTypes.size >= 4 &&
                            m.parameterTypes[0] == String::class.java && m.parameterTypes[1] == String::class.java &&
                            m.parameterTypes[2] == String::class.java && m.name.length <= 2)) {
                    hook(m)
                        .setPriority(PRIORITY_HIGHEST)
                        .intercept { chain ->
                            val args = chain.getArgs()
                            val srcPath = args[0] as? String ?: ""
                            val dstPath = args[1] as? String ?: ""
                            
