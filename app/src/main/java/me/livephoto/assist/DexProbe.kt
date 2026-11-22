package me.livephoto.assist

import java.io.InputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipFile

/**
 * 运行时 dex 结构探测：不依赖混淆类名，按方法签名特征定位 remux worker / 实况包装类 / 聊天查看门控。
 *
 * 内存策略：不再把整个 classes.dex（可达数百 MB）readBytes 进内存，只读
 * 「头 + 各 id 表 + 字符串数据区」——字符串数据排在 data 区最前部，从文件头读到
 * 「最远字符串偏移 + 余量」即可覆盖解析所需全部字节；三个探测合并成一次扫描，
 * 结果进程内缓存：启动只扫一遍，发送路径不再重复读 APK。
 *
 * 特征（8.0.77 / Play 8.0.72 / 8.0.78 三版静态验证）：
 *  - remux worker：同一个类同时声明
 *      聊天  (String,String,String,..,Continuation)->Object   （Vi / mh / dj）
 *      SNS   (RecordConfigProvider,Continuation)->Object       （Ui / vh / cj）
 *  - remux 结果类：worker 同 dex 内的 (ZI) 构造器类，同名 e 优先（re0.e / ad0.e / nf0.e）
 *
 * 只读 ZipFile + dex 方法表，不加载类。
 */
internal object DexProbe {

    data class Remux(val worker: String, val chat: String, val sns: String, val result: String)

    private const val CONT = "Lkotlin/coroutines/Continuation;"
    private const val PROVIDER = "Lcom/tencent/mm/plugin/recordvideo/jumper/RecordConfigProvider;"

    /** 字符串数据读取余量：覆盖最后一个字符串的内容尾巴（方法/类型名远小于 64KB） */
    private const val STR_MARGIN = 64 * 1024

    /** 进程内一次性扫描缓存：同一 APK 只解压一遍，三个探测共享同一次读取 */
    @Volatile private var scannedPath: String? = null
    @Volatile private var cachedRemux: Remux? = null
    @Volatile private var cachedWrapper: String? = null
    @Volatile private var cachedGate: String? = null

    private fun scanOnce(apkPath: String) {
        if (scannedPath == apkPath) return
        var remux: Remux? = null
        var wrapper: String? = null
        var gate: String? = null
        runCatching {
            ZipFile(apkPath).use { zip ->
                for (e in zip.entries()) {
                    val n = e.name
                    if (!n.startsWith("classes") || !n.endsWith(".dex")) continue
                    val bytes = runCatching { readDexTables(zip, e) }.getOrNull() ?: continue
                    if (remux == null) remux = runCatching { findInDex(bytes) }.getOrNull()
                    if (wrapper == null) wrapper = runCatching { findWrapperInDex(bytes) }.getOrNull()
                    if (gate == null) gate = runCatching { findViewGateInDex(bytes) }.getOrNull()
                    if (remux != null && wrapper != null && gate != null) break
                }
            }
        }
        cachedRemux = remux
        cachedWrapper = wrapper
        cachedGate = gate
        scannedPath = apkPath
    }

    fun findRemux(apkPath: String): Remux? {
        scanOnce(apkPath)
        return cachedRemux
    }

    /**
     * 结构探测实况包装类：field_ids 表中「类型为 LivePhotoCore 的静态字段」的宿主类。
     * 8.0.77=wp.b / Play 8.0.72=fq.b / 8.0.78=wp.b。
     */
    fun findWrapper(apkPath: String): String? {
        scanOnce(apkPath)
        return cachedWrapper
    }

    /**
     * 结构探测聊天查看门控：同类同时声明 `a()Z`（总开关）+ `b(e9)msg -> Z`（单条消息）。
     * 3141=lo5.f / 3180=mq5.f（类名漂移，结构稳定）。返回 dotted 类名，找不到返回 null。
     */
    fun findViewGate(apkPath: String): String? {
        scanOnce(apkPath)
        return cachedGate
    }

    // ---------- dex 表区读取 ----------

    /**
     * 只读一个 dex 的「头 + id 表 + 字符串数据区」。
     * 两遍流式：第一遍读 header + string_ids 算出最远字符串偏移，第二遍按需读一次。
     */
    private fun readDexTables(zip: ZipFile, e: ZipEntry): ByteArray {
        val entrySize = e.size
        var needed: Long
        zip.getInputStream(e).use { ins ->
            val header = ByteArray(0x70)
            readFully(ins, header)
            val r = Reader(header)
            val strSize = r.u4(0x38)
            val strOff = r.u4(0x3c).toLong()
            if (strSize <= 0 || strSize > 5_000_000) {
                throw IllegalArgumentException("bad dex string table size=$strSize")
            }
            skipFully(ins, strOff - 0x70)
            val offs = ByteArray(strSize * 4)
            readFully(ins, offs)
            val r2 = Reader(offs)
            var maxStr = 0
            for (k in 0 until strSize) {
                val off = r2.u4(k * 4)
                if (off > maxStr) maxStr = off
            }
            needed = minOf(entrySize, maxStr.toLong() + STR_MARGIN)
            if (needed <= 0) needed = entrySize
        }
        zip.getInputStream(e).use { ins ->
            val buf = ByteArray(needed.toInt())
            readFully(ins, buf)
            return buf
        }
    }

    // ---------- 最小 dex 解析：string/type/proto/method 四张表 ----------

    private class Reader(val b: ByteArray) {
        fun u4(p: Int): Int =
            (b[p].toInt() and 0xff) or ((b[p + 1].toInt() and 0xff) shl 8) or
                ((b[p + 2].toInt() and 0xff) shl 16) or ((b[p + 3].toInt() and 0xff) shl 24)
        fun u2(p: Int): Int = (b[p].toInt() and 0xff) or ((b[p + 1].toInt() and 0xff) shl 8)
        fun uleb(p0: Int): Pair<Int, Int> {
            var p = p0; var res = 0; var sh = 0
            while (true) {
                val x = b[p].toInt() and 0xff; p++
                res = res or ((x and 0x7f) shl sh)
                if (x and 0x80 == 0) break
                sh += 7
            }
            return res to p
        }
        fun mutf8(idx: Int, strData: IntArray): String {
            val (len, s0) = uleb(strData[idx])
            val sb = StringBuilder(len)
            var p = s0
            repeat(len) {
                val x = b[p].toInt() and 0xff; p++
                when {
                    x < 0x80 -> if (x != 0) sb.append(x.toChar())
                    x and 0xe0 == 0xc0 -> { val y = b[p].toInt() and 0xff; p++; sb.append(((x and 0x1f) shl 6 or (y and 0x3f)).toChar()) }
                    else -> { val y = b[p].toInt() and 0xff; p++; val z = b[p].toInt() and 0xff; p++; sb.append(((x and 0x0f) shl 12 or (y and 0x3f) shl 6 or (z and 0x3f)).toChar()) }
                }
            }
            return sb.toString()
        }
    }

    /** 在单个 dex 中找同时具备聊天+SNS 签名的类；找不到返回 null */
    internal fun findInDex(b: ByteArray): Remux? {
        if (b.size < 0x70) return null
        val r = Reader(b)
        val strSize = r.u4(0x38); val strOff = r.u4(0x3c)
        val typeSize = r.u4(0x40); val typeOff = r.u4(0x44)
        val protoSize = r.u4(0x48); val protoOff = r.u4(0x4c)
        val methodSize = r.u4(0x58); val methodOff = r.u4(0x5c)
        if (strSize <= 0 || strSize > 5_000_000 || typeSize > 1_000_000 || protoSize > 1_000_000 || methodSize > 5_000_000) return null
        val strData = IntArray(strSize) { k -> r.u4(strOff + 4 * k) }
        val types = Array(typeSize) { k -> r.mutf8(r.u4(typeOff + 4 * k), strData) }
        val protoParams = Array(protoSize) { k ->
            val listOff = r.u4(protoOff + 12 * k + 8)
            if (listOff == 0) emptyList()
            else List(r.u4(listOff)) { j -> types[r.u2(listOff + 4 + 2 * j)] }
        }
        val protoRet = Array(protoSize) { k -> types[r.u4(protoOff + 12 * k + 4)] }

        // 类 -> (聊天方法名, SNS 方法名, 聊天签名第 4 参类型)
        data class Sig(var chat: String? = null, var sns: String? = null, var chatArg4: String? = null)
        val sigs = HashMap<String, Sig>()
        for (k in 0 until methodSize) {
            val o = methodOff + 8 * k
            val cls = types.getOrNull(r.u2(o)) ?: continue
            if (!cls.startsWith("L") || !cls.contains('/')) continue
            val pi = r.u2(o + 2)
            val params = protoParams.getOrNull(pi) ?: continue
            val ret = protoRet.getOrNull(pi) ?: continue
            if (ret != "Ljava/lang/Object;") continue
            val name = r.mutf8(r.u4(o + 4), strData)
            val s = sigs.getOrPut(cls) { Sig() }
            if (params.size >= 4 && params[0] == "Ljava/lang/String;" && params[1] == "Ljava/lang/String;" &&
                params[2] == "Ljava/lang/String;" && params.last() == CONT
            ) { s.chat = name; s.chatArg4 = params[3] }
            if (params.size == 2 && params[0] == PROVIDER && params[1] == CONT) s.sns = name
        }
        val hit = sigs.entries.firstOrNull { it.value.chat != null && it.value.sns != null } ?: return null
        val (cls, s) = hit
        // 结果类由 worker 在同一 dex 内 new-instance 构造（np4.b0.mh→ad0/e、yt4.b0.Vi→re0/e、ox4.b0.dj→nf0/e），
        // 故只需在本 dex 内找 (ZI) 构造器类；同 dex 可能不止一个，同名 e 优先
        val zi = ArrayList<String>()
        for (k in 0 until methodSize) {
            val o = methodOff + 8 * k
            if (r.mutf8(r.u4(o + 4), strData) != "<init>") continue
            val pp = protoParams.getOrNull(r.u2(o + 2)) ?: continue
            if (pp.size == 2 && pp[0] == "Z" && pp[1] == "I") types.getOrNull(r.u2(o))?.let { zi.add(it) }
        }
        val result = (zi.firstOrNull { it.endsWith("/e;") } ?: zi.firstOrNull() ?: "").drop(1).dropLast(1).replace('/', '.')
        return Remux(cls.drop(1).dropLast(1).replace('/', '.'), s.chat!!, s.sns!!, result)
    }

    private const val MSG = "Lcom/tencent/mm/storage/e9;"

    /** 在单个 dex 中找「a()Z + b(e9)Z 同类」= 聊天查看门控（3141=lo5.f / 3180=mq5.f） */
    internal fun findViewGateInDex(b: ByteArray): String? {
        if (b.size < 0x70) return null
        val r = Reader(b)
        val strSize = r.u4(0x38); val strOff = r.u4(0x3c)
        val typeSize = r.u4(0x40); val typeOff = r.u4(0x44)
        val protoSize = r.u4(0x48); val protoOff = r.u4(0x4c)
        val methodSize = r.u4(0x58); val methodOff = r.u4(0x5c)
        if (strSize <= 0 || strSize > 5_000_000 || typeSize > 1_000_000 || protoSize > 1_000_000 || methodSize > 5_000_000) return null
        val strData = IntArray(strSize) { k -> r.u4(strOff + 4 * k) }
        val types = Array(typeSize) { k -> r.mutf8(r.u4(typeOff + 4 * k), strData) }
        val protoParams = Array(protoSize) { k ->
            val listOff = r.u4(protoOff + 12 * k + 8)
            if (listOff == 0) emptyList()
            else List(r.u4(listOff)) { j -> types[r.u2(listOff + 4 + 2 * j)] }
        }
        val protoRet = Array(protoSize) { k -> types[r.u4(protoOff + 12 * k + 4)] }
        val hasA = HashSet<String>(); val hasB = HashSet<String>()
        for (k in 0 until methodSize) {
            val o = methodOff + 8 * k
            val cls = types.getOrNull(r.u2(o)) ?: continue
            if (!cls.startsWith("L") || !cls.contains('/')) continue
            val pi = r.u2(o + 2)
            val params = protoParams.getOrNull(pi) ?: continue
            if (protoRet.getOrNull(pi) != "Z") continue
            val name = r.mutf8(r.u4(o + 4), strData)
            if (name == "a" && params.isEmpty()) hasA.add(cls)
            if (name == "b" && params.size == 1 && params[0] == MSG) hasB.add(cls)
        }
        // 短名混淆类优先（门控都是两段短名），都不是则任取交集
        val hit = hasA.intersect(hasB)
        val pick = hit.firstOrNull { it.count { c -> c == '/' } == 1 && it.length < 10 }
            ?: hit.firstOrNull() ?: return null
        return pick.drop(1).dropLast(1).replace('/', '.')
    }

    /** 在单个 dex 中找「持有 LivePhotoCore 类型字段的类」（字段静态与否在运行时校验） */
    internal fun findWrapperInDex(b: ByteArray): String? {
        if (b.size < 0x70) return null
        val r = Reader(b)
        val strSize = r.u4(0x38); val strOff = r.u4(0x3c)
        val typeSize = r.u4(0x40); val typeOff = r.u4(0x44)
        val fieldSize = r.u4(0x50); val fieldOff = r.u4(0x54)
        if (strSize <= 0 || strSize > 5_000_000 || typeSize > 1_000_000 || fieldSize > 3_000_000) return null
        val strData = IntArray(strSize) { k -> r.u4(strOff + 4 * k) }
        val types = Array(typeSize) { k -> r.mutf8(r.u4(typeOff + 4 * k), strData) }
        for (k in 0 until fieldSize) {
            val o = fieldOff + 8 * k
            val owner = types.getOrNull(r.u2(o)) ?: continue
            if (types.getOrNull(r.u2(o + 2)) == "Lcom/motion/core/LivePhotoCore;" && owner.startsWith("L")) {
                return owner.drop(1).dropLast(1).replace('/', '.')
            }
        }
        return null
    }
}

// ---------- 流式读工具（兼容 minSdk 26，不用 Java 9+ 的 readNBytes/skipNBytes） ----------

private fun readFully(ins: InputStream, buf: ByteArray) {
    var got = 0
    while (got < buf.size) {
        val n = ins.read(buf, got, buf.size - got)
        if (n < 0) throw java.io.EOFException("unexpected end of dex stream")
        got += n
    }
}

private fun skipFully(ins: InputStream, n: Long) {
    var left = n
    while (left > 0) {
        val k = ins.skip(left)
        if (k > 0) {
            left -= k
            continue
        }
        if (ins.read() < 0) throw java.io.EOFException("unexpected end of dex stream")
        left -= 1
    }
}
