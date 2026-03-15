package com.juanma0511.rootdetector.detector

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.juanma0511.rootdetector.model.DetectionCategory
import com.juanma0511.rootdetector.model.DetectionItem
import com.juanma0511.rootdetector.model.Severity
import java.io.File

class RootDetector(private val context: Context) {

    private val suPaths = listOf(
        "/sbin/su", "/system/bin/su", "/system/xbin/su",
        "/system/xbin/daemonsu", "/system/bin/.ext/.su",
        "/system/usr/we-need-root/su-backup", "/su/bin/su",
        "/data/local/su", "/data/local/bin/su", "/data/local/xbin/su",
        "/system/sd/xbin/su", "/system/bin/failsafe/su",
        "/data/adb/su", "/system/app/Superuser.apk",
        "/system/etc/init.d/99SuperSUDaemon", "/system/xbin/sugote",
        "/cache/recovery/su"
    )

    private val rootPackages = listOf(
        "com.noshufou.android.su", "com.noshufou.android.su.elite",
        "eu.chainfire.supersu", "eu.chainfire.supersu.pro",
        "com.koushikdutta.superuser", "com.thirdparty.superuser",
        "com.yellowes.su", "com.kingouser.com",
        "com.kingroot.kinguser", "com.kingo.root",
        "com.smedialink.oneclickroot", "com.alephzain.framaroot",
        "com.jrummy.root.browserfree", "com.jrummy.roots.browserfree",
        
        "com.topjohnwu.magisk",
        "io.github.huskydg.magisk",      
        "io.github.vvb2060.magisk",
        "io.github.a13e300.magisk",      
        "io.github.1q23lyc45.magisk",
        
        "me.weishu.kernelsu",
        "com.rifsxd.ksunext",            
        "com.sukisu.ultra",              
        
        "me.bmax.apatch",
        "me.yuki.folk",
        
        "org.lsposed.manager", "org.lsposed.lspatch",
        "de.robv.android.xposed.installer",
        "me.weishu.exp",                 
        "com.solohsu.android.edxp.manager",
        
        "com.fox2code.mmm", "com.fox2code.mmm.debug", "com.fox2code.mmm.fdroid",
        
        "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
        "com.chrisbjohnson.hiddenroot",
        
        "stericson.busybox", "stericson.busybox.donate",
        
        "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch",
        "com.ramdroid.appquarantine",
        "com.android.vending.billing.InAppBillingService.COIN",
        "com.android.vending.billing.InAppBillingService.LUCK"
    )

    private val patchedApps = listOf(
        "app.revanced.android.youtube", "app.revanced.android.youtube.music",
        "com.mgoogle.android.gms", "app.revanced.manager.flutter", "app.revanced.manager",
        "app.rvx.android.youtube", "app.rvx.android.youtube.music",
        "com.coderstory.toolkit",

        "com.catsoft.hmafree",
        "com.catsoft.hma",
        "me.hsc.hma",
        "app.hma.free",
        "app.hma",
        "com.tsng.hidemyapplist",
        "org.frknkrc44.hma_oss",

        "org.lsposed.manager",
        "org.lsposed.lspatch",
        "io.github.lsposed.manager",
        "com.lsposed.manager",
        "de.robv.android.xposed.installer",
        "com.solohsu.android.edxp.manager",
        "org.meowcat.edxposed.manager",
        "me.weishu.exp",

        "moe.shizuku.privileged.api",
        "com.speedsoftware.rootexplorer",
        "com.estrongs.android.pop"
    )

    private val magiskPaths = listOf(
        "/sbin/.magisk", "/data/adb/magisk", "/data/adb/magisk.img",
        "/data/adb/magisk.db", "/data/adb/modules", "/sbin/.core/mirror",
        "/cache/.disable_magisk", "/system/addon.d/99-magisk.sh",
        "/data/adb/ksu", "/data/adb/ksud",
        "/data/adb/ap", "/data/adb/apd",
        "/dev/.magisk.unblock", "/dev/magisk_merge"
    )

    private val dangerousBinaries = listOf("su", "busybox", "magisk", "magisk64", "resetprop", "ksud", "apd")
    private val binaryPaths = listOf(
        "/sbin/", "/system/bin/", "/system/xbin/",
        "/data/local/xbin/", "/data/local/bin/",
        "/su/bin/", "/vendor/bin/"
    )

    fun runAllChecks(progressCallback: (Int) -> Unit = {}): List<DetectionItem> {
        val checks: List<() -> List<DetectionItem>> = listOf(
            ::checkSuBinaries,
            ::checkRootPackages,
            ::checkPatchedApps,
            ::checkBuildTags,
            ::checkDangerousProps,
            ::checkRootBinaries,
            ::checkWritablePaths,
            ::checkMagiskFiles,
            ::checkFrida,
            ::checkEmulator,
            ::checkMountPoints,
            ::checkTestKeys,
            ::checkNativeLibMaps,
            ::checkMagiskTmpfs,
            ::checkKernelSU,
            ::checkZygiskModules,
            ::checkSuInPath,
            ::checkSELinux,
            ::checkPackageManagerAnomalies,
            ::checkCustomRom
        )
        val items = mutableListOf<DetectionItem>()
        val total = checks.size + 1 

        checks.forEachIndexed { i, check ->
            items += check()
            progressCallback(((i + 1) * 100) / total)
        }

        val native = NativeChecks()
        items += native.run()

        val integrity = IntegrityChecker(context)
        items += integrity.runAllChecks()

        progressCallback(100)
        return items
    }

    private fun checkSuBinaries(): List<DetectionItem> {
        val found = suPaths.filter { File(it).exists() }
        return listOf(det(
            "su_binary", "SU Binary Paths", DetectionCategory.SU_BINARIES, Severity.HIGH,
            "Checks for su binary in 17 known root paths",
            found.isNotEmpty(), found.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkRootPackages(): List<DetectionItem> {
        
        val pm = context.packageManager
        val found = rootPackages.filter { pkg ->
            try {
                pm.getPackageInfo(pkg, PackageManager.GET_META_DATA)
                true
            } catch (_: PackageManager.NameNotFoundException) { false }
        }
        return listOf(det(
            "root_apps", "Root Manager Apps", DetectionCategory.ROOT_APPS, Severity.HIGH,
            "Magisk, KernelSU, APatch, SuperSU, LSPosed and 40+ known packages",
            found.isNotEmpty(), found.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkPatchedApps(): List<DetectionItem> {
        val pm = context.packageManager
        val found = patchedApps.filter { pkg ->
            try { pm.getPackageInfo(pkg, 0); true }
            catch (_: PackageManager.NameNotFoundException) { false }
        }
        return listOf(det(
            "patched_apps", "Patched / Modified Apps", DetectionCategory.ROOT_APPS, Severity.MEDIUM,
            "ReVanced, CorePatch, Play Integrity Fix, TrickyStore, HMA, LSPosed and more",
            found.isNotEmpty(), found.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkBuildTags(): List<DetectionItem> {
        val tags = Build.TAGS ?: ""
        return listOf(det(
            "build_tags", "Build Tags (test-keys)", DetectionCategory.BUILD_TAGS, Severity.MEDIUM,
            "Release builds must use release-keys, not test-keys",
            tags.contains("test-keys"), "Build.TAGS=$tags"
        ))
    }

    private fun checkDangerousProps(): List<DetectionItem> {
        val checks = mapOf(
            "ro.debuggable" to "1", "ro.secure" to "0",
            "ro.build.type" to "userdebug", "service.adb.root" to "1",
            "ro.allow.mock.location" to "1"
        )
        val found = checks.filter { (k, v) -> getProp(k) == v }.map { (k, v) -> "$k=$v" }
        return listOf(det(
            "dangerous_props", "Dangerous System Props", DetectionCategory.SYSTEM_PROPS, Severity.HIGH,
            "ro.debuggable, ro.secure, ro.build.type, adb.root, mock.location",
            found.isNotEmpty(), found.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkRootBinaries(): List<DetectionItem> {
        val found = dangerousBinaries.flatMap { bin ->
            binaryPaths.mapNotNull { path ->
                File("$path$bin").takeIf { it.exists() }?.absolutePath
            }
        }
        return listOf(det(
            "root_binaries", "Root Binaries", DetectionCategory.BUSYBOX, Severity.MEDIUM,
            "Searches for su, busybox, magisk, ksud in common paths",
            found.isNotEmpty(), found.take(5).joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkWritablePaths(): List<DetectionItem> {
        val writable = listOf("/system", "/system/bin", "/system/xbin", "/vendor/bin")
            .filter { try { File(it).canWrite() } catch (_: Exception) { false } }
        return listOf(det(
            "rw_paths", "Writable System Paths", DetectionCategory.WRITABLE_PATHS, Severity.HIGH,
            "These paths should ALWAYS be read-only on a stock device",
            writable.isNotEmpty(), writable.joinToString().ifEmpty { null }
        ))
    }

    private fun checkMagiskFiles(): List<DetectionItem> {
        val found = magiskPaths.filter { File(it).exists() }
        return listOf(det(
            "magisk_files", "Magisk / KSU / APatch Files", DetectionCategory.MAGISK, Severity.HIGH,
            "Checks /data/adb for Magisk, KernelSU and APatch artifacts",
            found.isNotEmpty(), found.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkFrida(): List<DetectionItem> {
        val proc = isProcessRunning("frida-server")
        val port = try {
            val s = java.net.Socket()
            s.connect(java.net.InetSocketAddress("127.0.0.1", 27042), 150); s.close(); true
        } catch (_: Exception) { false }
        return listOf(det(
            "frida", "Frida Instrumentation", DetectionCategory.FRIDA, Severity.HIGH,
            "frida-server process or port 27042",
            proc || port,
            when { proc && port -> "frida-server + port 27042"; proc -> "frida-server process"; port -> "port 27042"; else -> null }
        ))
    }

    private fun checkEmulator(): List<DetectionItem> {
        val indicators = mutableListOf<String>()
        val fp = Build.FINGERPRINT ?: ""
        
        if (fp.startsWith("generic") || fp.contains(":generic/")) indicators += "FINGERPRINT starts with generic"
        if (Build.HARDWARE == "goldfish" || Build.HARDWARE == "ranchu") indicators += "HARDWARE=${Build.HARDWARE}"
        if (Build.MANUFACTURER.equals("Genymotion", ignoreCase = true)) indicators += "MANUFACTURER=Genymotion"
        val emuProducts = setOf("sdk_gphone_x86", "sdk_gphone64_x86_64", "sdk_x86", "google_sdk", "vbox86p", "generic_x86")
        if (Build.PRODUCT in emuProducts) indicators += "PRODUCT=${Build.PRODUCT}"
        return listOf(det(
            "emulator", "Emulator / Virtual Device", DetectionCategory.EMULATOR, Severity.MEDIUM,
            "Exact emulator hardware/product/fingerprint signatures",
            indicators.isNotEmpty(), indicators.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkMountPoints(): List<DetectionItem> {
        val suspicious = mutableListOf<String>()
        try {
            File("/proc/mounts").forEachLine { line ->
                val p = line.split(" "); if (p.size < 4) return@forEachLine
                val dev = p[0]; val mp = p[1]; val opts = p[3]
                val isBlock = dev.startsWith("/dev/block/") || dev.startsWith("dm-")
                
                val isSystem = mp == "/system" || mp == "/vendor" || mp == "/system_root"
                val isRw = opts.split(",").any { it == "rw" }
                if (isBlock && isSystem && isRw) suspicious += "$mp [$dev]"
            }
        } catch (_: Exception) {}
        return listOf(det(
            "mount_rw", "RW System Mount Points", DetectionCategory.MOUNT_POINTS, Severity.HIGH,
            "/proc/mounts: block-backed /system or /vendor mounted rw",
            suspicious.isNotEmpty(), suspicious.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkTestKeys(): List<DetectionItem> {
        val fp = Build.FINGERPRINT ?: ""
        val detected = fp.contains("test-keys") || fp.contains("dev-keys")
        return listOf(det(
            "test_keys", "Test/Dev Keys in Fingerprint", DetectionCategory.BUILD_TAGS, Severity.MEDIUM,
            "Build.FINGERPRINT should not contain test-keys or dev-keys",
            detected, if (detected) fp else null
        ))
    }

    private fun checkNativeLibMaps(): List<DetectionItem> {
        val found = mutableSetOf<String>()
        val systemPaths = listOf("/system/", "/apex/", "/vendor/", "/product/", "/odm/")
        val keywords = listOf("magisk", "zygisk", "riru", "xposed", "frida", "lspatch", "dobby", "substrate")
        try {
            File("/proc/self/maps").forEachLine { line ->
                val lower = line.lowercase()
                keywords.forEach { kw ->
                    if (lower.contains(kw)) {
                        
                        if (systemPaths.none { line.contains(it) }) {
                            found += "$kw → ${line.trim().take(80)}"
                        }
                    }
                }
            }
        } catch (_: Exception) {}
        return listOf(det(
            "native_lib_maps", "Injected Native Libraries", DetectionCategory.MAGISK, Severity.HIGH,
            "/proc/self/maps: Magisk/Zygisk/Xposed/Frida outside system paths",
            found.isNotEmpty(), found.take(4).joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkMagiskTmpfs(): List<DetectionItem> {
        var tmpfsOnSbin = false; var debugRamdisk = false; val devMagisk = File("/dev/magisk").exists()
        try {
            File("/proc/mounts").forEachLine { line ->
                val p = line.split(" "); if (p.size < 3) return@forEachLine
                if (p[2] == "tmpfs" && p[1] == "/sbin") tmpfsOnSbin = true
                if (p[1] == "/debug_ramdisk") debugRamdisk = true
            }
        } catch (_: Exception) {}
        val detected = tmpfsOnSbin || debugRamdisk || devMagisk
        return listOf(det(
            "magisk_tmpfs", "Magisk tmpfs / debug_ramdisk", DetectionCategory.MAGISK, Severity.HIGH,
            "tmpfs on /sbin (old Magisk) or /debug_ramdisk mount (new Magisk)",
            detected, buildString {
                if (tmpfsOnSbin)  appendLine("tmpfs on /sbin")
                if (debugRamdisk) appendLine("/debug_ramdisk present")
                if (devMagisk)    appendLine("/dev/magisk exists")
            }.trim().ifEmpty { null }
        ))
    }

    private fun checkKernelSU(): List<DetectionItem> {
        val evidence = mutableListOf<String>()

        val ksuProps = listOf(
            "ro.boot.kernelsu.version",
            "sys.kernelsu.version",
            "ro.kernelsu.version",
            "ro.boot.ksu.version",
            
            "ro.ksunext.version",
            "ro.boot.ksunext.version"
        )
        ksuProps.forEach { prop ->
            val v = getProp(prop)
            if (v.isNotEmpty()) evidence += "prop $prop=$v"
        }

        val ksuPkgs = listOf(
            "me.weishu.kernelsu",
            "com.rifsxd.ksunext",
            "com.sukisu.ultra"
        )
        val pm = context.packageManager
        ksuPkgs.forEach { pkg ->
            listOf(0, PackageManager.GET_META_DATA, PackageManager.MATCH_UNINSTALLED_PACKAGES).forEach { flags ->
                try {
                    pm.getPackageInfo(pkg, flags)
                    evidence += "package $pkg"
                    return@forEach
                } catch (_: PackageManager.NameNotFoundException) {}
            }
        }

        try {
            val initMaps = File("/proc/1/maps").readLines()
            if (initMaps.any { it.contains("ksu", ignoreCase = true) ||
                               it.contains("kernelsu", ignoreCase = true) }) {
                evidence += "/proc/1/maps contains ksu"
            }
        } catch (_: Exception) {}

        try {
            val p = Runtime.getRuntime().exec("getprop")
            val allProps = p.inputStream.bufferedReader().readText()
            p.waitFor()
            if (allProps.contains("kernelsu", ignoreCase = true) ||
                allProps.contains("ksunext", ignoreCase = true)) {
                
                if (evidence.none { it.startsWith("prop") }) {
                    evidence += "getprop output contains 'kernelsu'"
                }
            }
        } catch (_: Exception) {}

        if (File("/dev/ksud").exists()) evidence += "/dev/ksud exists"

        return listOf(det(
            "kernelsu", "KernelSU / KSU Next", DetectionCategory.MAGISK, Severity.HIGH,
            "Props, manager package, /dev/ksud, /proc/1/maps — multiple bypass-resistant techniques",
            evidence.isNotEmpty(), evidence.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkZygiskModules(): List<DetectionItem> {
        val modules = mutableListOf<String>()
        listOf("/data/adb/modules", "/data/adb/riru/modules").forEach { dir ->
            java.io.File(dir).takeIf { it.isDirectory }?.listFiles()?.forEach { modules += it.name }
        }

        val knownDangerous = mapOf(

            "playintegrityfix"          to "Play Integrity Fix (chiteroman)",
            "PlayIntegrityFix"          to "Play Integrity Fix (chiteroman)",
            "pif"                       to "Play Integrity Fix (short name)",

            "tricky_store"              to "TrickyStore",
            "trickystore"               to "TrickyStore",
            "TrickyStore"               to "TrickyStore",

            "HideMyApplist"             to "Hide My App List",
            "hidemyapplist"             to "Hide My App List",
            "hma"                       to "HMA (Hide Mock Android)",

            "lsposed"                   to "LSPosed Framework",
            "LSPosed"                   to "LSPosed Framework",
            "zygisk_lsposed"            to "LSPosed (Zygisk)",
            "riru_lsposed"              to "LSPosed (Riru)",

            "shamiko"                   to "Shamiko (Magisk hider)",
            "Shamiko"                   to "Shamiko (Magisk hider)",

            "zygisk-assistant"          to "Zygisk Assistant",
            "zygisksu"                  to "ZygiskSU",

            "susfs"                     to "SUSFS (filesystem spoofing)",
            "ksu_susfs"                 to "KernelSU SUSFS",

            "safetynet-fix"             to "SafetyNet Fix",
            "MagiskHidePropsConf"       to "MagiskHide Props Config",
            "magical_overlayfs"         to "Magical OverlayFS",

            "riru"                      to "Riru Framework",
            "riru-core"                 to "Riru Core",
        )

        val detectedModules = mutableListOf<String>()
        val genericModules = mutableListOf<String>()

        modules.forEach { name ->
            val label = knownDangerous.entries.firstOrNull { (key, _) ->
                name.equals(key, ignoreCase = true) || name.contains(key, ignoreCase = true)
            }?.value
            if (label != null) detectedModules += "$name → $label"
            else genericModules += name
        }

        val allFound = detectedModules + genericModules
        val detail = buildString {
            if (detectedModules.isNotEmpty()) {
                append("Known dangerous:\n")
                detectedModules.forEach { appendLine("  • $it") }
            }
            if (genericModules.isNotEmpty()) {
                append("Other modules:\n")
                genericModules.take(6).forEach { appendLine("  • $it") }
            }
        }.trim()

        return listOf(det(
            "zygisk_modules", "Magisk / KSU Modules Installed",
            DetectionCategory.MAGISK, Severity.HIGH,
            "Scans /data/adb/modules — detects Play Integrity Fix, TrickyStore, LSPosed, Shamiko, SUSFS and more",
            allFound.isNotEmpty(), detail.ifEmpty { null }
        ))
    }

    private fun checkSuInPath(): List<DetectionItem> {
        val found = (System.getenv("PATH") ?: "").split(":")
            .mapNotNull { dir -> File("$dir/su").takeIf { it.exists() }?.absolutePath }
        return listOf(det(
            "su_in_path", "SU in \$PATH", DetectionCategory.SU_BINARIES, Severity.HIGH,
            "Walks \$PATH for su binary",
            found.isNotEmpty(), found.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun checkSELinux(): List<DetectionItem> {
        val permissive = try {
            val p = Runtime.getRuntime().exec("getenforce")
            p.inputStream.bufferedReader().readText().trim().equals("Permissive", ignoreCase = true)
                .also { p.waitFor() }
        } catch (_: Exception) { false }
        val enforceFile = try {
            File("/sys/fs/selinux/enforce").readText().trim() == "0"
        } catch (_: Exception) { false }
        val detected = permissive || enforceFile
        return listOf(det(
            "selinux", "SELinux Permissive", DetectionCategory.SYSTEM_PROPS, Severity.HIGH,
            "Permissive mode is a strong indicator of root — can't be hidden by DenyList",
            detected, if (detected) "SELinux is PERMISSIVE (expected: Enforcing)" else null
        ))
    }

    private fun checkPackageManagerAnomalies(): List<DetectionItem> {
        val anomalies = mutableListOf<String>()
        val pm = context.packageManager

        try {
            @Suppress("DEPRECATION")
            val allPkgs = pm.getInstalledPackages(PackageManager.GET_META_DATA)
            val allNames = allPkgs.map { it.packageName }.toSet()

            val suspects = rootPackages + patchedApps
            suspects.forEach { pkg ->
                if (pkg in allNames) anomalies += pkg
            }
        } catch (_: Exception) {}

        try {
            val intent = android.content.Intent("com.topjohnwu.magisk.MAIN")
            val resolved = pm.queryIntentActivities(intent, 0)
            if (resolved.isNotEmpty()) anomalies += "Magisk MAIN intent resolved"
        } catch (_: Exception) {}

        return listOf(det(
            "pm_anomalies", "Package Manager Check", DetectionCategory.ROOT_APPS, Severity.HIGH,
            "Scans all installed packages and intent queries for root apps bypassing DenyList",
            anomalies.isNotEmpty(), anomalies.joinToString("\n").ifEmpty { null }
        ))
    }

    private fun det(
        id: String, name: String, cat: DetectionCategory, sev: Severity,
        desc: String, detected: Boolean, detail: String?
    ) = DetectionItem(id=id, name=name, description=desc, category=cat, severity=sev,
                      detected=detected, detail=detail)

    private fun getProp(key: String): String = try {
        val p = Runtime.getRuntime().exec("getprop $key")
        val finished = p.waitFor(1, java.util.concurrent.TimeUnit.SECONDS)
        if (!finished) { p.destroyForcibly(); "" }
        else p.inputStream.bufferedReader().readLine()?.trim() ?: ""
    } catch (_: Exception) { "" }

    private fun isProcessRunning(name: String): Boolean = try {
        Runtime.getRuntime().exec("ps -A").inputStream
            .bufferedReader().lineSequence().any { it.contains(name) }
    } catch (_: Exception) { false }

    private fun checkCustomRom(): List<DetectionItem> {
        val indicators = mutableListOf<String>()

        val romProps = mapOf(
            "ro.lineage.version"          to "LineageOS",
            "ro.lineage.build.version"    to "LineageOS",
            "ro.cm.version"               to "CyanogenMod",
            "ro.crdroid.version"          to "crDroid",
            "ro.evolution.version"        to "EvolutionX",
            "ro.arrow.version"            to "ArrowOS",
            "ro.havoc.version"            to "HavocOS",
            "ro.pe.version"               to "PixelExperience",
            "ro.pa.version"               to "ParanoidAndroid",
            "ro.derp.version"             to "DerpFest",
            "ro.elixir.version"           to "ProjectElixir",
            "ro.potato.version"           to "POSP",
            "ro.superior.version"         to "SuperiorOS",
            "ro.spark.version"            to "SparkOS",
            "ro.bliss.version"            to "BlissROMs",
            "ro.phhgsi.android.version"   to "PHH-GSI"
        )

        romProps.forEach { (prop, rom) ->
            val v = getProp(prop)
            if (v.isNotEmpty()) indicators += "$rom ($v)"
        }

        val fp = android.os.Build.FINGERPRINT ?: ""
        val brand = android.os.Build.BRAND ?: ""
        if (fp.contains("lineage", ignoreCase = true)) indicators += "LineageOS in fingerprint"
        if (fp.contains("evolution", ignoreCase = true)) indicators += "EvolutionX in fingerprint"
        if (brand.equals("LineageOS", ignoreCase = true)) indicators += "Brand=LineageOS"

        listOf("/system/etc/lineage-release", "/system/lineage").forEach { path ->
            if (java.io.File(path).exists()) indicators += path
        }

        return listOf(det(
            "custom_rom", "Custom / Third-Party ROM", DetectionCategory.CUSTOM_ROM, Severity.MEDIUM,
            "LineageOS, crDroid, EvolutionX, PixelExperience, ArrowOS and 10+ custom ROMs",
            indicators.isNotEmpty(), indicators.joinToString("\n").ifEmpty { null }
        ))
    }
}
