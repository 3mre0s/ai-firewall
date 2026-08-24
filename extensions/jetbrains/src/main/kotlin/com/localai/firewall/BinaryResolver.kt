package com.localai.firewall

import java.io.File

internal object BinaryResolver {
    fun resolve(
        environment: Map<String, String>,
        osName: String,
        home: String,
        exists: (File) -> Boolean = File::exists,
    ): File {
        environment["AI_FIREWALL_BINARY"]
            ?.takeIf { it.isNotBlank() }
            ?.let { return File(expandHome(it, home)) }

        val normalizedOS = osName.lowercase()
        val isWindows = normalizedOS.startsWith("windows")
        val isMac = normalizedOS.startsWith("mac") || normalizedOS.contains("darwin")
        val binaryName = if (isWindows) "ai-firewall.exe" else "ai-firewall"
        val candidates = mutableListOf<File>()

        when {
            isWindows -> {
                val localAppData = environment["LOCALAPPDATA"]
                    ?: home.takeIf { it.isNotEmpty() }?.let { "$it\\AppData\\Local" }
                localAppData?.let {
                    candidates += File("$it\\local-ai-firewall", binaryName)
                    candidates += File("$it\\Programs\\local-ai-firewall", binaryName)
                }
            }
            isMac -> {
                if (home.isNotEmpty()) {
                    candidates += File("$home/Library/Application Support/local-ai-firewall", binaryName)
                    candidates += File("$home/.local/bin", binaryName)
                }
                candidates += File("/opt/homebrew/bin", binaryName)
                candidates += File("/usr/local/bin", binaryName)
            }
            else -> {
                if (home.isNotEmpty()) candidates += File("$home/.local/bin", binaryName)
                candidates += File("/usr/local/bin", binaryName)
                candidates += File("/usr/bin", binaryName)
            }
        }

        val separator = if (isWindows) ";" else ":"
        environment["PATH"].orEmpty().split(separator).filter { it.isNotBlank() }.forEach {
            candidates += File(it, binaryName)
        }

        return candidates.firstOrNull(exists)
            ?: candidates.firstOrNull()
            ?: File(binaryName)
    }

    private fun expandHome(value: String, home: String): String {
        if ((value.startsWith("~/") || value.startsWith("~\\")) && home.isNotEmpty()) {
            return home + value.substring(1)
        }
        return value
    }
}
