package com.localai.firewall

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse

class BinaryResolverTest {
    @Test
    fun `project root is never a binary candidate`() {
        val projectRoot = File("/untrusted/project").absoluteFile
        val seen = mutableListOf<File>()
        BinaryResolver.resolve(
            environment = mapOf("PATH" to "/usr/local/bin:/usr/bin"),
            osName = "Linux",
            home = "/home/test",
            exists = { candidate -> seen += candidate.absoluteFile; false },
        )
        assertFalse(seen.any { it.path.startsWith(projectRoot.path) })
    }

    @Test
    fun `explicit environment path has priority`() {
        val resolved = BinaryResolver.resolve(
            environment = mapOf("AI_FIREWALL_BINARY" to "~/trusted/ai-firewall"),
            osName = "Linux",
            home = "/home/test",
        )
        assertEquals(File("/home/test/trusted/ai-firewall"), resolved)
    }

    @Test
    fun `windows search uses executable name and trusted global directories`() {
        val seen = mutableListOf<File>()
        BinaryResolver.resolve(
            environment = mapOf("LOCALAPPDATA" to "C:\\Users\\test\\AppData\\Local", "PATH" to "C:\\Tools"),
            osName = "Windows 11",
            home = "C:\\Users\\test",
            exists = { candidate -> seen += candidate; false },
        )
        assertFalse(seen.isEmpty())
        assertFalse(seen.any { it.name != "ai-firewall.exe" })
    }
}
