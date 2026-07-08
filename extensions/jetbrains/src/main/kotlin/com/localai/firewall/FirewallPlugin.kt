package com.localai.firewall

import com.intellij.ide.BrowserUtil
import com.intellij.notification.NotificationGroupManager
import com.intellij.notification.NotificationType
import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.ide.CopyPasteManager
import com.intellij.openapi.project.Project
import java.awt.datatransfer.StringSelection
import java.io.File

private object FirewallProcess {
    private var process: Process? = null

    fun start(project: Project?) {
        if (process?.isAlive == true) {
            notify(project, "Local AI Firewall is already running.", NotificationType.INFORMATION)
            return
        }

        val binary = resolveBinary(project)
        if (!binary.exists()) {
            notify(project, "Build ai-firewall in the project root or set AI_FIREWALL_BINARY.", NotificationType.ERROR)
            return
        }

        val apiKey = System.getenv("FORWARD_API_KEY")
        if (apiKey.isNullOrBlank()) {
            notify(project, "Set FORWARD_API_KEY before starting Local AI Firewall.", NotificationType.ERROR)
            return
        }

        val env = ProcessBuilder(binary.absolutePath)
            .directory(binary.parentFile)
            .redirectErrorStream(true)
            .redirectOutput(ProcessBuilder.Redirect.DISCARD)

        env.environment()["FORWARD_API_KEY"] = apiKey
        env.environment()["UPSTREAM_URL"] = System.getenv("UPSTREAM_URL") ?: "https://api.anthropic.com"
        env.environment()["PROVIDER_HINT"] = System.getenv("PROVIDER_HINT") ?: ""
        env.environment()["FIREWALL_PORT"] = port().toString()
        env.environment()["LOG_LEVEL"] = System.getenv("LOG_LEVEL") ?: "info"

        process = env.start()
        notify(project, "Local AI Firewall started on ${baseUrl()}.", NotificationType.INFORMATION)
    }

    fun stop(project: Project?) {
        process?.destroy()
        process = null
        notify(project, "Local AI Firewall stopped.", NotificationType.INFORMATION)
    }

    fun restart(project: Project?) {
        stop(project)
        start(project)
    }

    private fun resolveBinary(project: Project?): File {
        val configured = System.getenv("AI_FIREWALL_BINARY")
        if (!configured.isNullOrBlank()) {
            return File(expandHome(configured))
        }

        val osName = System.getProperty("os.name").lowercase()
        val isWindows = osName.startsWith("windows")
        val isMac = osName.startsWith("mac") || osName.contains("darwin")
        val binaryName = if (isWindows) "ai-firewall.exe" else "ai-firewall"

        val candidates = mutableListOf<File>()

        project?.basePath?.let { candidates += File(it, binaryName) }

        val home = System.getProperty("user.home") ?: ""
        when {
            isWindows -> {
                val localAppData = System.getenv("LOCALAPPDATA")
                    ?: (if (home.isNotEmpty()) "$home\\AppData\\Local" else null)
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
                if (home.isNotEmpty()) {
                    candidates += File("$home/.local/bin", binaryName)
                }
                candidates += File("/usr/local/bin", binaryName)
                candidates += File("/usr/bin", binaryName)
            }
        }

        val pathEnv = System.getenv("PATH").orEmpty()
        val sep = if (isWindows) ";" else ":"
        pathEnv.split(sep).filter { it.isNotBlank() }.forEach {
            candidates += File(it, binaryName)
        }

        return candidates.firstOrNull { it.exists() }
            ?: candidates.firstOrNull()
            ?: File(binaryName)
    }

    private fun expandHome(value: String): String {
        if (value.startsWith("~/") || value.startsWith("~\\")) {
            val home = System.getProperty("user.home") ?: return value
            return home + value.substring(1)
        }
        return value
    }
}

class StartFirewallAction : AnAction() {
    override fun actionPerformed(event: AnActionEvent) = FirewallProcess.start(event.project)
}

class StopFirewallAction : AnAction() {
    override fun actionPerformed(event: AnActionEvent) = FirewallProcess.stop(event.project)
}

class RestartFirewallAction : AnAction() {
    override fun actionPerformed(event: AnActionEvent) = FirewallProcess.restart(event.project)
}

class CopyEnvAction : AnAction() {
    override fun actionPerformed(event: AnActionEvent) {
        val snippet = """
            ANTHROPIC_BASE_URL=${baseUrl()}
            ANTHROPIC_API_KEY=any-placeholder
            OPENAI_BASE_URL=${baseUrl()}
            OPENAI_API_KEY=any-placeholder
        """.trimIndent()

        CopyPasteManager.getInstance().setContents(StringSelection(snippet))
        notify(event.project, "Local AI Firewall agent env copied.", NotificationType.INFORMATION)
    }
}

class OpenMetricsAction : AnAction() {
    override fun actionPerformed(event: AnActionEvent) {
        BrowserUtil.browse("${baseUrl()}/metrics")
    }
}

private fun baseUrl(): String = "http://127.0.0.1:${port()}"

private fun port(): Int = System.getenv("FIREWALL_PORT")?.toIntOrNull() ?: 8080

private fun notify(project: Project?, message: String, type: NotificationType) {
    ApplicationManager.getApplication().invokeLater {
        NotificationGroupManager.getInstance()
            .getNotificationGroup("Local AI Firewall")
            ?.createNotification(message, type)
            ?.notify(project)
    }
}
