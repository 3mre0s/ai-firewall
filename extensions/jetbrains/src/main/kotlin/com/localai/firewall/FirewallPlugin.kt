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

private object FirewallProcess {
    private var process: Process? = null

    fun start(project: Project?) {
        if (process?.isAlive == true) {
            notify(project, "Local AI Firewall is already running.", NotificationType.INFORMATION)
            return
        }

        val binary = BinaryResolver.resolve(
            environment = System.getenv(),
            osName = System.getProperty("os.name"),
            home = System.getProperty("user.home") ?: "",
        )
        if (!binary.exists()) {
            notify(project, "Install ai-firewall globally or set AI_FIREWALL_BINARY to a trusted binary.", NotificationType.ERROR)
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
