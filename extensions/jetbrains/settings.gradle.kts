pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    // The IntelliJ Gradle plugin contributes JetBrains repositories while
    // resolving the target IDE. Allow those project repositories explicitly.
    repositoriesMode.set(RepositoriesMode.PREFER_PROJECT)
    repositories {
        mavenCentral()
    }
}

rootProject.name = "local-ai-firewall-jetbrains"
