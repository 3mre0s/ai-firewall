plugins {
    id("java")
    id("org.jetbrains.kotlin.jvm") version "1.9.25"
    id("org.jetbrains.intellij") version "1.17.4"
}

group = "com.localai.firewall"
version = "0.1.0"

dependencies {
    testImplementation(kotlin("test-junit5"))
}

intellij {
    version.set("2024.1")
    type.set("IC")
}

tasks {
    test {
        useJUnitPlatform()
    }
    patchPluginXml {
        sinceBuild.set("241")
        untilBuild.set("243.*")
    }
}
