plugins {
    java
    application
}

group = "org.example"
version = "1.0.0"

repositories {
    mavenCentral()
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
}

dependencies {
    // Bouncy Castle Provider and PKIX for X.509 Certificate Builder
    implementation("org.bouncycastle:bcprov-jdk18on:1.80")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.80")

    // JUnit 5 for unit & integration testing
    testImplementation(platform("org.junit:junit-bom:5.11.4"))
    testImplementation("org.junit.jupiter:junit-jupiter")
}

application {
    mainClass.set("org.example.keygen.server.KeygenServerMain")
}

tasks.test {
    useJUnitPlatform()
}

tasks.register<JavaExec>("runClient") {
    group = "application"
    description = "Runs the keygen client"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("org.example.keygen.client.KeygenClientMain")
    standardInput = System.`in`
}
