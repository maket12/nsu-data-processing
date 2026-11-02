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
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

dependencies {
    // Bouncy Castle Provider and PKIX for X.509 Certificate Builder
    implementation("org.bouncycastle:bcprov-jdk18on:1.80")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.80")

    // JUnit 5 for unit & integration testing
    testImplementation(platform("org.junit:junit-bom:5.11.4"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

application {
    mainClass.set("org.example.keygen.server.KeygenServerMain")
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
        showStandardStreams = false
    }
}

tasks.register<JavaExec>("runClient") {
    group = "application"
    description = "Runs the keygen client"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("org.example.keygen.client.KeygenClientMain")
    standardInput = System.`in`
}
