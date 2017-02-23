import org.gradle.api.Task
import org.gradle.api.tasks.testing.Test
import org.gradle.api.tasks.wrapper.Wrapper
import org.gradle.api.reporting.ReportingExtension
import org.gradle.jvm.tasks.Jar
import org.gradle.language.jvm.tasks.ProcessResources
import org.gradle.testing.jacoco.plugins.JacocoPluginExtension
import org.gradle.testing.jacoco.plugins.JacocoTaskExtension
import org.gradle.testing.jacoco.tasks.JacocoReport
import org.springframework.boot.gradle.run.BootRunTask

buildscript {
    repositories {
        mavenCentral()
        maven { setUrl("http://repo.spring.io/plugins-release") }
        maven { setUrl("https://plugins.gradle.org/m2/") }
    }
    dependencies {
        classpath("org.springframework.boot:spring-boot-gradle-plugin:1.4.4.RELEASE")
        classpath("org.owasp:dependency-check-gradle:1.3.6")
        classpath("gradle.plugin.nl.javadude.gradle.plugins:license-gradle-plugin:0.13.1")
        classpath("org.springframework.build.gradle:propdeps-plugin:0.0.7")
    }
}

apply {
    plugin("java")
    plugin("idea")
    plugin("org.springframework.boot")
    plugin("org.owasp.dependencycheck")
    plugin("com.github.hierynomus.license")
    plugin("jacoco")
}

val jar = getTask<Jar>("jar")
jar.apply {
    baseName = "credhub"
    version = "${System.getenv("VERSION") ?: "DEV"}"
}

configure<JavaPluginConvention> {
    setSourceCompatibility(1.8)
    setTargetCompatibility(1.8)
}

repositories {
    mavenCentral()
    jcenter()
}

dependencies {
    listOf(
            "org.springframework.boot:spring-boot-starter-web",
            "org.springframework.boot:spring-boot-starter-security",
            "org.springframework.boot:spring-boot-starter-data-jpa",
            "org.springframework.security.oauth:spring-security-oauth2",
            "org.springframework.security:spring-security-jwt"
    ).forEach({
        compile(it) {
            exclude(module = "spring-boot-starter-logging")
            exclude(module = "logback-classic")
        }
    })

    compile("org.springframework.boot:spring-boot-starter-log4j2")
    compile("org.passay:passay:1.1.0")
    compile("com.h2database:h2:1.4.192")
    compile("com.jayway.jsonpath:json-path:2.2.0")
    compile("org.bouncycastle:bcpkix-jdk15on:1.52")
    compile("com.google.guava:guava:19.0")
    compile("org.apache.commons:commons-lang3:3.4")
    compile("com.fasterxml.jackson.datatype:jackson-datatype-jsr310:2.7.5")
    compile("org.exparity:hamcrest-bean:1.0.11")
    compile("org.postgresql:postgresql:9.3-1100-jdbc4")
    compile("mysql:mysql-connector-java:5.1.38")
    compile("org.flywaydb:flyway-core:4.0.3")
    compile("net.java.dev.jna:jna:4.2.2")
    compile("org.mariadb.jdbc:mariadb-java-client:1.5.8")
    testCompile("org.springframework.boot:spring-boot-starter-test")
    testCompile("org.skyscreamer:jsonassert")
    testCompile("com.jayway.jsonpath:json-path-assert:2.2.0")
    testCompile("com.greghaskins:spectrum:1.0.0")
    testCompile("org.apache.commons:commons-lang3:3.4")
}

task<Wrapper>("wrapper") {
    gradleVersion = "3.1"
}

getTask<ProcessResources>("processResources").apply {
    expand(mapOf("buildVersion" to "${jar.version}${if (System.getenv("BUILD_NUMBER") != null) "+build.${System.getenv("BUILD_NUMBER")}" else ""}").toSortedMap())
    outputs.upToDateWhen { false }
}

getExtension<JacocoPluginExtension>("jacoco").apply {
    toolVersion = "0.7.6.201602180812"
}

getTask<JacocoReport>("jacocoTestReport").apply {
    group = "Reporting"
    reports.apply {
        xml.isEnabled = false
        csv.isEnabled = false
        html.apply {
            isEnabled = true
            setDestination("${project.buildDir}/reports/jacoco")
        }
    }
}

getTask<BootRunTask>("bootRun").apply {
    addResources = true
    systemProperties["spring.profiles.active"] = System.getProperty("spring.profiles.active", "dev")
}

task("cleanAndAssemble") {
    dependsOn("clean")
    dependsOn("assemble")
}

getTask<Task>("assemble").mustRunAfter("clean")

getTask<Test>("test").apply {
    val jacoco = extensions.findByName("jacoco") as JacocoTaskExtension
    jacoco.apply {
        isAppend = false
        destinationFile = file("${project.buildDir}/jacoco/jacocoTest.exec")
        classDumpFile = file("${project.buildDir}/jacoco/classpathdumps")
    }
    testLogging.apply {
        setEvents(setOf("passed", "failed", "skipped"))
        setExceptionFormat("full")
    }
    systemProperties["spring.profiles.active"] = System.getProperty("spring.profiles.active", "unit-test-h2")
    outputs.upToDateWhen { false }
}

tasks.withType<Test> {
    val reporting = getExtension<ReportingExtension>("reporting")
    val name = project.name
    reports.html.setDestination(file("${reporting.baseDir}/${name}"))
}

fun <T : Task> getTask(taskName: String): T {
    return project.tasks.getByName(taskName) as T
}

fun <E> getExtension(extensionName: String): E {
    return project.extensions.findByName(extensionName) as E
}
