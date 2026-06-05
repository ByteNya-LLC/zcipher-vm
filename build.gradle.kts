plugins {
    id("java")
}

group = "net.coalcloud.xpwp"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.ow2.asm:asm:9.9.1")
    implementation("org.ow2.asm:asm-tree:9.9.1")
    implementation("org.ow2.asm:asm-util:9.9.1")
    implementation("org.ow2.asm:asm-commons:9.9.1")
    implementation("org.ow2.asm:asm-analysis:9.9.1")

    testImplementation(platform("org.junit:junit-bom:6.0.0"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
}

tasks.register<JavaExec>("inlineHydra") {
    group = "build"
    description = "Run ZCipherCompilerMain to produce the inlined HydraStream.class"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("com.bytenya.zcipher.compiler.ZCipherCompilerMain")
}

tasks.register<JavaExec>("compileVm") {
    group = "build"
    description = "Run VmCompilerMain to lower the inlined class to VM bytecode"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("com.bytenya.zcipher.compiler.VmCompilerMain")
    dependsOn("inlineHydra")
}

tasks.register<JavaExec>("checkInline") {
    group = "verification"
    description = "Run InlineEquivalenceCheck"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("com.bytenya.zcipher.compiler.InlineEquivalenceCheck")
    dependsOn("inlineHydra")
}

tasks.register<JavaExec>("checkVm") {
    group = "verification"
    description = "Run VmEquivalenceCheck"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("com.bytenya.zcipher.compiler.VmEquivalenceCheck")
    dependsOn("inlineHydra")
}

val generatedSrcDir = layout.buildDirectory.dir("generated-src/main/java")
val generatedPhpDir = layout.buildDirectory.dir("generated-src/php")
val generatedGoDir  = layout.buildDirectory.dir("generated-src/go")

tasks.register<JavaExec>("generateVmSource") {
    group = "build"
    description = "Run SourceGenerator to emit single-method obfuscated runtimes (Java + PHP + Go)"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("com.bytenya.zcipher.compiler.SourceGenerator")
    args(generatedSrcDir.get().asFile.absolutePath,
         generatedPhpDir.get().asFile.absolutePath,
         generatedGoDir.get().asFile.absolutePath)
    inputs.files("build/generated-classes/com/bytenya/zcipher/HydraStream.class")
    outputs.dir(generatedSrcDir)
    outputs.dir(generatedPhpDir)
    outputs.dir(generatedGoDir)
    dependsOn("inlineHydra")
}

sourceSets["test"].java.srcDir(generatedSrcDir)
tasks.named<JavaCompile>("compileTestJava") {
    dependsOn("generateVmSource")
}

tasks.register<Exec>("lintPhp") {
    group = "verification"
    description = "Run `php -l` against the generated PHP runtime"
    dependsOn("generateVmSource")
    workingDir = generatedPhpDir.get().asFile
    val script = "for f in *.php; do echo \"==> \$f\" && php -l \"\$f\" || exit 1; done"
    commandLine("sh", "-c", script)
}

tasks.register<JavaExec>("checkPhp") {
    group = "verification"
    description = "Run PhpEquivalenceCheck (drives the generated PHP via subprocess)"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("com.bytenya.zcipher.compiler.PhpEquivalenceCheck")
    dependsOn("generateVmSource", "lintPhp")
}

tasks.register<Exec>("vetGo") {
    group = "verification"
    description = "Build the generated Go runtime via `go build` (catches syntax/type errors)"
    dependsOn("generateVmSource")
    workingDir = generatedGoDir.get().asFile
    commandLine("go", "build", "-o", "/dev/null", "main.go")
}

tasks.register<JavaExec>("checkGo") {
    group = "verification"
    description = "Run GoEquivalenceCheck (drives the generated Go via `go run` subprocess)"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("com.bytenya.zcipher.compiler.GoEquivalenceCheck")
    dependsOn("generateVmSource", "vetGo")
}