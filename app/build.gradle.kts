import java.io.File

plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "com.pecker.payload"
    compileSdk = 35
    ndkVersion = "27.2.12479018"

    defaultConfig {
        minSdk = 21
        externalNativeBuild {
            cmake {
                abiFilters += "arm64-v8a"
                arguments(
                    "-DANDROID_STL=c++_static",
                    "-DANDROID_PLATFORM=android-21"
                )
            }
        }
    }

    buildFeatures {
        prefab = true
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }
}

dependencies {
    implementation("org.lsposed.lsplant:lsplant-standalone:5.1")
    implementation("com.bytedance.android:shadowhook:1.0.9")
}

// ---- Generate hooker.dex from HookerBridge.java ----
//
// Steps:
//   1. Compile HookerBridge.java with javac (using android.jar as classpath)
//   2. Run d8 on the .class file to produce hooker.dex
//
// Output: app/build/outputs/payload-libs/arm64-v8a/hooker.dex

val androidJar = "${android.sdkDirectory}/platforms/android-35/android.jar"

val compileHookerJava by tasks.registering(JavaCompile::class) {
    source = fileTree("src/main/java/com/pecker/payload") {
        include("HookerBridge.java")
    }
    classpath = files(androidJar)
    destinationDirectory.set(layout.buildDirectory.dir("hooker_classes"))
    sourceCompatibility = "11"
    targetCompatibility = "11"
    options.compilerArgs.addAll(listOf("-source", "11", "-target", "11", "-bootclasspath", androidJar))
}

val buildHookerDex by tasks.registering(Exec::class) {
    dependsOn(compileHookerJava)
    val classesDir = layout.buildDirectory.dir("hooker_classes").get().asFile
    val outDir = layout.buildDirectory.dir("outputs/payload-libs/arm64-v8a").get().asFile
    doFirst { outDir.mkdirs() }
    // d8 is in build-tools; find it dynamically
    val buildToolsDir = File("${android.sdkDirectory}/build-tools")
    val d8 = buildToolsDir.listFiles()
        ?.maxByOrNull { it.name }
        ?.let { File(it, if (System.getProperty("os.name").lowercase().contains("win")) "d8.bat" else "d8") }
        ?: throw GradleException("d8 not found in $buildToolsDir")
    commandLine(
        d8.absolutePath,
        "--min-api", "21",
        "--output", outDir.absolutePath,
        "--lib", androidJar
    )
    args(fileTree(classesDir) { include("**/*.class") }.files.map { it.absolutePath })
    doLast {
        // d8 outputs classes.dex; rename to hooker.dex
        File(outDir, "classes.dex").renameTo(File(outDir, "hooker.dex"))
    }
}

// Wire into the main assemble task so CI picks it up automatically
tasks.named("assembleRelease") {
    finalizedBy(buildHookerDex)
}
