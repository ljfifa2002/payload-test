plugins {
    alias(libs.plugins.android.library)
}

// NOTE: hooker.dex string encoding is NOT done here. hooker.dex is built in CI
// with javac + d8 directly (see .github/workflows/build.yml), bypassing AGP, so
// the AGP instrumentation API can't reach it. The Obf.s("...") literals are
// encoded by tools/ObfTransform.java, run on the javac output before d8.

android {
    namespace = "com.pecker.payload"
    compileSdk = 35
    ndkVersion = "27.2.12479018"

    defaultConfig {
        minSdk = 21
        externalNativeBuild {
            cmake {
                abiFilters += "arm64-v8a"
                abiFilters += "armeabi-v7a"
                arguments(
                    "-DANDROID_STL=c++_static",
                    "-DANDROID_PLATFORM=android-21"
                )
            }
        }
    }

    buildFeatures {
        prefab = true  // still needed for shadowhook
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }
}

dependencies {
    // LSPlant removed from prefab — imported manually as prebuilt in CMakeLists.txt
    implementation("com.bytedance.android:shadowhook:1.0.9")
}
