plugins {
    alias(libs.plugins.android.library)
}

// Toggle the LSPlant-only native build with: ./gradlew <task> -PlsplantOnly
val lsplantOnly = project.hasProperty("lsplantOnly")

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
                    "-DANDROID_PLATFORM=android-21",
                    // LSPLANT_ONLY: disable the ColorOS inline ART-hook path and use
                    // LSPlant on all devices. Enable with: ./gradlew <task> -PlsplantOnly
                    "-DLSPLANT_ONLY=" + (if (lsplantOnly) "ON" else "OFF")
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
