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
