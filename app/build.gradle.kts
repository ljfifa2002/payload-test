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
