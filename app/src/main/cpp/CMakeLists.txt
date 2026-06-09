cmake_minimum_required(VERSION 3.22.1)
project(payload)

# LSPLANT_ONLY: when ON, disables the ColorOS inline ART-hook path (art_hooks.cpp)
# and routes every device-id hook through LSPlant on all devices. Used to validate
# — and ultimately land — the LSPlant-only path on ColorOS once the Oplus
# entry-point watchdog is disabled on-device. Default OFF preserves production
# behaviour. Toggle from Gradle with: ./gradlew <task> -PlsplantOnly
option(LSPLANT_ONLY "Use LSPlant for all hooks; disable ColorOS inline ART hooks" OFF)

# ShadowHook via prefab (no riscv64 ABI in its package)
find_package(shadowhook REQUIRED CONFIG)

# LSPlant 6.4 — manual prebuilt import, bypasses prefab riscv64 issue.
# Headers and .so are extracted from the AAR by the CI workflow
# (see build.yml "Extract LSPlant 6.4" step) before this CMake runs.
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/lsplant/include)
add_library(lsplant SHARED IMPORTED)
set_target_properties(lsplant PROPERTIES
    IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/liblsplant.so
)

add_library(payload SHARED main.cpp hooks.cpp art_hooks.cpp ssl_hooks.cpp)

if(LSPLANT_ONLY)
    target_compile_definitions(payload PRIVATE LSPLANT_ONLY=1)
    message(STATUS "payload: LSPLANT_ONLY build — ColorOS inline ART hooks disabled")
endif()

target_link_libraries(payload
    lsplant
    shadowhook::shadowhook
    log
    android
)
