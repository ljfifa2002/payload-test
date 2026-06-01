#pragma once
#include <jni.h>

void install_device_id_hooks(JNIEnv* env);

// Cached after install_device_id_hooks() — valid for the process lifetime.
// Used by the Phase 10 thread in main.cpp to avoid FindClass on a bare native
// thread (which would use the system ClassLoader instead of InMemoryDexClassLoader).
extern jclass    g_hooker_class_global;
extern jmethodID g_install_mini_method;
