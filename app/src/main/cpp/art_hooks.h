#pragma once
#include <jni.h>

// Install ShadowHook inline hooks directly on compiled OAT code for each target method.
// The Oplus watchdog only monitors ArtMethod field values, not the bytes at those addresses,
// so patching the code itself survives restoration cycles.
void install_art_inline_hooks(JNIEnv* env, JavaVM* vm);
