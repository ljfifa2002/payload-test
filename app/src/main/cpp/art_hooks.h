#pragma once
#include <jni.h>

// Install ShadowHook inline hooks directly on compiled OAT code for each target method.
// The Oplus watchdog only monitors ArtMethod field values, not the bytes at those addresses,
// so patching the code itself survives restoration cycles.
void install_art_inline_hooks(JNIEnv* env, JavaVM* vm);

// Calibrated offset of entry_point_from_quick_compiled_code_ within ArtMethod*.
// Default 32 (standard AOSP arm64). Oplus devices may have a larger offset due to
// extra fields inserted before the standard layout.
// access_flags_ is always at (g_ep_offset - 28).
extern int g_ep_offset;
