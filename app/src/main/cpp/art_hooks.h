#pragma once
#include <jni.h>

// Calibrate g_ep_offset for this device (no-op on standard layouts). Call once at
// startup after the JavaVM is up; the inline ART-hook path that used to live here
// was removed (LSPlant covers all devices now).
void calibrate_art_offsets(JNIEnv* env);

// Calibrated offset of entry_point_from_quick_compiled_code_ within ArtMethod*.
// Default 32 (standard AOSP arm64). Oplus devices may have a larger offset due to
// extra fields inserted before the standard layout.
// access_flags_ is always at (g_ep_offset - 28).
extern int g_ep_offset;
