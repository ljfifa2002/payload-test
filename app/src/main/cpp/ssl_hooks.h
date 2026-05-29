#pragma once
#include <jni.h>

void install_ssl_hooks();
// Called once from payload_init after lsplant::Init; stores JavaVM + caches
// HookerBridge.jniLogNetwork method reference for ssl_hooks callbacks.
void init_ssl_hooks_jni(JavaVM* vm, JNIEnv* env);
