#include "jiagu_bypass.h"
#include <bytehook.h>
#include <android/log.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <stdarg.h>

#define TAG "payload"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ── Hook: open() ─────────────────────────────────────────────────────────────
// Block obfuscator from reading /proc/self/maps to detect injected libraries.
static int (*orig_open)(const char *pathname, int flags, ...) = nullptr;

static int fake_open(const char *pathname, int flags, ...) {
    // Check if this is a maps detection attempt
    if (pathname && strstr(pathname, "/proc") && strstr(pathname, "maps")) {
        LOGI("bytehook: blocked jiagu maps detection: %s", pathname);
        errno = ENOENT;
        return -1;
    }

    // Handle optional mode argument for O_CREAT
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
        BYTEHOOK_STACK_SCOPE();
        return BYTEHOOK_CALL_PREV(fake_open, pathname, flags, mode);
    } else {
        BYTEHOOK_STACK_SCOPE();
        return BYTEHOOK_CALL_PREV(fake_open, pathname, flags);
    }
}

// ── Hook: openat() ───────────────────────────────────────────────────────────
// Android 5.0+ apps use openat() more frequently than open().
static int (*orig_openat)(int dirfd, const char *pathname, int flags, ...) = nullptr;

static int fake_openat(int dirfd, const char *pathname, int flags, ...) {
    if (pathname && strstr(pathname, "/proc") && strstr(pathname, "maps")) {
        LOGI("bytehook: blocked jiagu maps detection (openat): %s", pathname);
        errno = ENOENT;
        return -1;
    }

    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
        BYTEHOOK_STACK_SCOPE();
        return BYTEHOOK_CALL_PREV(fake_openat, dirfd, pathname, flags, mode);
    } else {
        BYTEHOOK_STACK_SCOPE();
        return BYTEHOOK_CALL_PREV(fake_openat, dirfd, pathname, flags);
    }
}

// ── Hook: kill() ─────────────────────────────────────────────────────────────
// Block obfuscator suicide attempts (kill(getpid(), SIGKILL)).
static int (*orig_kill)(pid_t pid, int sig) = nullptr;

static int fake_kill(pid_t pid, int sig) {
    // Block self-termination with SIGKILL or SIGABRT
    if (pid == getpid() && (sig == SIGKILL || sig == SIGABRT)) {
        LOGI("bytehook: blocked jiagu suicide attempt: kill(%d, %d)", pid, sig);
        return 0; // Pretend success
    }

    BYTEHOOK_STACK_SCOPE();
    return BYTEHOOK_CALL_PREV(fake_kill, pid, sig);
}

// ── Hook: pthread_kill() ─────────────────────────────────────────────────────
// Block thread-targeted suicide attempts.
static int (*orig_pthread_kill)(pthread_t thread, int sig) = nullptr;

static int fake_pthread_kill(pthread_t thread, int sig) {
    // Block SIGKILL/SIGABRT to any thread in our process
    if (sig == SIGKILL || sig == SIGABRT) {
        LOGI("bytehook: blocked jiagu thread suicide: pthread_kill(%lu, %d)",
             (unsigned long)thread, sig);
        return 0;
    }

    BYTEHOOK_STACK_SCOPE();
    return BYTEHOOK_CALL_PREV(fake_pthread_kill, thread, sig);
}

// ── Installation ─────────────────────────────────────────────────────────────
int install_jiagu_bypass_hooks() {
    LOGI("bytehook: installing jiagu bypass hooks");

    // Initialize ByteHook (automatic mode hooks all existing and future libs)
    int ret = bytehook_init(BYTEHOOK_MODE_AUTOMATIC, false);
    if (ret != 0) {
        LOGE("bytehook: init failed, ret=%d", ret);
        return -1;
    }

    // Hook libc.so functions used for detection
    bytehook_stub_t stub;

    stub = bytehook_hook_all(nullptr, "open", (void*)fake_open, nullptr, nullptr);
    if (stub == nullptr) {
        LOGE("bytehook: failed to hook open()");
    }

    stub = bytehook_hook_all(nullptr, "openat", (void*)fake_openat, nullptr, nullptr);
    if (stub == nullptr) {
        LOGE("bytehook: failed to hook openat()");
    }

    stub = bytehook_hook_all(nullptr, "kill", (void*)fake_kill, nullptr, nullptr);
    if (stub == nullptr) {
        LOGE("bytehook: failed to hook kill()");
    }

    stub = bytehook_hook_all(nullptr, "pthread_kill", (void*)fake_pthread_kill, nullptr, nullptr);
    if (stub == nullptr) {
        LOGE("bytehook: failed to hook pthread_kill()");
    }

    LOGI("bytehook: jiagu bypass hooks installed successfully");
    return 0;
}
