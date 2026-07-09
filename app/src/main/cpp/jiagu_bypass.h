#ifndef JIAGU_BYPASS_H
#define JIAGU_BYPASS_H

// Install ByteHook PLT hooks to intercept obfuscator detection functions.
// This must be called BEFORE shadowhook_init() and lsplant::Init() to prevent
// the obfuscator from detecting inline hooks.
//
// Hooked functions:
//   - open/openat: block access to /proc/self/maps (hide injected libraries)
//   - kill/pthread_kill: block suicide attempts
//
// Note: ptrace hook is intentionally NOT included to avoid blocking peckerd's
// PTRACE_ATTACH to zygote during injection.
//
// Returns: 0 on success, -1 on failure (logged).
int install_jiagu_bypass_hooks();

#endif // JIAGU_BYPASS_H
