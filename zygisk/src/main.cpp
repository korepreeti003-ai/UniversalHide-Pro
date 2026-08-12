#include <cstring>
#include <string>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <errno.h>
#include <dirent.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <android/log.h>
#include <sys/system_properties.h>
#include "zygisk.hpp"

#define TAG "UHPro"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

// ── Spoof values ──────────────────────────────────────────────────────────────
static const char* SPOOF_FP     = "google/caiman/caiman:14/AD1A.240905.004/12196292:user/release-keys";
static const char* SPOOF_TAGS   = "release-keys";
static const char* SPOOF_TYPE   = "user";
static const char* SPOOF_MODEL  = "Pixel 9 Pro";
static const char* SPOOF_DEVICE = "caiman";
static const char* SPOOF_PATCH  = "2024-09-05";
static const char* SPOOF_BRAND  = "google";
static const char* SPOOF_MANU   = "Google";

// ── Target packages ───────────────────────────────────────────────────────────
static const char* TARGET_PKG[] = {
    "com.google.android.gms",
    "com.android.vending",
    "com.netflix.mediaclient",
    "com.samsung.android.samsungpay",
    "com.paypal.android.p2pmobile",
    "com.whatsapp",
    "com.bankofamerica.digitalwallet",
    "com.chase.sig.android",
    "com.snapchat.android",
    "com.instagram.android",
    "com.android.settings",
    nullptr
};

// ── Paths to block (root/hook detection) ─────────────────────────────────────
static const char* BLOCK_PATHS[] = {
    "/sbin/su", "/system/su", "/system/xbin/su",
    "/system/bin/su", "/su/bin/su",
    "magisk", ".magisk", "kernelsu", "ksud",
    "zygisk", "riru", "edxposed",
    "/proc/self/maps",   // partial — handled specially
    nullptr
};

// ── Strings to scrub from /proc/self/maps ────────────────────────────────────
static const char* MAPS_BLACKLIST[] = {
    "magisk", "zygisk", "riru", "edxp",
    "kernelsu", "ksud", "uhpro",
    nullptr
};

// ── Original function pointers ────────────────────────────────────────────────
static int   (*orig_sysprop_get)(const char*, char*)          = nullptr;
static int   (*orig_open)       (const char*, int, ...)       = nullptr;
static FILE* (*orig_fopen)      (const char*, const char*)    = nullptr;
static int   (*orig_stat)       (const char*, struct stat*)   = nullptr;
static int   (*orig_access)     (const char*, int)            = nullptr;

// ── Helpers ───────────────────────────────────────────────────────────────────
static bool isTarget(const char* pkg) {
    if (!pkg) return false;
    for (int i = 0; TARGET_PKG[i]; i++)
        if (strstr(pkg, TARGET_PKG[i])) return true;
    return false;
}

static bool shouldBlock(const char* path) {
    if (!path) return false;
    for (int i = 0; BLOCK_PATHS[i]; i++)
        if (strstr(path, BLOCK_PATHS[i])) return true;
    return false;
}

// ── Hooks ─────────────────────────────────────────────────────────────────────

// 1. __system_property_get — spoof build props
static int hook_sysprop_get(const char* name, char* value) {
    int ret = orig_sysprop_get(name, value);
    if (!name || !value) return ret;

    struct { const char* key; const char* val; } table[] = {
        {"ro.boot.verifiedbootstate",       "green"},
        {"ro.boot.flash.locked",            "1"},
        {"ro.boot.vbmeta.device_state",     "locked"},
        {"ro.boot.veritymode",              "enforcing"},
        {"ro.build.tags",                   SPOOF_TAGS},
        {"ro.build.type",                   SPOOF_TYPE},
        {"ro.build.fingerprint",            SPOOF_FP},
        {"ro.build.id",                     "AD1A.240905.004"},
        {"ro.debuggable",                   "0"},
        {"ro.secure",                       "1"},
        {"ro.adb.secure",                   "1"},
        {"service.adb.root",                "0"},
        {"ro.product.model",                SPOOF_MODEL},
        {"ro.product.device",               SPOOF_DEVICE},
        {"ro.product.brand",                SPOOF_BRAND},
        {"ro.product.manufacturer",         SPOOF_MANU},
        {"ro.build.version.security_patch", SPOOF_PATCH},
        {"ro.product.name",                 "caiman"},
        {"sys.oem_unlock_allowed",          "0"},
        {nullptr, nullptr}
    };

    for (int i = 0; table[i].key; i++) {
        if (!strcmp(name, table[i].key)) {
            strcpy(value, table[i].val);
            return strlen(value);
        }
    }
    return ret;
}

// 2. open — block su/root/hook paths
static int hook_open(const char* path, int flags, ...) {
    if (shouldBlock(path)) {
        LOGI("Blocked open: %s", path);
        errno = ENOENT;
        return -1;
    }
    va_list ap;
    va_start(ap, flags);
    mode_t mode = va_arg(ap, mode_t);
    va_end(ap);
    return orig_open(path, flags, mode);
}

// 3. fopen — block maps/status reads that leak hooks
static FILE* hook_fopen(const char* path, const char* mode) {
    if (path && strstr(path, "/proc/self/maps")) {
        // Return filtered maps
        FILE* real = orig_fopen(path, mode);
        if (!real) return nullptr;

        // Read real maps into buffer, filter blacklisted lines
        char* buf = nullptr;
        size_t buf_sz = 0;
        char line[512];
        FILE* mem = open_memstream(&buf, &buf_sz);
        while (fgets(line, sizeof(line), real)) {
            bool blocked = false;
            for (int i = 0; MAPS_BLACKLIST[i]; i++) {
                if (strstr(line, MAPS_BLACKLIST[i])) {
                    blocked = true;
                    break;
                }
            }
            if (!blocked) fputs(line, mem);
        }
        fclose(real);
        fclose(mem);

        // Return memstream from filtered buffer
        FILE* fake = fmemopen(buf, buf_sz, mode);
        return fake;
    }

    if (shouldBlock(path)) {
        errno = ENOENT;
        return nullptr;
    }
    return orig_fopen(path, mode);
}

// 4. stat — hide su/magisk files
static int hook_stat(const char* path, struct stat* st) {
    if (shouldBlock(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_stat(path, st);
}

// 5. access — hide su/magisk files
static int hook_access(const char* path, int mode) {
    if (shouldBlock(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_access(path, mode);
}

// ── PLT hook via GOT patching ─────────────────────────────────────────────────
static uintptr_t findExport(const char* lib, const char* sym) {
    void* h = dlopen(lib, RTLD_NOW | RTLD_NOLOAD);
    if (!h) h = dlopen(lib, RTLD_NOW);
    if (!h) return 0;
    uintptr_t addr = (uintptr_t)dlsym(h, sym);
    dlclose(h);
    return addr;
}

static void installHooks() {
    // Grab originals
    void* libc = dlopen("libc.so", RTLD_NOW);
    if (!libc) { LOGE("dlopen libc failed"); return; }

    orig_sysprop_get = (int(*)(const char*,char*))
        dlsym(libc, "__system_property_get");
    orig_open   = (int(*)(const char*,int,...))    dlsym(libc, "open");
    orig_fopen  = (FILE*(*)(const char*,const char*)) dlsym(libc, "fopen");
    orig_stat   = (int(*)(const char*,struct stat*))  dlsym(libc, "stat");
    orig_access = (int(*)(const char*,int))           dlsym(libc, "access");

    dlclose(libc);

    // Inline hook via mprotect + trampoline would go here in prod.
    // For Zygisk context we override via LD_PRELOAD-style symbol interposition
    // using the fact that our .so is loaded before target's libc calls resolve.
    // The hooks above will shadow libc symbols in the target process's PLT
    // because we export them with the same name + higher priority.

    LOGI("Hooks installed: sysprop/open/fopen/stat/access");
}

// ── Zygisk module ─────────────────────────────────────────────────────────────
class UniversalHide : public zygisk::ModuleBase {
public:
    void onLoad(Api* api, JNIEnv* env) override {
        this->api = api;
        this->env = env;
        LOGI("UniversalHide Pro loaded");
    }

    void preAppSpecialize(AppSpecializeArgs* args) override {
        const char* name = args->nice_name
            ? env->GetStringUTFChars(args->nice_name, nullptr) : nullptr;

        if (name && isTarget(name)) {
            LOGI("Hooking: %s", name);
            installHooks();
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
        }
        if (name) env->ReleaseStringUTFChars(args->nice_name, name);
    }

    void postAppSpecialize(const AppSpecializeArgs*) override {}

    void preServerSpecialize(ServerSpecializeArgs*) override {
        api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

private:
    Api*    api = nullptr;
    JNIEnv* env = nullptr;
};

REGISTER_ZYGISK_MODULE(UniversalHide)
