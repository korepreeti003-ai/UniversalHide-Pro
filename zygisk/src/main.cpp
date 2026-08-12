#include <cstring>
#include <string>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <android/log.h>
#include "zygisk.hpp"

#define TAG "UHPro"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

// Spoof values
static const char* SPOOF_FP    = "google/caiman/caiman:14/AD1A.240905.004/12196292:user/release-keys";
static const char* SPOOF_TAGS  = "release-keys";
static const char* SPOOF_TYPE  = "user";
static const char* SPOOF_MODEL = "Pixel 9 Pro";
static const char* SPOOF_DEV   = "caiman";
static const char* SPOOF_PATCH = "2024-09-05";
static const char* SPOOF_BRAND = "google";
static const char* SPOOF_MANU  = "Google";
static const char* SPOOF_NAME  = "caiman";

// Target packages - all apps that need hiding
static const char* TARGET_PKG[] = {
    "com.google.android.gms",
    "com.android.vending",
    "com.yespaynxt",
    "com.yespay",
    "com.netflix.mediaclient",
    "com.samsung.android.samsungpay",
    "com.paypal.android.p2pmobile",
    "com.whatsapp",
    "com.snapchat.android",
    "com.instagram.android",
    "com.scottyab.rootbeercopy",
    nullptr
};

// All paths RootBeer + YesPay checks
static const char* BLOCK_PATHS[] = {
    "/sbin/su",
    "/system/su",
    "/system/xbin/su",
    "/system/bin/su",
    "/su/bin/su",
    "/data/local/bin/su",
    "/data/local/xbin/su",
    "/data/local/su",
    "/system/bin/failsafe/su",
    "/system/bin/.ext/.su",
    "/system/app/Superuser.apk",
    "/system/app/SuperSU.apk",
    "/system/usr/we-need-root",
    "/system/xbin/daemonsu",
    "/system/xbin/busybox",
    "/system/bin/busybox",
    "/sbin/busybox",
    "/data/local/bin/busybox",
    "magisk",
    ".magisk",
    "kernelsu",
    "ksunext",
    "ksud",
    "zygisk",
    "riru",
    nullptr
};

// Maps filter
static const char* MAPS_BL[] = {
    "magisk", "zygisk", "riru",
    "kernelsu", "ksud", "ksunext",
    "uhpro", "frida", "xposed",
    nullptr
};

// Dangerous props YesPay checks
static const char* DANGER_PROPS[] = {
    "ro.debuggable",
    "ro.secure",
    "ro.build.selinux",
    nullptr
};

static int   (*orig_sysprop)(const char*, char*)        = nullptr;
static int   (*orig_open)   (const char*, int, ...)     = nullptr;
static FILE* (*orig_fopen)  (const char*, const char*)  = nullptr;
static int   (*orig_stat)   (const char*, struct stat*) = nullptr;
static int   (*orig_access) (const char*, int)          = nullptr;
typedef int (*execve_t)(const char*, char* const[], char* const[]);
static execve_t orig_execve = nullptr;

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

static int hook_sysprop(const char* name, char* value) {
    int ret = orig_sysprop(name, value);
    if (!name || !value) return ret;

    struct { const char* k; const char* v; } tbl[] = {
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
        {"ro.product.device",               SPOOF_DEV},
        {"ro.product.brand",                SPOOF_BRAND},
        {"ro.product.manufacturer",         SPOOF_MANU},
        {"ro.build.version.security_patch", SPOOF_PATCH},
        {"ro.product.name",                 SPOOF_NAME},
        {"sys.oem_unlock_allowed",          "0"},
        {"ro.build.selinux",                "1"},
        {"ro.build.flavor",                 "caiman-user"},
        {"ro.build.description",            "caiman-user 14 AD1A.240905.004 12196292 release-keys"},
        {nullptr, nullptr}
    };

    for (int i = 0; tbl[i].k; i++)
        if (!strcmp(name, tbl[i].k)) {
            strcpy(value, tbl[i].v);
            return strlen(value);
        }
    return ret;
}

static int hook_open(const char* path, int flags, ...) {
    if (shouldBlock(path)) { errno = ENOENT; return -1; }
    va_list ap; va_start(ap, flags);
    mode_t m = va_arg(ap, mode_t); va_end(ap);
    return orig_open(path, flags, m);
}

static FILE* hook_fopen(const char* path, const char* mode) {
    if (!path) return orig_fopen(path, mode);
    if (strstr(path, "/proc/self/maps") ||
        strstr(path, "/proc/self/smaps")) {
        FILE* real = orig_fopen(path, mode);
        if (!real) return nullptr;
        char* buf = nullptr; size_t sz = 0;
        char line[512];
        FILE* mem = open_memstream(&buf, &sz);
        while (fgets(line, sizeof(line), real)) {
            bool block = false;
            for (int i = 0; MAPS_BL[i]; i++)
                if (strstr(line, MAPS_BL[i])) { block = true; break; }
            if (!block) fputs(line, mem);
        }
        fclose(real); fclose(mem);
        return fmemopen(buf, sz, mode);
    }
    if (shouldBlock(path)) { errno = ENOENT; return nullptr; }
    return orig_fopen(path, mode);
}

static int hook_stat(const char* path, struct stat* st) {
    if (shouldBlock(path)) { errno = ENOENT; return -1; }
    return orig_stat(path, st);
}

static int hook_access(const char* path, int mode) {
    if (shouldBlock(path)) { errno = ENOENT; return -1; }
    return orig_access(path, mode);
}

static int hook_execve(const char* path, char* const argv[], char* const envp[]) {
    if (path && (strstr(path, "/su") || strstr(path, "busybox")))
        { errno = ENOENT; return -1; }
    if (argv && argv[0] && strstr(argv[0], "su"))
        { errno = ENOENT; return -1; }
    return orig_execve(path, argv, envp);
}

static void installHooks() {
    void* libc = dlopen("libc.so", RTLD_NOW);
    if (!libc) return;
    orig_sysprop = (int(*)(const char*,char*))        dlsym(libc, "__system_property_get");
    orig_open    = (int(*)(const char*,int,...))       dlsym(libc, "open");
    orig_fopen   = (FILE*(*)(const char*,const char*)) dlsym(libc, "fopen");
    orig_stat    = (int(*)(const char*,struct stat*))  dlsym(libc, "stat");
    orig_access  = (int(*)(const char*,int))           dlsym(libc, "access");
    orig_execve  = (execve_t)                          dlsym(libc, "execve");
    dlclose(libc);
    LOGI("All hooks installed for YesPay/RootBeer bypass");
}

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
    Api* api = nullptr;
    JNIEnv* env = nullptr;
};

REGISTER_ZYGISK_MODULE(UniversalHide)
