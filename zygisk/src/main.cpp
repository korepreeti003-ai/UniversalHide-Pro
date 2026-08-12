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
#include "zygisk.hpp"

#define TAG "UHPro"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

// ── Spoof ─────────────────────────────────────────────────────────────────────
static const char* SPOOF_FP    = "google/caiman/caiman:14/AD1A.240905.004/12196292:user/release-keys";
static const char* SPOOF_TAGS  = "release-keys";
static const char* SPOOF_TYPE  = "user";
static const char* SPOOF_MODEL = "Pixel 9 Pro";
static const char* SPOOF_DEV   = "caiman";
static const char* SPOOF_PATCH = "2024-09-05";
static const char* SPOOF_BRAND = "google";
static const char* SPOOF_MANU  = "Google";

// ── Targets ───────────────────────────────────────────────────────────────────
static const char* TARGET_PKG[] = {
    "com.google.android.gms",
    "com.android.vending",
    "com.netflix.mediaclient",
    "com.samsung.android.samsungpay",
    "com.paypal.android.p2pmobile",
    "com.whatsapp",
    "com.snapchat.android",
    "com.instagram.android",
    nullptr
};

// ── Block paths ───────────────────────────────────────────────────────────────
static const char* BLOCK_PATHS[] = {
    "/sbin/su", "/system/su", "/system/xbin/su",
    "/system/bin/su", "/su/bin/su",
    "/data/local/bin/su", "/data/local/xbin/su",
    "/data/local/su", "/system/bin/failsafe/su",
    "/system/app/Superuser.apk",
    "/system/usr/we-need-root",
    "magisk", ".magisk", "kernelsu", "ksud",
    "zygisk", "riru",
    nullptr
};

// ── Package names to hide from package manager ───────────────────────────────
static const char* BLOCK_PKGS[] = {
    "com.topjohnwu.magisk",
    "me.weishu.kernelsu",
    "io.github.kernelsu",
    "eu.chainfire.supersu",
    "com.koushikdutta.superuser",
    "com.thirdparty.superuser",
    "com.amphoras.hidemyroot",
    "com.devadvance.rootcloak",
    "com.devadvance.rootcloakplus",
    "com.formyhm.hideroot",
    "com.zachspong.temprootremovejb",
    "com.alephzain.framaroot",
    "com.kingo.root",
    "com.smedialink.oneclickroot",
    nullptr
};

// ── Maps blacklist ────────────────────────────────────────────────────────────
static const char* MAPS_BL[] = {
    "magisk", "zygisk", "riru",
    "kernelsu", "ksud", "uhpro",
    nullptr
};

// ── Originals ─────────────────────────────────────────────────────────────────
static int   (*orig_sysprop)(const char*, char*)       = nullptr;
static int   (*orig_open)   (const char*, int, ...)    = nullptr;
static FILE* (*orig_fopen)  (const char*, const char*) = nullptr;
static int   (*orig_stat)   (const char*, struct stat*)= nullptr;
static int   (*orig_access) (const char*, int)         = nullptr;

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

// ── Hook: sysprop ─────────────────────────────────────────────────────────────
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
        {"service.adb.root",               "0"},
        {"ro.product.model",                SPOOF_MODEL},
        {"ro.product.device",               SPOOF_DEV},
        {"ro.product.brand",                SPOOF_BRAND},
        {"ro.product.manufacturer",         SPOOF_MANU},
        {"ro.build.version.security_patch", SPOOF_PATCH},
        {"ro.product.name",                 "caiman"},
        {"sys.oem_unlock_allowed",          "0"},
        {"ro.build.selinux",                "1"},
        {nullptr, nullptr}
    };

    for (int i = 0; tbl[i].k; i++) {
        if (!strcmp(name, tbl[i].k)) {
            strcpy(value, tbl[i].v);
            return strlen(value);
        }
    }
    return ret;
}

// ── Hook: open ────────────────────────────────────────────────────────────────
static int hook_open(const char* path, int flags, ...) {
    if (shouldBlock(path)) {
        errno = ENOENT;
        return -1;
    }
    va_list ap; va_start(ap, flags);
    mode_t m = va_arg(ap, mode_t); va_end(ap);
    return orig_open(path, flags, m);
}

// ── Hook: fopen — filter /proc/self/maps ──────────────────────────────────────
static FILE* hook_fopen(const char* path, const char* mode) {
    if (path && strstr(path, "/proc/self/maps")) {
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
        FILE* fake = fmemopen(buf, sz, mode);
        return fake;
    }
    if (shouldBlock(path)) { errno = ENOENT; return nullptr; }
    return orig_fopen(path, mode);
}

// ── Hook: stat ───────────────────────────────────────────────────────────────
static int hook_stat(const char* path, struct stat* st) {
    if (shouldBlock(path)) { errno = ENOENT; return -1; }
    return orig_stat(path, st);
}

// ── Hook: access ─────────────────────────────────────────────────────────────
static int hook_access(const char* path, int mode) {
    if (shouldBlock(path)) { errno = ENOENT; return -1; }
    return orig_access(path, mode);
}

// ── Install all hooks ────────────────────────────────────────────────────────
static void installHooks() {
    void* libc = dlopen("libc.so", RTLD_NOW);
    if (!libc) return;
    orig_sysprop = (int(*)(const char*,char*))      dlsym(libc, "__system_property_get");
    orig_open    = (int(*)(const char*,int,...))     dlsym(libc, "open");
    orig_fopen   = (FILE*(*)(const char*,const char*))dlsym(libc, "fopen");
    orig_stat    = (int(*)(const char*,struct stat*)) dlsym(libc, "stat");
    orig_access  = (int(*)(const char*,int))          dlsym(libc, "access");
    dlclose(libc);
    LOGI("Hooks installed");
}

// ── Zygisk module ─────────────────────────────────────────────────────────────
class UniversalHide : public zygisk::ModuleBase {
public:
    void onLoad(Api* api, JNIEnv* env) override {
        this->api = api; this->env = env;
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
