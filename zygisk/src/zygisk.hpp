#pragma once
#include <jni.h>
#include <cstdint>

#define ZYGISK_API_VERSION 4

namespace zygisk {

struct AppSpecializeArgs {
    jint&        uid;
    jint&        gid;
    jintArray&   gids;
    jint&        runtime_flags;
    jint&        mount_external;
    jstring&     se_info;
    jstring&     nice_name;
    jstring&     instruction_set;
    jstring&     app_data_dir;
    jboolean*    is_child_zygote;
    jboolean*    is_top_app;
    jobjectArray* pkg_data_info_list;
    jobjectArray* whitelisted_data_info_list;
    jboolean*    mount_data_dirs;
    jboolean*    mount_storage_dirs;
    AppSpecializeArgs() = delete;
};

struct ServerSpecializeArgs {
    jint&  uid;
    jint&  gid;
    jintArray& gids;
    jint&  runtime_flags;
    jlong& permitted_capabilities;
    jlong& effective_capabilities;
    ServerSpecializeArgs() = delete;
};

enum class Option : int {
    FORCE_DENYLIST_UNMOUNT = 0,
    DLCLOSE_MODULE_LIBRARY = 1,
};

namespace internal { struct api_table; }

struct Api {
    int      connectCompanion() const;
    int      getModuleDir()     const;
    void     setOption(Option);
    uint32_t getFlags()         const;
    bool     exemptFd(int fd)   const;
    void     registerModuleFunc(void (*func)(int)) const;
private:
    internal::api_table* tbl;
    friend struct internal::api_table;
};

struct ModuleBase {
    virtual void onLoad              (Api*, JNIEnv*)               {}
    virtual void preAppSpecialize    (AppSpecializeArgs*)           {}
    virtual void postAppSpecialize   (const AppSpecializeArgs*)     {}
    virtual void preServerSpecialize (ServerSpecializeArgs*)        {}
    virtual void postServerSpecialize(const ServerSpecializeArgs*)  {}
    virtual ~ModuleBase() = default;
};

namespace internal {
struct api_table {
    void*    impl;
    bool   (*registerModule)    (api_table*, ModuleBase*);
    void   (*setOption)         (api_table*, Option);
    int    (*getModuleDir)      (api_table*);
    uint32_t (*getFlags)        (api_table*);
    bool   (*exemptFd)          (api_table*, int);
    int    (*connectCompanion)  (api_table*);
    void   (*registerModuleFunc)(api_table*, void(*)(int));
};
inline void     Api::setOption(Option o)             { tbl->setOption(tbl, o); }
inline int      Api::getModuleDir() const            { return tbl->getModuleDir(tbl); }
inline uint32_t Api::getFlags()     const            { return tbl->getFlags(tbl); }
inline bool     Api::exemptFd(int fd) const          { return tbl->exemptFd(tbl, fd); }
inline int      Api::connectCompanion() const        { return tbl->connectCompanion(tbl); }
inline void     Api::registerModuleFunc(void(*f)(int)) const { tbl->registerModuleFunc(tbl, f); }
}
}

#define REGISTER_ZYGISK_MODULE(clazz)                                               \
    __attribute__((visibility("default")))                                          \
    extern "C" void zygisk_module_entry(                                            \
            zygisk::internal::api_table* tbl, JNIEnv* env) {                       \
        auto* api = reinterpret_cast<zygisk::Api*>(new char[sizeof(zygisk::Api)]); \
        reinterpret_cast<zygisk::internal::api_table**>(api)[0] = tbl;             \
        auto* mod = new clazz();                                                    \
        tbl->registerModule(tbl, mod);                                              \
        mod->onLoad(api, env);                                                      \
}
