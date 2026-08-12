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

struct api_table {
    void*    impl;
    bool   (*registerModule)    (api_table*, struct ModuleBase*);
    void   (*setOption)         (api_table*, Option);
    int    (*getModuleDir)      (api_table*);
    uint32_t (*getFlags)        (api_table*);
    bool   (*exemptFd)          (api_table*, int);
    int    (*connectCompanion)  (api_table*);
    void   (*registerModuleFunc)(api_table*, void(*)(int));
};

struct Api {
    api_table* tbl;

    void setOption(Option o)                        { tbl->setOption(tbl, o); }
    int  getModuleDir()                             { return tbl->getModuleDir(tbl); }
    uint32_t getFlags()                             { return tbl->getFlags(tbl); }
    bool exemptFd(int fd)                           { return tbl->exemptFd(tbl, fd); }
    int  connectCompanion()                         { return tbl->connectCompanion(tbl); }
    void registerModuleFunc(void(*f)(int))          { tbl->registerModuleFunc(tbl, f); }
};

struct ModuleBase {
    virtual void onLoad              (Api*, JNIEnv*)               {}
    virtual void preAppSpecialize    (AppSpecializeArgs*)           {}
    virtual void postAppSpecialize   (const AppSpecializeArgs*)     {}
    virtual void preServerSpecialize (ServerSpecializeArgs*)        {}
    virtual void postServerSpecialize(const ServerSpecializeArgs*)  {}
    virtual ~ModuleBase() = default;
};

} // namespace zygisk

#define REGISTER_ZYGISK_MODULE(clazz)                                        \
    __attribute__((visibility("default")))                                   \
    extern "C" void zygisk_module_entry(                                     \
            zygisk::api_table* tbl, JNIEnv* env) {                          \
        zygisk::Api* api = new zygisk::Api();                                \
        api->tbl = tbl;                                                      \
        zygisk::ModuleBase* mod = new clazz();                               \
        tbl->registerModule(tbl, mod);                                       \
        mod->onLoad(api, env);                                               \
}
