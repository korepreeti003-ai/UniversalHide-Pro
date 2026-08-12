#!/system/bin/sh
# UniversalHide Pro - background service
# Runs after boot, keeps props enforced

MODDIR=${0%/*}
LOG=/data/local/tmp/uhide.log

echo "[$(date)] UniversalHide Pro service started" >> $LOG

# Re-enforce critical props at runtime
resetprop ro.boot.verifiedbootstate green
resetprop ro.boot.flash.locked 1
resetprop ro.boot.vbmeta.device_state locked
resetprop ro.build.tags release-keys
resetprop ro.build.type user
resetprop ro.debuggable 0
resetprop ro.secure 1
resetprop service.adb.root 0
resetprop ro.build.fingerprint "google/caiman/caiman:14/AD1A.240905.004/12196292:user/release-keys"
resetprop ro.product.model "Pixel 9 Pro"
resetprop ro.product.device caiman
resetprop ro.build.version.security_patch 2024-09-05

echo "[$(date)] Props enforced" >> $LOG
