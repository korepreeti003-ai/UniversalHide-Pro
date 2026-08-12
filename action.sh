#!/system/bin/sh
# UniversalHide Pro - Action
am start -a android.intent.action.VIEW \
    -n com.android.settings/.Settings \
    --es "title" "UniversalHide Active" 2>/dev/null

# Re-enforce props
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

echo "UniversalHide: Props enforced!"
