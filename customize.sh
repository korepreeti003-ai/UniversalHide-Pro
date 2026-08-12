#!/system/bin/sh
SKIPUNZIP=1

ui_print "━━━━━━━━━━━━━━━━━━━━━━━━━━"
ui_print "   UniversalHide Pro v1.0"
ui_print "   by Temu"
ui_print "━━━━━━━━━━━━━━━━━━━━━━━━━━"

MODEL=$(getprop ro.product.model)
API=$(getprop ro.build.version.sdk)
ui_print "[-] Device : $MODEL"
ui_print "[-] API    : $API"

if [ "$ZYGISK_ENABLED" != "1" ]; then
    ui_print "[!] Zygisk not enabled!"
    abort "Enable Zygisk in Magisk settings first"
fi

mkdir -p "$MODPATH/zygisk"
unzip -o "$ZIPFILE" "zygisk/arm64-v8a.so"   -d "$MODPATH"
unzip -o "$ZIPFILE" "zygisk/armeabi-v7a.so" -d "$MODPATH"

mkdir -p "$MODPATH/system/etc/props"

PIXEL_FP="google/caiman/caiman:14/AD1A.240905.004/12196292:user/release-keys"

cat > "$MODPATH/system/etc/props/uhide.prop" << EOF
ro.boot.verifiedbootstate=green
ro.boot.flash.locked=1
ro.boot.vbmeta.device_state=locked
ro.build.tags=release-keys
ro.build.type=user
ro.debuggable=0
ro.secure=1
ro.adb.secure=1
service.adb.root=0
ro.build.fingerprint=$PIXEL_FP
ro.build.id=AD1A.240905.004
ro.product.device=caiman
ro.product.name=caiman
ro.product.model=Pixel 9 Pro
ro.build.version.security_patch=2024-09-05
EOF

cp "$MODPATH/service.sh" "$MODPATH/service.sh"
set_perm_recursive "$MODPATH" root root 0755 0644
set_perm "$MODPATH/service.sh" root root 0755
set_perm "$MODPATH/customize.sh" root root 0755

ui_print "[+] Zygisk module installed"
ui_print "[+] Props injected"
ui_print "[✓] UniversalHide Pro ready!"
ui_print "[!] Reboot to activate"
