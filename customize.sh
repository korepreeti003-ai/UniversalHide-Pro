#!/system/bin/sh

SKIPUNZIP=1
MODPATH="$MODPATH"

ui_print "━━━━━━━━━━━━━━━━━━━━━━━━━━"
ui_print "   UniversalHide Pro v1.0"
ui_print "   by Temu"
ui_print "━━━━━━━━━━━━━━━━━━━━━━━━━━"

unzip -o "$ZIPFILE" 'zygisk/*' -d "$MODPATH" >&2

mkdir -p "$MODPATH/system/etc/props"

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
ro.build.fingerprint=google/caiman/caiman:14/AD1A.240905.004/12196292:user/release-keys
ro.build.id=AD1A.240905.004
ro.product.device=caiman
ro.product.name=caiman
ro.product.model=Pixel 9 Pro
ro.build.version.security_patch=2024-09-05
EOF

set_perm_recursive "$MODPATH" root root 0755 0644

ui_print "[✓] Done! Reboot to activate"
