# weaponx_root_helper — Theos makefile for the bundled root helper.
#
# Builds a tiny standalone tool that is embedded in the main app bundle and
# declared in its TSRootBinaries. It is invoked as root via TrollStore's
# spawnRoot: (see PXRootHelper). After building, the binary must be code-signed
# with helper/entitlements.plist using ldid:
#
#   ldid -Sentitlements.plist .theos/obj/weaponx_root_helper
#
# then copied into the app bundle root and listed under TSRootBinaries in the
# app's Info.plist.

TARGET := iphone:clang:16.5:14.0
ARCHS := arm64 arm64e

include $(THEOS)/makefiles/common.mk

TOOL_NAME = weaponx_root_helper

weaponx_root_helper_FILES = main.m
weaponx_root_helper_CFLAGS = -fobjc-arc
weaponx_root_helper_FRAMEWORKS = Foundation
weaponx_root_helper_CODESIGN_FLAGS = -Sentitlements.plist
weaponx_root_helper_INSTALL_PATH = /

include $(THEOS)/makefiles/tool.mk
