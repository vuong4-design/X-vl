# ProjectXInject — substrate-free injected dylib for TrollStore modes.

TARGET := iphone:clang:16.5:14.0
ARCHS := arm64 arm64e

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = ProjectXInject

ProjectXInject_FILES = ProjectXInject.m
ProjectXInject_CFLAGS = -fobjc-arc -D PROJECTX_INJECT=1
ProjectXInject_FRAMEWORKS = Foundation UIKit
ProjectXInject_LDFLAGS = -Wl,-no_fixup_chains
ProjectXInject_CODESIGN_FLAGS = -SProjectXInject.entitlements.plist
ProjectXInject_INSTALL_PATH = /usr/lib

include $(THEOS_MAKE_PATH)/library.mk
