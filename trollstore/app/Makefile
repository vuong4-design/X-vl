# trollstore/app/Makefile — TrollStore-only build for ProjectX.
#
# Cô lập hoàn toàn khỏi pipeline jailbreak ở Makefile gốc:
#   - KHÔNG build WeaponXDaemon, LaunchDaemon Guardian.
#   - KHÔNG build ProjectXTweak / WeaponXKeychainBridge (cần MobileSubstrate).
#   - KHÔNG cài keychain_backup.sh.
#
# Build:
#   cd trollstore/app && make package
#
# Sản phẩm: ProjectXTroll.app — đóng gói cho TrollStore, gồm:
#   - app binary (Objective-C app code từ thư mục gốc + trollstore/ primitives)
#   - weaponx_root_helper (build từ trollstore/helper/Makefile, copy vào bundle root)
#   - TSRootBinaries khai báo trong Info.plist của app

TARGET := iphone:clang:16.5:14.0
ARCHS = arm64 arm64e
INSTALL_TARGET_PROCESSES = ProjectXTroll
DEBUG = 1
FINALPACKAGE = 0

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = ProjectXTroll

# Paths relative to this Makefile (trollstore/app/).
REPO_ROOT = ../..
TROLLSTORE_DIR = ..

# App source files: pull every .m from repo root + common/ + the trollstore
# primitives we wired in. Explicit list to avoid sweeping in PXShellRouter.m
# (header-only until G2) or files that depend on TSUtil internals.
ProjectXTroll_FILES = \
	$(wildcard $(REPO_ROOT)/*.m) \
	$(wildcard $(REPO_ROOT)/common/*.m) \
	$(TROLLSTORE_DIR)/PXArchive.m \
	$(TROLLSTORE_DIR)/PXDiagnostics.m \
	$(TROLLSTORE_DIR)/PXDYLDLauncher.m \
	$(TROLLSTORE_DIR)/PXShellRouter.m \
	$(TROLLSTORE_DIR)/PXEntitlements.m \
	$(TROLLSTORE_DIR)/PXFileOps.m \
	$(TROLLSTORE_DIR)/PXInPlacePatcher.m \
	$(TROLLSTORE_DIR)/PXMachOInjector.m \
	$(TROLLSTORE_DIR)/PXRootHelper.m \
	$(TROLLSTORE_DIR)/PXRuntimeSnapshot.m \
	$(TROLLSTORE_DIR)/TSUtil.m

ProjectXTroll_RESOURCE_DIRS = $(REPO_ROOT)/Assets.xcassets
ProjectXTroll_RESOURCE_FILES = \
	Info.plist \
	$(REPO_ROOT)/Icon.png \
	$(REPO_ROOT)/LaunchScreen.storyboard

ProjectXTroll_PRIVATE_FRAMEWORKS = \
	FrontBoardServices \
	SpringBoardServices \
	BackBoardServices \
	StoreKitUI \
	MobileCoreServices

ProjectXTroll_FRAMEWORKS = \
	Foundation \
	MobileCoreServices \
	CoreServices \
	StoreKit \
	IOKit \
	CoreLocation

# UIKit, Security, CoreLocationUI weak-linked (iOS 14+ TrollStore target,
# but keeping parity with root Makefile minimizes surprise).
ProjectXTroll_LDFLAGS = \
	-weak_framework UIKit \
	-weak_framework CoreLocationUI \
	-weak_framework Security \
	-lz \
	-lsqlite3

# Codesign with TrollStore-specific entitlements. Keep this separate from the
# jailbreak/rootful entitlements so packaging can verify the exact signed keys.
ProjectXTroll_CODESIGN_FLAGS = -S$(TROLLSTORE_DIR)/app/entitlements.plist

# Header search paths: app code includes "common/..." and now "PXEntitlements.h".
ProjectXTroll_CFLAGS = \
	-fobjc-arc \
	-D SUPPORT_IPAD=1 \
	-D ENABLE_STATE_RESTORATION=1 \
	-D PROJECTX_TROLLSTORE=1 \
	-Wno-error=unguarded-availability-new \
	-Wno-error=unused-function \
	-Wno-error=unused-variable \
	-Wno-error=unused-but-set-variable \
	-Wno-error=incomplete-implementation \
	-I$(REPO_ROOT) \
	-I$(REPO_ROOT)/common \
	-I$(TROLLSTORE_DIR)

ProjectXTroll_INSTALL_PATH = /Applications
ProjectXTroll_APPLICATION_MODE = 0755

include $(THEOS_MAKE_PATH)/application.mk

# After staging the app bundle, drop the root helper alongside the executable
# and declare it in TSRootBinaries so TrollStore signs it as embedded uid-0.
#
# Build the helper first (from trollstore/helper/Makefile), then copy its
# output binary into the app bundle root.
internal-stage::
	@echo "Installing TrollStore Info.plist..."
	@cp Info.plist $(THEOS_STAGING_DIR)/Applications/ProjectXTroll.app/Info.plist
	@echo "Building root helper..."
	@$(MAKE) -C $(TROLLSTORE_DIR)/helper clean all messages=yes FINALPACKAGE=0 || (echo "Helper build failed" && exit 1)
	@echo "Installing root helper into app bundle..."
	@HELPER_BIN="$$(find $(TROLLSTORE_DIR)/helper $(THEOS_OBJ_DIR) .theos -type f -name weaponx_root_helper 2>/dev/null | head -n 1)"; \
	if [ ! -f "$$HELPER_BIN" ]; then \
		echo "weaponx_root_helper binary not found after build"; \
		echo "Searched helper tree and app .theos output:"; \
		find $(TROLLSTORE_DIR)/helper .theos -maxdepth 8 -print 2>/dev/null || true; \
		exit 1; \
	fi; \
	echo "Using helper binary: $$HELPER_BIN"; \
	cp "$$HELPER_BIN" $(THEOS_STAGING_DIR)/Applications/ProjectXTroll.app/weaponx_root_helper; \
	chmod 755 $(THEOS_STAGING_DIR)/Applications/ProjectXTroll.app/weaponx_root_helper
	@echo "Building ProjectXInject dylib..."
	@$(MAKE) -C $(TROLLSTORE_DIR)/inject clean all messages=yes FINALPACKAGE=0 || (echo "ProjectXInject build failed" && exit 1)
	@echo "Installing ProjectXInject dylib into app bundle..."
	@INJECT_DYLIB="$$(find $(TROLLSTORE_DIR)/inject $(THEOS_OBJ_DIR) .theos -type f \( -name ProjectXInject.dylib -o -name libProjectXInject.dylib -o -name '*ProjectXInject*.dylib' \) 2>/dev/null | head -n 1)"; \
	if [ ! -f "$$INJECT_DYLIB" ]; then \
		echo "ProjectXInject.dylib not found after build"; \
		echo "Searched for ProjectXInject.dylib / libProjectXInject.dylib under inject tree and app .theos output:"; \
		find $(TROLLSTORE_DIR)/inject .theos -maxdepth 8 -print 2>/dev/null || true; \
		exit 1; \
	fi; \
	echo "Using inject dylib: $$INJECT_DYLIB"; \
	cp "$$INJECT_DYLIB" $(THEOS_STAGING_DIR)/Applications/ProjectXTroll.app/ProjectXInject.dylib; \
	chmod 755 $(THEOS_STAGING_DIR)/Applications/ProjectXTroll.app/ProjectXInject.dylib
	@echo "TSRootBinaries declared in trollstore/app/Info.plist"
