TARGET := iphone:clang:16.5:12.0
ARCHS = arm64 arm64e
LOGOS_DEFAULT_GENERATOR = internal
INSTALL_TARGET_PROCESSES = SpringBoard ProjectX
DEBUG=1
FINALPACKAGE=0

# Note: This project now includes a Notification Service Extension for rich push notifications
# The extension needs to be manually added in Xcode after installing this package
# See /NotificationServiceExtension/README.md for integration instructions

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = ProjectX
TOOL_NAME = WeaponXDaemon backup_helper



# App files
ProjectX_FILES = $(wildcard *.m) $(wildcard common/*.m)
ProjectX_RESOURCE_DIRS = Assets.xcassets
ProjectX_RESOURCE_FILES = Info.plist Icon.png LaunchScreen.storyboard
ProjectX_PRIVATE_FRAMEWORKS = FrontBoardServices SpringBoardServices BackBoardServices StoreKitUI MobileCoreServices
# ProjectX_LDFLAGS = -I./common
ProjectX_FRAMEWORKS = Foundation MobileCoreServices CoreServices StoreKit IOKit CoreLocation
# UIKit, Security and CoreLocationUI are weak-linked for iOS 12+ compatibility
# UIButtonConfiguration and SecTrustCopyCertificateChain are iOS 15+ only
ProjectX_LDFLAGS = -weak_framework UIKit -weak_framework CoreLocationUI -weak_framework Security -lsqlite3
ProjectX_CODESIGN_FLAGS = -Sent.plist
ProjectX_CFLAGS = -fobjc-arc -D SUPPORT_IPAD=1 -D ENABLE_STATE_RESTORATION=1 -I./common

# Daemon files
WeaponXDaemon_FILES = WeaponXMountDaemon/WeaponXDaemon.m common/PXRoot.m
WeaponXDaemon_CFLAGS = -fobjc-arc -I./common
WeaponXDaemon_FRAMEWORKS = Foundation IOKit
WeaponXDaemon_INSTALL_PATH = /Library/WeaponX
WeaponXDaemon_CODESIGN_FLAGS = -Sent.plist
WeaponXDaemon_LDFLAGS = -framework IOKit

# Keychain Helper Tool - CLI for backup/restore/wipe keychain items
backup_helper_FILES = KeychainHelper/backup_helper.m KeychainHelper/KeychainBackupHelper.m
backup_helper_CFLAGS = -fobjc-arc -Wno-error=unused-variable
backup_helper_FRAMEWORKS = Foundation Security
backup_helper_INSTALL_PATH = /Library/WeaponX
backup_helper_CODESIGN_FLAGS = -Skeychain_base_ent.plist

# Ensure app is installed to the correct location with proper permissions
ProjectX_INSTALL_PATH = /Applications
ProjectX_APPLICATION_MODE = 0755

# Make sure both tweak and application are built
all::
	@echo "Building tweak, application, and daemon..."

# Tweak Configuration (Moved from ProjectXTweak/Makefile)
TWEAK_NAME = ProjectXTweak WeaponXKeychainBridge

# Files - Adjusted paths for root compilation
ProjectXTweak_FILES = $(wildcard ProjectXTweak/*.x) $(wildcard ProjectXTweak/*.m) $(wildcard common/*.m)

# CFlags - Adjusted include paths
ProjectXTweak_CFLAGS = -fobjc-arc -Wno-error=unused-variable -Wno-error=unused-function -I./common -I./include -D USES_LIBUNDIRECT=1 -D SUPPORT_IPAD=1 -D ENABLE_STATE_RESTORATION=1

# Frameworks and Libraries
ProjectXTweak_FRAMEWORKS = UIKit Foundation AdSupport UserNotifications IOKit Security CoreLocation CoreFoundation Network CoreTelephony SystemConfiguration WebKit SafariServices   
ProjectXTweak_PRIVATE_FRAMEWORKS = MobileCoreServices AppSupport SpringBoardServices 
ProjectXTweak_LIBRARIES = MobileGestalt

# Linker Flags
# -lobjc: force link libobjc
# -Wl,-ObjC: load all ObjC classes/categories
# -Wl,-no_fixup_chains: DISABLE chained fixups (Xcode 15+ default) which break iOS 12/13 compatibility
# -Wl,-undefined,dynamic_lookup: standard for tweaks
ProjectXTweak_LDFLAGS = -lobjc -Wl,-ObjC -Wl,-no_fixup_chains -Wl,-undefined,dynamic_lookup

# Keychain Bridge Tweak (minimal, in-app keychain export/import)
WeaponXKeychainBridge_FILES = WeaponXKeychainBridge/Tweak.m
WeaponXKeychainBridge_CFLAGS = -fobjc-arc -Wno-error=unused-variable -Wno-error=unused-function
WeaponXKeychainBridge_FRAMEWORKS = Foundation Security CoreFoundation
WeaponXKeychainBridge_LDFLAGS = -lobjc -Wl,-ObjC -Wl,-no_fixup_chains -Wl,-undefined,dynamic_lookup

# Include makefiles
include $(THEOS_MAKE_PATH)/application.mk
include $(THEOS_MAKE_PATH)/tweak.mk
include $(THEOS_MAKE_PATH)/tool.mk

# Custom rule to ensure our scripts are included in the package
internal-stage::
	@echo "Adding custom scripts to package..."
	@mkdir -p $(THEOS_STAGING_DIR)/DEBIAN
	@cp -a DEBIAN/postinst $(THEOS_STAGING_DIR)/DEBIAN/
	@cp -a DEBIAN/preinst $(THEOS_STAGING_DIR)/DEBIAN/
	@cp -a DEBIAN/prerm $(THEOS_STAGING_DIR)/DEBIAN/
	@chmod 755 $(THEOS_STAGING_DIR)/DEBIAN/postinst
	@chmod 755 $(THEOS_STAGING_DIR)/DEBIAN/preinst
	@chmod 755 $(THEOS_STAGING_DIR)/DEBIAN/prerm
	@echo "Adding setup script to package..."
	@mkdir -p $(THEOS_STAGING_DIR)/usr/bin
	@cp -a setup_app.sh $(THEOS_STAGING_DIR)/usr/bin/projectx-setup
	@chmod 755 $(THEOS_STAGING_DIR)/usr/bin/projectx-setup
	@echo "Creating MobileSubstrate directories for compatibility..."
	@mkdir -p $(THEOS_STAGING_DIR)/Library/MobileSubstrate/DynamicLibraries/
	@cp -a $(THEOS_OBJ_DIR)/ProjectXTweak.* $(THEOS_STAGING_DIR)/Library/MobileSubstrate/DynamicLibraries/
	@cp -a $(THEOS_OBJ_DIR)/WeaponXKeychainBridge.* $(THEOS_STAGING_DIR)/Library/MobileSubstrate/DynamicLibraries/
	@echo "Ensuring LaunchScreen.storyboard is properly compiled..."
	@if [ -f "LaunchScreen.storyboard" ]; then \
		mkdir -p $(THEOS_STAGING_DIR)/Applications/ProjectX.app/; \
		ibtool --compile $(THEOS_STAGING_DIR)/Applications/ProjectX.app/LaunchScreen.storyboardc LaunchScreen.storyboard || true; \
		cp -a LaunchScreen.storyboard $(THEOS_STAGING_DIR)/Applications/ProjectX.app/; \
	fi
	@echo "Adding LaunchDaemon for persistent operation..."
	@mkdir -p $(THEOS_STAGING_DIR)/Library/LaunchDaemons
	@mkdir -p $(THEOS_STAGING_DIR)/Library/WeaponX/Guardian
	@mkdir -p $(THEOS_STAGING_DIR)/var/mobile/Library/Preferences
	@cp -a com.hydra.weaponx.guardian.plist $(THEOS_STAGING_DIR)/Library/LaunchDaemons/
	@chmod 644 $(THEOS_STAGING_DIR)/Library/LaunchDaemons/com.hydra.weaponx.guardian.plist
	@chmod 755 $(THEOS_STAGING_DIR)/Library/WeaponX
	@chmod 755 $(THEOS_STAGING_DIR)/Library/WeaponX/Guardian
	@touch $(THEOS_STAGING_DIR)/Library/WeaponX/Guardian/daemon.log
	@touch $(THEOS_STAGING_DIR)/Library/WeaponX/Guardian/guardian-stdout.log
	@touch $(THEOS_STAGING_DIR)/Library/WeaponX/Guardian/guardian-stderr.log
	@chmod 664 $(THEOS_STAGING_DIR)/Library/WeaponX/Guardian/*.log
	@echo "Installing WeaponXDaemon..."
	@cp -a $(THEOS_OBJ_DIR)/WeaponXDaemon $(THEOS_STAGING_DIR)/Library/WeaponX/
	@chmod 755 $(THEOS_STAGING_DIR)/Library/WeaponX/WeaponXDaemon
	@echo "Installing backup_helper tool..."
	@cp -a $(THEOS_OBJ_DIR)/backup_helper $(THEOS_STAGING_DIR)/Library/WeaponX/
	@chmod 755 $(THEOS_STAGING_DIR)/Library/WeaponX/backup_helper
	@echo "Installing keychain backup script..."
	@cp -a scripts/keychain_backup.sh $(THEOS_STAGING_DIR)/Library/WeaponX/
	@chmod 755 $(THEOS_STAGING_DIR)/Library/WeaponX/keychain_backup.sh
	@echo "Adding debug tools..."
	@mkdir -p $(THEOS_STAGING_DIR)/usr/bin
	@cp -a weaponx-debug.sh $(THEOS_STAGING_DIR)/usr/bin/weaponx-debug
	@chmod 755 $(THEOS_STAGING_DIR)/usr/bin/weaponx-debug

export CFLAGS = -fobjc-arc -Wno-error

ProjectXCLI_FILES = ProjectXCLIbinary.m DeviceNameManager.m IdentifierManager.m IDFAManager.m IDFVManager.m WiFiManager.m SerialNumberManager.m ProjectXLogging.m ProfileManager.m IOSVersionInfo.m
ProjectXCLI_CFLAGS = -fobjc-arc -Wno-error=unused-variable -Wno-error=unused-function -I$(THEOS_VENDOR_INCLUDE_PATH)
ProjectXCLI_FRAMEWORKS = UIKit Foundation AdSupport UserNotifications IOKit Security
ProjectXCLI_PRIVATE_FRAMEWORKS = MobileCoreServices AppSupport
ProjectXCLI_LDFLAGS = -L$(THEOS_VENDOR_LIBRARY_PATH)

after-package::
	@echo "🔍 Checking package contents..."
	@mkdir -p $(THEOS_STAGING_DIR)/../debug
	@PACKAGE_FILE="$$(ls -t ./packages/com.hydra.projectx_*_iphoneos-arm.deb | head -1)" && \
	if [ -f "$$PACKAGE_FILE" ]; then \
		echo "Extracting $$PACKAGE_FILE"; \
		(cd $(THEOS_STAGING_DIR)/../debug && ar -x "../../$$PACKAGE_FILE" && tar -xf data.tar.*); \
	else \
		echo "❌ Package file not found!"; \
		exit 1; \
	fi
	@echo "✅ Checking WeaponXDaemon executable..."
	@ls -la $(THEOS_STAGING_DIR)/../debug/Library/WeaponX/WeaponXDaemon || echo "❌ WeaponXDaemon not found!"
	@echo "✅ Checking LaunchDaemon plist..."
	@ls -la $(THEOS_STAGING_DIR)/../debug/Library/LaunchDaemons/com.hydra.weaponx.guardian.plist || echo "❌ LaunchDaemon plist not found!"
	@echo "✅ Checking Guardian directory and log files..."
	@ls -la $(THEOS_STAGING_DIR)/../debug/Library/WeaponX/Guardian/ || echo "❌ Guardian directory not found!"
	@echo "Package check completed!"

# SUBPROJECTS += ProjectXTweak
# include $(THEOS_MAKE_PATH)/aggregate.mk
