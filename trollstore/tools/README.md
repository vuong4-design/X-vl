Place optional TrollStore helper tools here.

Supported filenames:

- cp
- cp-15
- mv
- mv-15
- rm
- ldid
- ct_bypass
- insert_dylib
- install_name_tool
- libiosexec.1.dylib
- libintl.8.dylib
- libcrypto.3.dylib
- libxar.1.dylib

The app build copies these files into ProjectXTroll.app/Tools when present. The root helper looks in that directory before system paths.

The helper prefers cp-15 over cp because older iOS 15/16 libSystem builds may not export symbols required by newer cp binaries.
