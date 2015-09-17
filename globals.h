#ifndef __GLOBALS_H__
#define __GLOBALS_H__

// XX should be named kextd_globals.h or similar
// currently not suitable for sharing with other tools

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <libc.h>

#include <IOKit/kext/KXKextManager.h>
#include "request.h"
#include "PTLock.h"

// in main.c
void kextd_handle_sighup(int);

extern char * progname;
extern int g_verbose_level;

extern char * g_kernel_file;
extern char * g_patch_dir;
extern char * g_symbol_dir;
extern Boolean gOverwrite_symbols;

extern Boolean g_safe_boot_mode;

extern Boolean gStaleStartupMkext;
extern Boolean gStaleKernel;

extern mach_port_t g_io_master_port;

extern KXKextManagerRef gKextManager;

extern CFRunLoopRef gMainRunLoop;
extern CFRunLoopSourceRef gKernelRequestRunLoopSource;
extern CFRunLoopSourceRef gRescanRunLoopSource;
//extern CFRunLoopSourceRef gClientRequestRunLoopSource;       // XX not global?
extern CFRunLoopSourceRef gCurrentNotificationRunLoopSource;

extern PTLockRef gKernelRequestQueueLock;
extern PTLockRef gRunLoopSourceLock;

extern queue_head_t g_request_queue;

// in request.c
#ifndef NO_CFUserNotification

extern CFRunLoopSourceRef gNotificationQueueRunLoopSource;
extern CFMutableArrayRef gPendedNonsecureKextPaths; // alerts to be raised on user login
extern CFMutableDictionaryRef gNotifiedNonsecureKextPaths;
extern CFUserNotificationRef gCurrentNotification;

#endif /* NO_CFUserNotification */

extern uid_t logged_in_uid;

// in mig_server.c
extern uid_t gClientUID;

#endif __GLOBALS_H__
