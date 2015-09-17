/*
 * FILE: bootcaches.h
 * AUTH: Soren Spies (sspies)
 * DATE: "spring" 2006
 * DESC: routines for dealing with bootcaches.plist data, bootstamps, etc
 *	 shared between kextcache and kextd
 *
 */

#ifndef __BOOTROOT_H__
#define __BOOTROOT_H__

#include <CoreFoundation/CoreFoundation.h>
#include <DiskArbitration/DiskArbitration.h>
#include <sys/stat.h>
#include <sys/time.h>

// timestamp directory
#define kTSCacheDir         "/System/Library/Caches/com.apple.bootstamps/"
#define kTSCacheMask	    0755	// Sec reviewed
#define kRPSDirMask	    0755

// bootcaches.plist and keys
#define kBootCachesPath     "/usr/standalone/bootcaches.plist"
#define kBCPreBootKey		    CFSTR("PreBootPaths")    // dict
#define kBCLabelKey		    CFSTR("DiskLabel")	     // ".disk_label"
#define kBCBootersKey		    CFSTR("BooterPaths")     // dict
#define kBCEFIBooterKey		    CFSTR("EFIBooter")	     // "boot.efi"
// #define kBCOFBooterKey	    CFSTR("OFBooter")	     // "BootX"
#define kBCPostBootKey		    CFSTR("PostBootPaths")   // dict
#define kBCMKextKey                 CFSTR("MKext")           // dict
#define kBCArchsKey                 CFSTR("Archs")           //   ar: ppc, i386
#define kBCExtensionsDirKey         CFSTR("ExtensionsDir")   //   /S/L/E
#define kBCPathKey                  CFSTR("Path")            //   /S/L/E.mkext
#define kBCAdditionalPathsKey       CFSTR("AdditionalPaths") // array
#define kBCBootConfigKey            CFSTR("BootConfig")      // path string

typedef enum {
    kMkextCRCError = -1,
    kMkextCRCFound = 0,
    kMkextCRCNotFound = 1,
} MkextCRCResult;

// utility routines
Boolean isBootRoot(char *volroot, Boolean *isGPT);
Boolean bootedFromDifferentMkext(void);
Boolean bootedFromDifferentKernel(void);

// for kextcache and watchvol.c
typedef struct {
    char rpath[PATH_MAX];       // real path in the root filesystem
    char tspath[PATH_MAX];      // shadow timestamp path tracking Apple_Boot[s]
    struct timeval tstamps[2];  // rpath's initial timestamp(s)
} cachedPath;

struct bootCaches {
    int cachefd;		// Sec: file descriptor to validate data
    CFStringRef volUUIDStr;	// from diskarb
    char volname[NAME_MAX];     // for label
    char root[PATH_MAX];	// needed to create absolute paths
    CFDictionaryRef cacheinfo;  // raw BootCaches.plist data (for archs, etc)

    char exts[PATH_MAX];        // /Volumes/foo/S/L/E (watch only; no update)
    int nrps;                   // number of RPS paths Apple_Boot
    cachedPath *rpspaths;       // e.g. mkext, kernel, Boot.plist 
    int nmisc;			// "other" files (non-critical)
    cachedPath *miscpaths;	// e.g. icons, labels, etc
    cachedPath efibooter;	// booters get their own paths
    cachedPath ofbooter;	// (we have to bless them, etc)

    // pointers to special watched paths
    cachedPath *mkext;          // -> /Volumes/foo/S/L/E.mkext (in rpsPaths)
    cachedPath *bootconfig;	// -> .../L/Prefs/SC/com.apple.Boot.plist
    cachedPath *label;		// -> .../S/L/CS/.disk_label (in miscPaths)
};

// ctors / dtors
struct bootCaches* readCaches(char *volroot);
void destroyCaches(struct bootCaches *caches);
int fillCachedPath(cachedPath *cpath, char *uuidchars, char *relpath);

// "stat" a cachedPath, setting tstamp, logging errors
int needsUpdate(char *root, cachedPath* cpath, Boolean *outofdate);
// check all cached paths w/needsUpdate (exts/mkext not checked)
int needUpdates(struct bootCaches *caches, Boolean *any,
		    Boolean *rps, Boolean *booters, Boolean *misc);
// apply the stored timestamps to the bootstamps (?unless the source changed?)
int applyStamps(struct bootCaches *caches);

// fork_kextcache handles wait-free launch/cleanup (and kextcache bugs ;)
// returns pid if !wait; WEXITSTATUS otherwis
int fork_kextcache(char *cacheRoot, char *argv[], Boolean wait);
// check to see if the mkext needs rebuilding
Boolean check_mkext(struct bootCaches *caches);
// build the mkext; waiting if instructed
int rebuild_mkext(struct bootCaches *caches, Boolean wait);

// generic diskarb helper
void _daDone(DADiskRef disk, DADissenterRef dissenter, void *ctx);

#endif /* __BOOTROOT_H__ */
