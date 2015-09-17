/*
 * FILE: watchvol.c
 * AUTH: Soren Spies (sspies)
 * DATE: 5 March 2006
 * DESC: watch volumes as they come, go, or are changed, fire rebuilds
 *       NOTE: everything in this file should happen on the main thread
 *
 * Here's roughly how it all works.
 * 1. sign up for diskarb notifications
 * 2. generate a data structure for each incoming comprehensible OS volume
 * 2a. set up notifications for all relevant paths on said volume
 *     [notifications <-> structures]
 * (2) uses bootcaches.plist to describe what caches a system needs.
 *     All top-level keys are assumed required (which means the mkext could
 *     get fancier in the future if an old-fashioned mkext was still okay).
 *     If keys exist that can't be understood or don't parse correctly, 
 *     we bail on watching that volume.
 *
 * 3. intelligently respond to notifications
 * 3a. set up a timer to fire so the system has time to settle
 * 3b. upon lazy firing, rebuild caches OR copy files to Apple_Boot
 * 3c. if someone tries to unmount a volume, cancel any timer and check
 * 3d. if a locker unlocks happily, cancel any timer and check  (TODO)
 * 3e. if a locker unlocks unhappily, need to force a check of non-caches? (???)
 * 3f. we don't care if the volume is locked; additional kextcaches wait
 * (3d) has the effect that the first kextcache effectively triggers the
 *      second one which copies caches down.  It also allows us ... to be
 *      smart about things like forcing reboots if we booted from staleness.
 *
 * 4. arbitrate kextcache locks
 * 4a. keep a Mach send right to a receive right in the locker
 * 4b. detect crashes via CFMachPortInvalidaton callback
 * 4c. take success information on unlock
 * 4d. if a lock was lost, force a rebuild (XX)?
 * TODO (still as part of 4252674):
 * (4) means that kextcache rebuilds the mkext (-> scheduling a timer)
 * (4c) means that we can schedule the Apple_Boot check on success (unschedules)
 *
 * 5. keep structures up to date
 * 5a. clean up when a volume goes away
 * 5b. disappear/appear whenever there's a change
 *
 * 6. reboot stuff: take a big lock; free it only if locker dies
 *
 * given that we read bootcaches.plist, we don't trust anything in it
 * ... but we push the checking off to kextcache, which ensures
 * (via dev_t/safecalls) that it is only operating on a single volume and 
 * not being redirected to other volumes, etc.  We have had Security review.
 *
 * XX we need to figure out what to do about ignored owners and UID 99.
 * We don't want to go writing an mkext with uid 99 ... but we do want
 * this scheme to work ... could we temporarily enable owners??
 * The current plan (4554031) is to notice when VQ_UPDATE's occur ...
 * enabling owners ourselves could lead to some very mysterious behavior.
 *	
 * $removing checkin comments expander in the header$
 */

// system includes
#include <notify.h>	// yay notify_monitor_file (well, maybe someday ;)
#include <string.h>	// strerror()
#include <sysexits.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/types.h>	// waitpid() (fork/daemon/waitpid)
#include <sys/wait.h>	// " "
#include <stdlib.h>	// daemon(3)
#include <unistd.h>	// e.g. execv

#include <bless.h>
#include <CoreFoundation/CoreFoundation.h>
#include <DiskArbitration/DiskArbitration.h>
#include <IOKit/kext/kextmanager_types.h>

// notifyd SPI :P (at least the latter two are API for Leopard)
extern uint32_t notify_monitor_file(int token, const char *name, int flags);
#ifdef MAC_OS_X_VERSION_10_5
extern uint32_t notify_set_state(int token, uint64_t state);
extern uint32_t notify_get_state(int token, uint64_t *state);
#else
extern uint32_t notify_set_state(int token, int state);
extern uint32_t notify_get_state(int token, int *state);
#endif


// project includes
#include "watchvol.h"	// kextd_watch_volumes
#include "bootroot.h"	// watchedVol
#include "logging.h"
#include "globals.h"	// gClientUID
// #include "safecalls.h"

// constants
#define kWatchKeyBase       "com.apple.system.kextd.fswatch"
#define kWatchSettleTime    5

// struct watchedVol's (struct bootCaches in bootroot.h)
// created/destroyed with volumes coming/going; stored in sFsysWatchDict
// use notify_set_state on our notifications to point to these objects
struct watchedVol {
    // CFStringRef bsdName;     // DA id (is the key in sFsysWatchDict)
    CFRunLoopTimerRef delayer;  // non-NULL if something is scheduled
    CFMachPortRef lock;         // send right to locker's port
    int errcount;               // did most recent locker report an error? (???)
    Boolean disableOwners;      // should we disable owners on unlock?

    CFMutableArrayRef tokens;   // notify(3) tokens
    struct bootCaches *caches;  // parsed version of bootcaches.plist
};

// module-wide data
static DASessionRef sDASession = NULL;                  // learn about volumes
static DAApprovalSessionRef sDAApproval = NULL;         // retain volumes
static CFMachPortRef sFsysChangedPort = NULL;           // let us know
static CFRunLoopSourceRef sFsysChangedSource = NULL;    // on the runloop
static CFMutableDictionaryRef sFsysWatchDict = NULL;    // disk ids -> wstruct*s
static CFMachPortRef sRebootLock = NULL;		// if locked for reboot


// function declarations (kextd_watch_volumes, _stop in watchvol.h)

// ctor/dtor for struct watchedVol
static struct watchedVol* create_watchedVol(CFURLRef volURL);
static void destroy_watchedVol(struct watchedVol *watched);

// volume state
static void vol_appeared(DADiskRef disk, void *ctx);
static void vol_changed(DADiskRef, CFArrayRef keys, void* ctx);
static void vol_disappeared(DADiskRef, void* ctx);
static DADissenterRef is_dadisk_busy(DADiskRef, void *ctx);
static Boolean check_vol_busy(struct watchedVol *watched);

// notification processing delay scheme
static void fsys_changed(CFMachPortRef p, void *msg, CFIndex size, void *info);
static void check_now(CFRunLoopTimerRef timer, void *ctx);    // notify timer cb

// actual rebuilders!
static Boolean check_rebuild(struct watchedVol*, Boolean force); // do anything?

// CFMachPort invalidation callback
static void lock_died(CFMachPortRef p, void *info);

// XX reboot checks (also defined in MiG) and helpers
static Boolean reconsiderVolumes(dev_path_t busyDev);
static Boolean reconsiderVolume(dev_path_t volDev);
static void toggleOwners(dev_path_t disk, Boolean enableOwners);

// additional "local" helpers are declared/defined just before use


// utility macros
#define CFRELEASE(x) if(x) { CFRelease(x); x = NULL; }


/******************************************************************************
 * kextd_watch_volumes sets everything up (on the current runloop)
 *****************************************************************************/
#if 0
// for testing
#define twrite(msg) write(STDERR_FILENO, msg, sizeof(msg))
static void debug_chld(int signum) __attribute__((unused))
{
    int olderrno = errno;
    int status;
    pid_t childpid;

    if (signum != SIGCHLD)
	twrite("debug_chld not registered for signal\n");
    else
    if ((childpid = waitpid(-1, &status, WNOHANG)) == -1)
	twrite("DEBUG: SIGCHLD received, but no children available?\n");
    else 
    if (!WIFEXITED(status))
	twrite("DEBUG: child quit on signal?\n");
    else
    if (WEXITSTATUS(status))
	twrite("DEBUG: child exited with unhappy status\n");
    else
	twrite("DEBUG: child exited with happy status\n");

    errno = olderrno;
}
#endif

int kextd_watch_volumes(int sourcePriority)
{
    int rval = ELAST + 1;
    char *errmsg;
    CFRunLoopRef rl;

    errmsg = "already watching volumes?!";
    if (sFsysWatchDict)  goto finish;

    // the callbacks will want to go digging in here, so set it up first
    errmsg = "couldn't create data structures";
    sFsysWatchDict = CFDictionaryCreateMutable(nil, 0,
	&kCFTypeDictionaryKeyCallBacks, NULL);  // storing watchedVol*'s
    if (!sFsysWatchDict)  goto finish;

    errmsg = "trouble setting up ports and sources";
    rl = CFRunLoopGetCurrent();
    if (!rl)  goto finish;

    // change notifications will eventually come in through this port/source
    sFsysChangedPort = CFMachPortCreate(nil, fsys_changed, NULL, NULL);
    // we have to keep these objects so we can unschedule them later?
    if (!sFsysChangedPort)  goto finish;
    sFsysChangedSource = CFMachPortCreateRunLoopSource(kCFAllocatorDefault,
	sFsysChangedPort, sourcePriority);
    if (!sFsysChangedSource)  goto finish;
    CFRunLoopAddSource(rl, sFsysChangedSource, kCFRunLoopDefaultMode);

    // in general, being on the runloop means we could be called ...
    // and we are thus careful about our ordering.  In practice, however,
    // we're adding to the current runloop, which means nothing can happen
    // until this routine exits (we're on the one and only thread).

    /*
     * XX need to set up a better match dictionary
     * kDADiskDescriptionMediaWritableKey = true
     * kDADiskDescriptionVolumeNetworkKey != true
     */

    // make sure we have a chance to block unmounts
    errmsg = "couldn't set up diskarb sessions";
    sDAApproval = DAApprovalSessionCreate(nil);
    if (!sDAApproval)  goto finish;
    DARegisterDiskUnmountApprovalCallback(sDAApproval,
	kDADiskDescriptionMatchVolumeMountable, is_dadisk_busy, NULL);
    DAApprovalSessionScheduleWithRunLoop(sDAApproval, rl,kCFRunLoopDefaultMode);

    // set up the regular session
    sDASession = DASessionCreate(nil);
    if (!sDASession)  goto finish;
    DARegisterDiskAppearedCallback(sDASession,
	kDADiskDescriptionMatchVolumeMountable, vol_appeared, NULL);
    DARegisterDiskDescriptionChangedCallback(sDASession,
	kDADiskDescriptionMatchVolumeMountable,
	kDADiskDescriptionWatchVolumePath, vol_changed, NULL);
    DARegisterDiskDisappearedCallback(sDASession,
	kDADiskDescriptionMatchVolumeMountable, vol_disappeared, NULL);

    // okay, we're ready to rumble!
    DASessionScheduleWithRunLoop(sDASession, rl, kCFRunLoopDefaultMode);

    // if (signal(SIGCHLD, SIG_IGN) == SIG_ERR)  goto finish;
    // errmsg = "couldn't set debug signal handler";
    // if (signal(SIGCHLD, debug_chld) == SIG_ERR)  goto finish;

    errmsg = NULL;
    rval = 0;

    // volume notifications should start coming in shortly

finish:
    if (rval) {
	kextd_error_log("kextd_watch_volumes: %s", errmsg);
	kextd_stop_volwatch();
    }

    return rval;
}
/******************************************************************************
 * kextd_giveup_volwatch (4692369) simply initializes sFsysWatchDict to 
 * be empty so that reboot locking can occur.
 *****************************************************************************/
int kextd_giveup_volwatch()
{
    int rval = ENOMEM;
    sFsysWatchDict = CFDictionaryCreateMutable(nil, 0,
	&kCFTypeDictionaryKeyCallBacks, NULL);  // storing watchedVol*'s

    if (sFsysWatchDict) {
	rval = 0;
    } else {
    	kextd_error_log("giveup_volwatch(): allocation failure");
    }

    return rval;
}

/******************************************************************************
 * kextd_stop_volwatch unregisters from everything and cleans up
 * - called from watch_volumes to handle partial cleanup
 *****************************************************************************/
// to help clear out sFsysWatch
static void free_dict_item(const void* key, const void *val, void *c)
{
    destroy_watchedVol((struct watchedVol*)val);
}

// public entry point to this module
void kextd_stop_volwatch()
{
    CFRunLoopRef rl;

    // runloop cleanup
    rl = CFRunLoopGetCurrent();
    if (rl && sDASession)   DASessionUnscheduleFromRunLoop(sDASession, rl,
				kCFRunLoopDefaultMode);
    if (rl && sDAApproval)  DAApprovalSessionUnscheduleFromRunLoop(sDAApproval,
				rl, kCFRunLoopDefaultMode);

    // use CFRELEASE to nullify cfrefs in case watch_volumes called again
    if (sDASession) {
	DAUnregisterCallback(sDASession, vol_disappeared, NULL);
	DAUnregisterCallback(sDASession, vol_changed, NULL);
	DAUnregisterCallback(sDASession, vol_appeared, NULL);
	CFRELEASE(sDASession);
    }

    if (sDAApproval) {
	DAUnregisterApprovalCallback(sDAApproval, is_dadisk_busy, NULL);
	CFRELEASE(sDAApproval);
    }

    if (rl && sFsysChangedSource)  CFRunLoopRemoveSource(rl, sFsysChangedSource,
				       kCFRunLoopDefaultMode);
    CFRELEASE(sFsysChangedSource);
    CFRELEASE(sFsysChangedPort);

    if (sFsysWatchDict) {
	CFDictionaryApplyFunction(sFsysWatchDict, free_dict_item, NULL);
	CFRELEASE(sFsysWatchDict);
    }

    return;
}

/******************************************************************************
* destroy_watchedVol unregisters any notification tokens and frees
* pieces created in create_watchedVol
******************************************************************************/
static void destroy_watchedVol(struct watchedVol *watched)
{
    CFIndex ntokens;
    int token;      

    // assert that ->delayer and ->lock have already been cleaned up
    if (watched->tokens) {
        ntokens = CFArrayGetCount(watched->tokens);
        while(ntokens--) { 
            token = (int)CFArrayGetValueAtIndex(watched->tokens,ntokens);
            // XX should take (hacky) steps to insure token is never zero?
            if (/* !token || */ notify_cancel(token))
                kextd_error_log("destroy_watchedVol: "
                        "trouble canceling notification?");
        }
        CFRelease(watched->tokens);
    }    
    if (watched->caches)    destroyCaches(watched->caches);
}

/******************************************************************************
* create_watchedVol calls readCaches and creates watch-specific necessities
******************************************************************************/
static struct watchedVol* create_watchedVol(CFURLRef volURL)
{
    struct watchedVol *watched, *rval = NULL;
    char *errmsg = NULL;
    char rootpath[PATH_MAX] = { '\0' };
    Boolean isGPT = false;
    char *bsdname;
    Boolean ownersIgnored = false;
    struct statfs sfs;

    errmsg = "allocation error";
    watched = calloc(1, sizeof(*watched));
    if (!watched)  goto finish;
    if (!CFURLGetFileSystemRepresentation(volURL, false, /*CF folk: make up
	your minds!*/ (UInt8*)rootpath, PATH_MAX)) 	goto finish;

    // 4616366 only watch BootRoot volumes
    if (!isBootRoot(rootpath, &isGPT) || !isGPT) {
	errmsg = NULL;
	goto finish;
    }

    // There will be RPS paths, booters, "misc" paths, and the exts folder.
    // For now, we'll just set the array size to 0 and let it grow.
    watched->tokens = CFArrayCreateMutable(nil, 0, NULL);
    if (!watched->tokens)  goto finish;

    // try to enable owners if currently ignored
    if (statfs(rootpath, &sfs))	    goto finish;
    if ((bsdname = strstr(sfs.f_mntfromname, "disk"))) {
	ownersIgnored = ((sfs.f_flags & MNT_IGNORE_OWNERSHIP) != 0);
	if (ownersIgnored) 	toggleOwners(bsdname, true);
    }

    errmsg = NULL;	// readCaches logs its own errors
    watched->caches = readCaches(rootpath);
    if (!watched->caches)  goto finish;
    
    rval = watched;	// success?

finish:
    if (ownersIgnored) 	    toggleOwners(bsdname, false);	// toggle back
    if (errmsg) {
	if (rootpath[0]) {
	    kextd_error_log("%s: %s", rootpath, errmsg);
	} else {
	    kextd_error_log("create_watchedVol(): %s", errmsg);
	}
    }
    if (!rval && watched) {
	destroy_watchedVol(watched);
    }
    
    return rval;
}


// helper
#define cleanupLock(/*CFMachPortRef*/ lock) \
{ \
    mach_port_t lport; \
 \
    if (lock) { \
	lport = CFMachPortGetPort(lock); \
	CFRelease(lock); \
	lock = NULL; \
	mach_port_deallocate(mach_task_self(), lport); \
    } \
}

/******************************************************************************
 * vol_appeared checks whether a volume is interesting
 * (note: the first time we see a volume, it's probably not mounted yet)
 * (we rely on vol_changed to call us when the mountpoint actually appears)
 * - signs up for notifications -> creates new entries in our structures
 * - initiates an initial volume check
 *****************************************************************************/
// set up notifications for a single path
static int watch_path(char *path, mach_port_t port, struct watchedVol* watched)
{
    int rval = ELAST + 1;   // cheesy
    char key[PATH_MAX];
    int token = 0;
#ifdef MAC_OS_X_VERSION_10_5
    uint64_t state;
#else
    int state;
#endif

    // generate key, register for token, monitor, record pointer in token
    if (strlcpy(key, kWatchKeyBase, PATH_MAX) >= PATH_MAX)  goto finish;
    if (strlcat(key, path, PATH_MAX) >= PATH_MAX)  goto finish;
    if (notify_register_mach_port(key, &port, NOTIFY_REUSE, &token))
	goto finish;
    state = (intptr_t)watched;
    if (notify_set_state(token, state))  goto finish;
    if (notify_monitor_file(token, path, 1)) goto finish;

    CFArrayAppendValue(watched->tokens, (void*)token);

    rval = 0;

finish:
    if (rval && token != -1 && notify_cancel(token))
	kextd_error_log("watch_path: trouble canceling token?");

    return rval;
}

#define makerootpath(caches, dst, path) do { \
	if (strlcpy(dst, caches->root, PATH_MAX) >= PATH_MAX)	goto finish; \
	if (strlcat(dst, path, PATH_MAX) >= PATH_MAX)		goto finish; \
    } while(0)
static void vol_appeared(DADiskRef disk, void *ctx)
{
    int result = 0;	// for now, ignore inability to get basic data (4528851)
    mach_port_t fsPort;
    CFDictionaryRef ddesc = NULL;
    CFBooleanRef traitVal;
    CFURLRef volURL;
    CFStringRef bsdName;
    struct watchedVol *watched = NULL;

    struct bootCaches *caches;
    int i;
    char path[PATH_MAX];

    // see if the disk is writable, etc
    ddesc = DADiskCopyDescription(disk);
    if (!ddesc)  goto finish;

    // note: "whole" media (e.g. "disk1") have *either* mountpoints or children
    volURL = CFDictionaryGetValue(ddesc, kDADiskDescriptionVolumePathKey);
    if (!volURL || CFGetTypeID(volURL) != CFURLGetTypeID())  goto finish;

    // bsdName is the key in the dictionary (might we already be watching?)
    bsdName = CFDictionaryGetValue(ddesc, kDADiskDescriptionMediaBSDNameKey);
    if (!bsdName || CFGetTypeID(bsdName) != CFStringGetTypeID())  goto finish;
    if (CFDictionaryGetValue(sFsysWatchDict, bsdName)) {
	kextd_error_log("refreshing watch of volume already in watch table?");
	vol_disappeared(disk, ctx);	// brush before uncharted territory
    }

    // check traits (haven't seen writable network volumes; need to custom dict)
    traitVal = CFDictionaryGetValue(ddesc, kDADiskDescriptionMediaWritableKey);
    if (!traitVal || CFGetTypeID(traitVal) != CFBooleanGetTypeID()) goto finish;
    if (CFEqual(traitVal, kCFBooleanFalse))  goto finish;

    traitVal = CFDictionaryGetValue(ddesc, kDADiskDescriptionVolumeNetworkKey);
    if (!traitVal || CFGetTypeID(traitVal) != CFBooleanGetTypeID()) goto finish;
    if (CFEqual(traitVal, kCFBooleanTrue))  goto finish;

    // kextd_log("DEBUG: proceeding with volume:"); //CFShow(bsdName);
    // does it have a usable bootcaches.plist? (if not, just ignored)
    if (!(watched = create_watchedVol(volURL)))  goto finish;


    result = -1;    // anything after this is an error
    caches = watched->caches;
    // set up notifications on the change port
    fsPort = CFMachPortGetPort(sFsysChangedPort);
    if (fsPort == MACH_PORT_NULL)  goto finish;

    // for path in { exts, rpspaths[], booters, miscpaths[] }
    // rpspaths contains mkext, bootconfig; miscpaths the label file
    // cache paths are relative; need to make absolute
    makerootpath(caches, path, caches->exts);
    if (watch_path(path, fsPort, watched))  goto finish;
    for (i = 0; i < caches->nrps; i++) {
	makerootpath(caches, path, caches->rpspaths[i].rpath);
	if (watch_path(path, fsPort, watched))  	goto finish;
    }
    if (caches->efibooter.rpath[0]) {
	makerootpath(caches, path, caches->efibooter.rpath);
	if (watch_path(path, fsPort, watched))  	goto finish;
    }
    if (caches->ofbooter.rpath[0]) {
	makerootpath(caches, path, caches->ofbooter.rpath);
	if (watch_path(path, fsPort, watched))  	goto finish;
    }
    for (i = 0; i < caches->nmisc; i++) {
	makerootpath(caches, path, caches->miscpaths[i].rpath);
	if (watch_path(path, fsPort, watched))  	goto finish;
    }

    // we cleaned up any pre-existing entry for bsdName above
    CFDictionarySetValue(sFsysWatchDict, bsdName, watched);

    (void)check_rebuild(watched, false);   // in case it needs an update

    result = 0;           // we made it :)

finish:
    if (ddesc)   CFRelease(ddesc);

    if (result) {
	if (watched) {
	    kextd_error_log("trouble setting up notifications on %s",
		watched->caches->root);
	    destroy_watchedVol(watched);
	}
	// else kextd_log("DEBUG: skipping uninteresting volume");
    }

    return;
}

/******************************************************************************
 * vol_changed updates our structures if the mountpoint changed
 * - includes the initial mount after a device appears 
 * - thus we only call appeared and disappeared as appropriate
 *   _appeared and _disappeared are smart enough, but debugging is a pain
 *   when vol_disappeared gets called on a volume mount!
 *****************************************************************************/
static void vol_changed(DADiskRef disk, CFArrayRef keys, void* ctx)
{
    CFIndex i = CFArrayGetCount(keys);
    CFTypeRef key;
    CFDictionaryRef ddesc = DADiskCopyDescription(disk);
    CFStringRef bsdName = NULL;

    if (!ddesc)  goto finish;	// can't do much otherwise

    bsdName = CFDictionaryGetValue(ddesc,kDADiskDescriptionMediaBSDNameKey);
    if (!bsdName)  goto finish;

    while (i--)
	if ((key = CFArrayGetValueAtIndex(keys, i)) &&
		CFEqual(key, kDADiskDescriptionVolumePathKey)) {
	    // kextd_log("DEBUG: mountpoint changed");

	    // XX need to use a custom match dictionary
	    // diskarb sends lots of notifications about random stuff
	    // thus: only need to call _disappeared if we're watching it
	    if (CFDictionaryGetValue(sFsysWatchDict, bsdName))
		vol_disappeared(disk, ctx);
	    // and: only need to call _appeared if there's a mountpoint
	    if (CFDictionaryGetValue(ddesc, key))
		vol_appeared(disk, ctx);
	} else {
	    kextd_log("vol_changed: ignoring update: no mountpoint change");
	}

finish:
    if (ddesc)  CFRelease(ddesc);
}

/******************************************************************************
 * vol_disappeared removes entries from the relevant structures
 * - handles forced removal by invalidating the lock
 *****************************************************************************/
static void vol_disappeared(DADiskRef disk, void* ctx)
{
    int result = 0;	// ignore weird requests (4528851)
    CFDictionaryRef ddesc = NULL;
    CFStringRef bsdName;
    struct watchedVol *watched;

    ddesc = DADiskCopyDescription(disk);
    if (!ddesc)  goto finish;
    bsdName = CFDictionaryGetValue(ddesc, kDADiskDescriptionMediaBSDNameKey);
    if (!bsdName || CFGetTypeID(bsdName) != CFStringGetTypeID())  goto finish;

    //kextd_log("DEBUG: vol_disappeared:");
    //CFShow(bsdName);
    watched = (void*)CFDictionaryGetValue(sFsysWatchDict, bsdName);
    if (!watched)  goto finish;

    CFDictionaryRemoveValue(sFsysWatchDict, bsdName);

    // and in case some action was in progress
    if (watched->delayer) {
	CFRunLoopTimerInvalidate(watched->delayer); // refcount->0
	watched->delayer = NULL;
    }
    // disappeared means perm/noperm doesn't matter
    cleanupLock(watched->lock);

    destroy_watchedVol(watched);    // cancels notifications

    result = 0;

finish:
    if (result)
	kextd_error_log("vol_disappeared: unexpected error");
    if (ddesc)  CFRelease(ddesc);

    return;
}

/******************************************************************************
 * is_dadisk_busy lets diskarb know if we'd rather nothing changed
 * note: dissenter callback is called when root initiates an unmount,
 * but the result is ignored.  :)
 *****************************************************************************/
static DADissenterRef is_dadisk_busy(DADiskRef disk, void *ctx)
{
    int result = 0;	// ignore weird requests for now (4528851)
    DADissenterRef rval = NULL;
    CFDictionaryRef ddesc = NULL;
    CFStringRef bsdName = NULL;
    struct watchedVol *watched;

    // kextd_log("DEBUG: is_dadisk_busy called");
    ddesc = DADiskCopyDescription(disk);
    if (!ddesc)  goto finish;
    bsdName = CFDictionaryGetValue(ddesc, kDADiskDescriptionMediaBSDNameKey);
    if (!bsdName || CFGetTypeID(bsdName) != CFStringGetTypeID())  goto finish;

    result = -1;
    watched = (void*)CFDictionaryGetValue(sFsysWatchDict, bsdName);
    if (watched && check_vol_busy(watched)) {
	rval = DADissenterCreate(nil, kDAReturnBusy, CFSTR("kextmanager busy"));
	if (!rval)  goto finish;
    }
	
    result = 0;

finish:
    if (result) kextd_error_log("is_dadisk_busy had trouble answering diskarb");
    // else kextd_log("returning dissenter %p", rval);
    if (ddesc)  CFRelease(ddesc);

    return rval;    // caller releases dissenter if non-null
}

/******************************************************************************
 * check_vol_busy
 * - busy if locked
 * - check_rebuild to check once more (return code indicates if it did anything)
 *****************************************************************************/
static Boolean check_vol_busy(struct watchedVol *watched)
{
    Boolean rval = (watched->lock != NULL);

    if (!rval)
	rval = check_rebuild(watched, false);

    return rval;
}


/******************************************************************************
 * fsys_changed gets the mach messages from notifyd
 * - schedule a timer (urgency detected elsewhere calls direct, canceling timer)
 *****************************************************************************/
static void fsys_changed(CFMachPortRef p, void *m, CFIndex size, void *info)
{
    int result = -1;
#ifdef MAC_OS_X_VERSION_10_5
    uint64_t nstate;
#else
    int nstate;
#endif
    struct watchedVol *watched;
    int token;
    mach_msg_empty_rcv_t *msg = (mach_msg_empty_rcv_t*)m;

    // msg_id==token -> notify_get_state() -> watchedVol*
    // XX if (token == 0, perhaps a force-rebuild message?)
    token = msg->header.msgh_id;
    if (notify_get_state(token, &nstate))  goto finish;
    watched = (struct watchedVol*)(intptr_t)nstate;
    if (!watched)  goto finish;

    // is the volume valid? (notification should have been canceled)
    if (CFDictionaryGetCountOfValue(sFsysWatchDict, watched)) {
	CFRunLoopTimerContext tc = { 0, watched, NULL, NULL, NULL };
	CFAbsoluteTime firetime = CFAbsoluteTimeGetCurrent() + kWatchSettleTime;

	// cancel any existing timer (evidently updates are in progress)
	if (watched->delayer)
	    CFRunLoopTimerInvalidate(watched->delayer);

	// schedule a timer to call check_now after a delay
	watched->delayer=CFRunLoopTimerCreate(nil,firetime,0,0,0,check_now,&tc);
	if (!watched->delayer)  goto finish;

	CFRunLoopAddTimer(CFRunLoopGetCurrent(), watched->delayer,
	    kCFRunLoopDefaultMode);
	CFRelease(watched->delayer);  // so later invalidation will free
    } else
	kextd_error_log("invalid token/volume: %d, %p", token, watched);

    result = 0;

finish:
    if (result)
	kextd_error_log("couldn't respond to filesystem change notification!");

    return;
}

/******************************************************************************
 * check_now, called after the timer expires, calls check_rebuild() 
 *****************************************************************************/
void check_now(CFRunLoopTimerRef timer, void *info)
{
    struct watchedVol *watched = (struct watchedVol*)info;

    // is the volume still valid? (timer should have been invalidated)
    if (watched && CFDictionaryGetCountOfValue(sFsysWatchDict, watched)) {
	watched->delayer = NULL;	 	// timer is no longer pending
	(void)check_rebuild(watched, false);  	// don't care what it did
    } /* else
	kextd_log("DEBUG: timer for %p wasn't invalidated?", watched);
    */
}

/******************************************************************************
 * check_rebuild (indirectly) stats everything and fires kextcache as needed
 * returns a Boolean indicating whether anything *was* accomplished
 * a helper returning an error doesn't count (?)
 * - Boolean 'force' allows us to eventually fully handle SIGHUP
 * - fast path: ck_vol_busy->ck_rebuild-> newMKext/timer ->unlock->check/cancel
 * - if any caches are out of date, only rebuild them
 * - otherwise (or always if there was a stat error), copypaths->Apple_Boot's
 * - note: important to only rebuild out-of-date caches to prevent looping
 *****************************************************************************/
// kextcache -u helper sets up argv
static int rebuild_boot(struct bootCaches *caches, Boolean force)
{
    int rval = ELAST + 1;
    pid_t pid;
    int argc, argi = 0; 
    char **kcargs;

    //  argv[0] '-u'  root  NULL
    argc =  1  +  1  + 1  + 1;
    kcargs = malloc(argc * sizeof(char*));
    if (!kcargs)  goto finish;

    kcargs[argi++] = "kextcache";
    if (force) {
	kcargs[argi++] = "-f";
    }
    kcargs[argi++] = "-u";
    kcargs[argi++] = caches->root;
    // kextcache reads bc.plist so nothing more needed

    kcargs[argi] = NULL;    // terminate the list

    rval = 0;
    pid = fork_kextcache(caches->root, kcargs, false);

finish:
    if (rval) {
	kextd_error_log("data error before rebuilding boot partition");
    } else if (pid < 0) {
	rval = pid;
    }

    return rval;
}

/*
 * ?? watched->errcount (tracking cache rebuild problems on a particular volume)
 * could be used to prevent the case where caches are out
 * of date and can't be rebuilt, but we still want to copy stuff to the
 * boot partitions??  Otherwise, we always fire the kextcache -u, but it
 * might beat [regular] kextcache to the lock.
 *
 * That all said, if the mkext is straight up *gone*, we can't do much
 * in the way of rebuilding the data in the boot partition.
 *
 * ... after some testing, it became obvious that repeated attempts at
 * a failling volume would just block reboot.  So we try not to let such a 
 * volume delay reboot for long.
 */
static Boolean check_rebuild(struct watchedVol *watched, Boolean force)
{
    Boolean launched = false;
    Boolean rebuildmkext = force;	// force the mkext, nuke the stamps

    // if we came in some other way and there's a timer pending, cancel it
    if (watched->delayer) {  
	CFRunLoopTimerInvalidate(watched->delayer);  // runloop holds last ref
	watched->delayer = NULL;
    }

#if 0	// no one calls us with force right now
    // if forcing, we need to nuke the bootstamps so that kextcache -u 
    // updates everything after the mkext is rebuilt
    if (force) {
        char bspath[PATH_MAX];

        if (snprintf(bspath, PATH_MAX, "%s/%s", watched->caches->root,
                kTSCacheDir) < PATH_MAX) {
            if (sdeepunlink(watched->caches->cachefd, bspath)) {
		kextd_error_log("couldn't nuke bootstamps: %d", errno);
            }
        } else {
            kextd_error_log("couldn't build Extensions path");
	}
    }
#endif

    // might have been forced above
    if (!rebuildmkext)     rebuildmkext = check_mkext(watched->caches);

    // if we rebuild the mkext this time, we'll be here again on success
    // because we're watching for changes to the mkext file
    if (rebuildmkext) {
	if (rebuild_mkext(watched->caches, false /*wait*/)) {	// logs
	    watched->errcount++;	// so we don't block reboot forever
	} else {
	    launched = true;
	}
    } else {
	// check to see if the volume has helper partitions (and might need -u)
	char bsdname[DEVMAXPATHSIZE];
	struct stat sb;
	CFDictionaryRef binfo = NULL;
	Boolean hasBoots, isGPT;

	// if not BootRoot, we don't bother with kextcache -u
	if (fstat(watched->caches->cachefd, &sb) == 0 && 
		devname_r(sb.st_dev, S_IFBLK, bsdname, DEVMAXPATHSIZE) &&
		BLCreateBooterInformationDictionary(NULL,bsdname,&binfo) == 0) {
	    CFArrayRef ar;

	    ar = CFDictionaryGetValue(binfo, kBLAuxiliaryPartitionsKey);
	    hasBoots = (ar && CFArrayGetCount(ar) > 0);
	    ar = CFDictionaryGetValue(binfo, kBLSystemPartitionsKey);
	    isGPT = (ar && CFArrayGetCount(ar) > 0);

	    if (hasBoots && isGPT) {
		Boolean anyOutOfDate = true;
		if (needUpdates(watched->caches,&anyOutOfDate,NULL,NULL,NULL)) {
		    anyOutOfDate = true;
		}

		// and if necessary, run kextcache -u
		if (force || anyOutOfDate) {
		    launched = (rebuild_boot(watched->caches, force) == 0);
		}
	    }
	}
	if (binfo)	CFRelease(binfo);
    }

    return launched;
}


    /* ??? will we track the current root volume to treat it specially?
    if (rebuildplcache)
	KXKextManagerResetAllRepositories(gKextManager);  // resets "/"
    // Extensions.kextcache?
    if (watched == rootvol) {
	rebuildplcache = true;  // in case stat() fails
	if (stat(watched->plcache->rpath, &sb) == -1)
	    goto cachecheckfailed;
	rebuildplcache = (sb.st_mtime == extsb.st_mtime + 1);
    }
    */

// ---- locking services (prototyped via MiG and kextmanager[_mig].defs) ----

/******************************************************************************
 * kextmanager_lock_reboot locks everything (called by shutdown(8) & reboot(8))
 *****************************************************************************/
static int lock_vol(struct watchedVol *watched, mach_port_t client)
{
    int rval = ENOMEM;
    CFRunLoopSourceRef invalidator;
    CFMachPortContext mp_ctx = { 0, watched, NULL, NULL, NULL };
    CFRunLoopRef rl = CFRunLoopGetCurrent();
    if (!rl)  goto finish;

    // create a new lock with the client port
    watched->lock = CFMachPortCreateWithPort(nil,client,NULL,&mp_ctx,false);
    if (!watched->lock)  goto finish;
    CFMachPortSetInvalidationCallBack(watched->lock, lock_died);
    invalidator = CFMachPortCreateRunLoopSource(nil, watched->lock, 0);
    if (!invalidator)  goto finish;
    CFRunLoopAddSource(rl, invalidator, kCFRunLoopDefaultMode);
    CFRelease(invalidator);	// owned by the runloop now

    rval = 0;

finish:
    return rval;
}

#define GIVEUPTHRESH 5
// iterator helper locking for locked or should-be-locked volumes
static void check_locked(const void *key, const void *val, void *ctx)
{
    struct watchedVol *watched = (struct watchedVol*)val;
    const void **bsdName = ctx;

    // report this one if:
    // it's already locked or if it needs a rebuild
    // but don't block reboot if it's been having errors
    if (watched->lock ||
	    (watched->errcount < GIVEUPTHRESH && check_rebuild(watched, false)))
	*bsdName = key;
}

kern_return_t _kextmanager_lock_reboot(mach_port_t p, mach_port_t client,
				    dev_path_t busyDev, int *busyStatus)
{
    kern_return_t rval = KERN_FAILURE;
    int result = ELAST + 1;
    CFStringRef bsdName = NULL;

    if (!busyDev || !busyStatus) {
	rval = KERN_SUCCESS;
	result = EINVAL;
	goto finish;
    }

    if (gClientUID != 0) {
	kextd_error_log("non-root doesn't need to lock or unlock volumes");
	rval = KERN_SUCCESS;
	result = EPERM;
	goto finish;
    }

    if (sRebootLock) {
	rval = KERN_SUCCESS;	// for MiG
	result = EBUSY;	// for the client
	busyDev[0] = '\0';
	goto finish;
    }

    // check to see if any new volumes have become eligible
    if (reconsiderVolumes(busyDev)) {
	rval = KERN_SUCCESS;	// for MiG
	result = EBUSY;	// for the client
	goto finish;
    }

    // if we've contacted diskarb, scan the dictionary for locked items
    if (sFsysWatchDict) {
	CFDictionaryApplyFunction(sFsysWatchDict, check_locked, &bsdName);
    }
    if (bsdName == NULL) {
	// great, this guy gets to lock everything (which we expect to work)
	CFRunLoopSourceRef invalidator;
	CFMachPortContext mp_ctx = { 0, &sRebootLock, 0, };
	CFRunLoopRef rl = CFRunLoopGetCurrent();

	if (!rl)  goto finish;

	// create a new lock with the client port
	sRebootLock = CFMachPortCreateWithPort(nil,client,NULL,&mp_ctx,false);
	if (!sRebootLock)  goto finish;
	CFMachPortSetInvalidationCallBack(sRebootLock, lock_died);
	invalidator = CFMachPortCreateRunLoopSource(nil, sRebootLock, 0);
	if (!invalidator)  goto finish;
	CFRunLoopAddSource(rl, invalidator, kCFRunLoopDefaultMode);
	CFRelease(invalidator);	// owned by the runloop now

	result = 0;	    // not locked
    } else {
	// bsdName (at least) was locked, try again later
	result = EBUSY;
	if(!CFStringGetFileSystemRepresentation(bsdName, busyDev,
		DEVMAXPATHSIZE))  busyDev[0] = '\0';
    }

    rval = KERN_SUCCESS;

finish:
    if (rval == KERN_SUCCESS) {
	*busyStatus = result;
    } else {
	kextd_error_log("error locking for reboot");
    }

    if (result == EBUSY && bsdName)
	kextd_log("%s was busy, preventing lock for reboot", busyDev);

    return rval;
}

/******************************************************************************
 * _kextmanager_lock_volume tries to lock volumes for clients (i.e. kextcache)
 * - volDev is the "bsdName" of the volume in question
 *****************************************************************************/
kern_return_t _kextmanager_lock_volume(mach_port_t p, mach_port_t client,
				    dev_path_t volDev, int *lockstatus)
{
    kern_return_t rval = KERN_FAILURE;
    int result;
    CFStringRef bsdName = NULL;
    struct watchedVol *watched = NULL;
    struct statfs sfs;

    if (!lockstatus) {
	kextd_error_log("kextmanager_lock_volume requires lockstatus != NULL");
	rval = KERN_SUCCESS;
	result = EINVAL;
    }

    if (gClientUID != 0 /*watched->fsinfo->f_owner ?*/) {
	kextd_error_log("non-root doesn't need to lock or unlock volumes");
	rval = KERN_SUCCESS;
	result = EPERM;
	goto finish;
    }

    // if we're still trying to initialize or we're rebooting,
    // deny any new locks
    if (!sFsysWatchDict || sRebootLock) {
	rval = KERN_SUCCESS;	// for MiG
	result = EBUSY;	// for the client
	goto finish;
    }

    result = ENOMEM;
    bsdName = CFStringCreateWithFileSystemRepresentation(nil, volDev);
    if (!bsdName)  goto finish;
    watched = (void*)CFDictionaryGetValue(sFsysWatchDict, bsdName);
    if (!watched) {
	rval = KERN_SUCCESS;
	result = ENOENT;
	goto finish;
    }

    if (watched->lock) {
	// kextd_log("DEBUG: volume %s locked", watched->caches->root);
	result = EBUSY;
    } else {
	if (lock_vol(watched, client))  goto finish;
	result = 0;
    }

    // try to enable owners if not currently honored
    if (statfs(watched->caches->root, &sfs) == 0 &&
	    (sfs.f_flags & MNT_IGNORE_OWNERSHIP)) {
	toggleOwners(volDev, true);
	watched->disableOwners = true;
    }

    rval = KERN_SUCCESS;

finish:
    if (bsdName)  CFRelease(bsdName);
    if (rval) {
	if (gClientUID == 0)
	    kextd_error_log("trouble while locking %s", volDev);
	cleanupLock(watched->lock);
    } else {
	*lockstatus = result;	    // only meaningful on rval == 0
    }

    return rval;
}

/******************************************************************************
 * _kextmanager_unlock_volume unlocks for clients (i.e. kextcache)
 *****************************************************************************/
kern_return_t _kextmanager_unlock_volume(mach_port_t p, mach_port_t client,
				    dev_path_t volDev, int exitstatus)
{
    kern_return_t rval = KERN_FAILURE;
    CFStringRef bsdName = NULL;
    struct watchedVol *watched = NULL;

    // since we don't need the extra send right added by MiG
    if (mach_port_deallocate(mach_task_self(), client))  goto finish;

    if (gClientUID != 0 /*watched->fsinfo->f_owner ?*/) {
	kextd_error_log("non-root doesn't need to lock or unlock volumes");
	rval = KERN_SUCCESS;
	goto finish;
    }

    // make sure we're set up
    if (!sFsysWatchDict)    goto finish;

    bsdName = CFStringCreateWithFileSystemRepresentation(nil, volDev);
    if (!bsdName)  goto finish;
    watched = (void*)CFDictionaryGetValue(sFsysWatchDict, bsdName);
    if (!watched)  goto finish;

    if (!watched->lock) {
	kextd_error_log("%s isn't locked", watched->caches->root);
	goto finish;
    }
    
    if (client != CFMachPortGetPort(watched->lock)) {
	kextd_error_log("%p not used to lock %s", client,
		watched->caches->root);
	goto finish;
    }

    // okay, recording any error and releasing the lock
    if (exitstatus) {
	if (exitstatus == EX_TEMPFAIL) {
	    // kextcache not done yet; so don't record error
	} else {
	    kextd_log("kextcache reported a problem updating %s", volDev);
	    watched->errcount++;
	}
    } else if (watched->errcount) {
	// put reassuring message in the log
	kextd_log("kextcache succeeded with %s (previously failed)", volDev);
	watched->errcount = 0;
    }
 
    // disable owners if we enabled them for the locker
    if (watched->disableOwners) {
	toggleOwners(volDev, false);
	watched->disableOwners = false;
    }

    cleanupLock(watched->lock);

    /* could try to speed things along (-m to -u; 5 seconds faster at shutdown)
     * disabled with mutli-lock/unlock for owners; check EX_TEMPFAIL in Leopard
     if (watched->errcount < GIVEUPTHRESH)
	(void)check_rebuild(watched, false);
     */

    rval = KERN_SUCCESS;

finish:
    if (bsdName)  CFRelease(bsdName);
    if (rval && watched) {
	kextd_error_log("couldn't unlock %s", watched->caches->root);
    }

    return rval;
}

/******************************************************************************
 * lock_died tells us when the receive right went away
 * - this is okay if we're currently unlocked; bad otherwise
 *****************************************************************************/
static void lock_died(CFMachPortRef p, void *info)
{
    struct watchedVol* watched = (struct watchedVol*)info;

    if (info == &sRebootLock) {
	kextd_log("reboot/shutdown should have rebooted instead of dying");
	cleanupLock(sRebootLock);   // there is explicit releasing this lock
    } else if (!watched) {
	kextd_error_log("lock_died: NULL info??");
    } else if (CFDictionaryGetCountOfValue(sFsysWatchDict, watched) == 0) {
	// volume might have been renamed while in action (4620558)
	// kextd_log("no container for invalid lock"); // expected via vol_gone?
    } else if (watched->lock) {
	kextd_error_log("child exited w/o releasing lock on %s",
		watched->caches->root);
 
	// try to disable owners if we enabled them for the locker
	if (watched->disableOwners) {
	    struct statfs sfs;
	    char *bsdname;

	    if (statfs(watched->caches->root, &sfs) == 0 &&
	    	    (bsdname = strstr(sfs.f_mntfromname, "disk"))) {
		toggleOwners(bsdname, false);
		watched->disableOwners = false;
	    }
	}

	cleanupLock(watched->lock);
	// could clean up worker pid if we were actually storing it
    }
    /*else {
	// kextd_log("DEBUG: lock (cleanly) deallocated for %s",
		watched->caches->root);
    }*/
}

/******************************************************************************
 * reconsiderVolume() rechecks to see if a volume has become interesting
 * given that we watch owners-ignored volumes, only needed for OS copies
 *****************************************************************************/
static Boolean reconsiderVolume(dev_path_t volDev)
{
    int result = -1;
    Boolean rval = false;
    CFStringRef bsdName = NULL;
    struct watchedVol *watched;
    DADiskRef disk = NULL;

    bsdName = CFStringCreateWithCString(nil, volDev, kCFStringEncodingASCII);
    if (!bsdName)	goto finish;

    // lock_reboot will shortly call check_rebuild on all watched volumes
    if (!CFDictionaryGetValue(sFsysWatchDict, bsdName)) {
	if (!(disk = DADiskCreateFromBSDName(nil, sDASession, volDev)))
	    goto finish;

	// maybe we should be watching it now?
	vol_appeared(disk, NULL);
	if ((watched = (void*)CFDictionaryGetValue(sFsysWatchDict, bsdName))) {
	    rval = check_rebuild(watched, false);   // vol_appeared calling too
	}
    }

    result = 0;

finish:
    if (disk)	    CFRelease(disk);
    if (bsdName)    CFRelease(bsdName);
    if (result) {
	kextd_error_log("error reconsidering volume %d");
    }

    return rval;
}

/******************************************************************************
 * reconsiderVolumes() iterates the mount list, reconsidering all local mounts
 * if any one of them needed an update, busyDev is set to the disk in question
 *****************************************************************************/
static Boolean reconsiderVolumes(dev_path_t busyDev)
{
    Boolean rval = false;
    char *errmsg = NULL;
    int nfsys, i;
    size_t bufsz;
    struct statfs *mounts;
    char *bsdname;

    // if not set up ...
    if (!sDASession)	    goto finish;

    errmsg = "error while getting mount list";
    if (-1 == (nfsys = getfsstat(NULL, 0, 0)))	    goto finish;
    bufsz = nfsys * sizeof(struct statfs);
    if (!(mounts = malloc(bufsz)))	    	    goto finish;
    if (-1 == getfsstat(mounts, bufsz, MNT_NOWAIT)) goto finish;

    errmsg = NULL;	// let reconsiderVolume() take it from here
    for (i = 0; i < nfsys; i++) {
	struct statfs *sfs = &mounts[i];

	if (sfs->f_flags & MNT_LOCAL &&
	       (bsdname = strstr(sfs->f_mntfromname, "disk"))) {
	    if (reconsiderVolume(bsdname)) {
		rval = true;
		strlcpy(busyDev, bsdname, DEVMAXPATHSIZE);
	    }
	}
    }

    errmsg = NULL;

finish:
    if (errmsg)     kextd_error_log(errmsg);

    return rval;
}

/******************************************************************************
 * toggleOwners() enables or disables owners as requested
 *****************************************************************************/
static void toggleOwners(dev_path_t volDev, Boolean enableOwners)
{
    int result = ELAST + 1;
    DASessionRef session = NULL;
    CFStringRef toggleMode = CFSTR("toggleOwnersMode");
    DADiskRef disk = NULL;
    DADissenterRef dis = (void*)kCFNull;
    CFStringRef mountargs[] = { CFSTR("update"), NULL,  NULL };

    if (enableOwners) {
	mountargs[1] = CFSTR("perm");
    } else {
	mountargs[1] = CFSTR("noperm");
    }

    // same 'dis' logic as mountBoot in update_boot.c
    if (!(session = DASessionCreate(nil)))  	goto finish;
    DASessionScheduleWithRunLoop(session, CFRunLoopGetCurrent(), toggleMode);
    if (!(disk = DADiskCreateFromBSDName(nil, session, volDev))) goto finish;
    DADiskMountWithArguments(disk, NULL, kDADiskMountOptionDefault, _daDone,
				 &dis, mountargs);

    while (dis == (void*)kCFNull) {
	CFRunLoopRunInMode(toggleMode, 0, true);    // _daDone updates 'dis'
    }
    if (dis) 	goto finish;

    result = 0;

finish:
    if (dis && dis != (void*)kCFNull) 	    CFRelease(dis);
    if (disk)	    			    CFRelease(disk);
    if (session)			    CFRelease(session);

    if (result)
	kextd_log("WARNING: couldn't %s owners for %s", 
		enableOwners ? "enable":"disable", volDev);
}

/*******************************************************************************
* updateRAIDSet() -- Something on a RAID set has changed, so we may need to
* update its boot partition info.
*******************************************************************************/
#define RAID_MATCH_SIZE   (2)

void updateRAIDSet(
    CFNotificationCenterRef center,
    void * observer,
    CFStringRef name,
    const void * object,
    CFDictionaryRef userInfo)
{
    char * errorMessage = NULL;
    CFStringRef matchingKeys[RAID_MATCH_SIZE] = {
        CFSTR("RAID"),
        CFSTR("UUID") };
    CFTypeRef matchingValues[RAID_MATCH_SIZE] = {
        (CFTypeRef)kCFBooleanTrue,
        (CFTypeRef)object };
    CFDictionaryRef matchPropertyDict = NULL;
    CFMutableDictionaryRef matchingDict = NULL;
    io_service_t theRAIDSet = MACH_PORT_NULL;
    CFStringRef bsdName = NULL;
    struct watchedVol * watched = NULL;  // do not free

    // nothing to do if we're not watching yet
    if (!sFsysWatchDict)    goto finish;    

    errorMessage = "No RAID set named in RAID set changed notification.";
    if (!object) {
        goto finish;
    }

    errorMessage = "Unable to create matching dictionary for RAID set.";
    matchPropertyDict = CFDictionaryCreate(kCFAllocatorDefault,
        (const void **)&matchingKeys,
        (const void **)&matchingValues,
        RAID_MATCH_SIZE,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    if (!matchPropertyDict) {
        goto finish;
    }

    matchingDict = CFDictionaryCreateMutable(kCFAllocatorDefault,
        0,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    if (!matchingDict) {
        goto finish;
    }
    CFDictionarySetValue(matchingDict, CFSTR(kIOPropertyMatchKey), 
        matchPropertyDict);

    errorMessage = NULL;	// maybe the RAID just went away
    theRAIDSet  = IOServiceGetMatchingService(kIOMasterPortDefault,
        matchingDict);
    matchingDict = NULL;  // IOServiceGetMatchingService() consumes reference!
    if (!theRAIDSet) {
        goto finish;
    }

    errorMessage = "Missing BSD Name for updated RAID set.";
    bsdName = IORegistryEntryCreateCFProperty(theRAIDSet,
        CFSTR("BSD Name"),
        kCFAllocatorDefault,
        0);
    if (!bsdName) {
        goto finish;
    }

    watched = (void*)CFDictionaryGetValue(sFsysWatchDict, bsdName);
    if (watched) {
        (void)rebuild_boot(watched->caches, true /* force rebuild */);
    }

    errorMessage = NULL;

finish:
    if (errorMessage) {
        kextd_error_log(errorMessage);
    }
    if (matchPropertyDict) CFRelease(matchPropertyDict);
    if (matchingDict)      CFRelease(matchingDict);
    if (theRAIDSet)        IOObjectRelease(theRAIDSet);
    if (bsdName)           CFRelease(bsdName);
    return;
}
