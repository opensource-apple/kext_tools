/*
 * FILE: update_boot.c
 * AUTH: Soren Spies (sspies)
 * DATE: 8 June 2006
 * DESC: implement 'kextcache -u' (copying to Apple_Boot partitions)
 *
 */

#include <bless.h>
#include <err.h>
#include <fcntl.h>
#include <libgen.h>
#include <sysexits.h>
#include <sys/mount.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <IOKit/kext/kextmanager_types.h>	// DEVMAXPATHSIZE

#include <CoreFoundation/CoreFoundation.h>
#include <DiskArbitration/DiskArbitration.h>

#include "bootroot.h"	    // eventually "bootcaches.h" (v2)
#include "bootfiles.h"
#include "logging.h"
#include "safecalls.h"
#include "update_boot.h"

enum bootReversions {
    nothingSerious = 0,
    nukedLabels,	    // 1
    copyingOFBooter,	    // 2
    copyingEFIBooter,	    // 3
    copiedBooters,	    // 4
    activatingOFBooter,	    // 5
    activatingEFIBooter,    // 6
    activatedBooters	    // 7
};

// for non-RPS content, including booters
#define OLDEXT ".old"
#define NEWEXT ".new"
#define CONTENTEXT ".contentDetails"

// for Apple_Boot update
struct updatingVol {
    int curbootfd;			// Sec: handle to curBoot
    char curMount[MNAMELEN];		// path to current boot mountpt
    DADiskRef curBoot;			// and matching diskarb ref
    char curRPS[PATH_MAX];		// RPS dir inside
    char efidst[PATH_MAX], ofdst[PATH_MAX];
    enum bootReversions changestate;	// changes that might need rollback

    Boolean doRPS, doMisc, doBooters;	// what are we updating
    CFArrayRef boots;			// bsdname's of Apple_Boot partitions
    DASessionRef dasession;		// handle to diskarb
    struct bootCaches *caches;		// parsed bootcaches.plist data
};

// diskarb
static int mountBoot(struct updatingVol *up, CFIndex bootindex);
static int unmountBoot(struct updatingVol *up);

// ucopy = unlink & copy
// no race for RPS, so install it first
static int ucopyRPS(struct updatingVol *s);	    // nuke/copy to inactive
// labels (e.g.) have no fallback, .new is harmless
// XX ucopy"Preboot/Firmware"
static int ucopyMisc(struct updatingVol *s);	    // use/overwrite .new names
// booters have fallback paths, but originals might be broken
static int ucopyBooters(struct updatingVol *s);     // nuke/copy booters (inact)
// no label -> hint of indeterminate state (label key in plist?)
static int nukeLabels(struct updatingVol *s);	    // byebye (all?)
// booters have worst critical:fragile ratio (point of departure)
static int activateBooters(struct updatingVol *s);  // bless new names
// and the RPS data needed for booting
static int activateRPS(struct updatingVol *s);	    // leap-frog w/rename() :)
// finally, the labels (indicating a working system)
// XX activate"FirmwarePaths/postboot"
static int activateMisc(struct updatingVol *s, int bidx); // rename .new / label
// and now that we're safe
static int nukeFallbacks(struct updatingVol *s);

// cleanup routines (RPS is the last step; activateMisc handles label)
static int revertState(struct updatingVol *up);

/* Chain of Trust
 * Our goal is to do anything the bootcaches.plist says, but only to that vol.
 * #1 we only pay attention to root-owned bootcaches.plist files
 * #2 we get an fd to the bootcaches.plist		[trust is here]
// * #3 we validate the bc.plist fd after getting an fd to the volume's root
 * #4 we use cachefd to generate the bsdname for libbless
 * #5 we validate cachefd after the call to bless	[trust -> bsdname]
 * #6 we get curbootfd after each apple_boot mount
 * #7 we validate cachefd after the call		[trust -> curfd]
 * #8 all operations on take an fd limiting them to volume scope
 */

// ? do these *need* do { } while() wrappers?
// XX should probably rename to all-caps
#define pathcpy(dst, src) do { \
	if (strlcpy(dst, src, PATH_MAX) >= PATH_MAX)  goto finish; \
    } while(0)
#define pathcat(dst, src) do { \
	if (strlcat(dst, src, PATH_MAX) >= PATH_MAX)  goto finish; \
    } while(0)
// could have made this macro sooner
#define makebootpath(path, rpath) do { \
				    pathcpy(path, up->curMount); \
				    pathcat(path, rpath); \
				} while(0)

/*******************************************************************************
* updateBoots will lock the volume and update the booter partitions 
* Sec: must ensure each target is one of the source's Apple_Boot partitions
*******************************************************************************/
int updateBoots(char *volRoot, int filec, const char *files[],
		       Boolean force, int dashv)
{
    int rval;
    char *errmsg = NULL;
    struct updatingVol up = { -1, { '\0' }, };
    char bsdname[DEVMAXPATHSIZE];
    CFDictionaryRef bdict = NULL;
    struct stat cachesb;

    CFIndex i, bootcount, bootupdates = 0;
    Boolean doAny;

    // if no bootcaches.plist, we don't care about this volume
    rval = 0;
    if (takeVolumeForPaths(volRoot, filec, files))  goto finish;  // -u owners
    up.caches = readCaches(volRoot);
    if (!up.caches)  goto finish;

    /* XX Sec reviewed: how we secure against replacing /'s mkext from external
     * TMPDIR set to target volume
     * final rename must be on whatever volume provided the kexts
     * if volume is /, then kexts owned by root can be trusted (4623559 fstat)
     * otherwise, rename from wrong volume will fail
     *  
     * Either rename() will fail or kexts should be safe via root :!
     */
    // check mkext for no-kextd case
    rval = ELAST + 1;
    errmsg = "couldn't rebuild stale mkext?";	    // XX redundant
    if (check_mkext(up.caches)) {
	// give up the lock so child can get it (EX_TEMPFAIL == "no status")
	putVolumeForPath(volRoot, EX_TEMPFAIL);
	// rebuild the mkext
	if (rebuild_mkext(up.caches, true /*wait*/))  goto finish;
	// retake the lock
	errmsg = NULL;	// takeVolume.. logs its own errors
	if (takeVolumeForPaths(volRoot, filec, files))  goto finish;
    }

    // call bless to get booter info (shouldn't access the disk; most common)
    errmsg = "couldn't get Apple_Boot information";
    if (fstat(up.caches->cachefd, &cachesb))  goto finish;	// get data
    if (!(devname_r(cachesb.st_dev,S_IFBLK,bsdname,DEVMAXPATHSIZE)))goto finish;
    if (BLCreateBooterInformationDictionary(NULL, bsdname, &bdict))
	goto finish;
    if (fstat(up.caches->cachefd, &cachesb))  goto finish;	// boots good?

    up.boots = CFDictionaryGetValue(bdict, kBLAuxiliaryPartitionsKey);
    if (!up.boots)  goto finish;	    // no Apple_Boots -> empty array
    bootcount = CFArrayGetCount(up.boots);
    if (!bootcount) {
	rval = 0;	// no boots -> nothing to do; byebye
	if (dashv > 0)	kextd_log("no helper partitions; skipping update");
	goto finish;
    }


    // Actually have boot partitions
    errmsg = "trouble analyzing what needs updating";
    // needUpdates populates our timestamp values for applyStamps
    if (needUpdates(up.caches, &doAny, &up.doRPS, &up.doBooters, &up.doMisc))
	goto finish;
    if (!doAny && !force) {
	rval = 0;
	if (dashv > 0)	kextd_log("helper partitions appear up to date");
	goto finish;
    }
    if (force)	up.doRPS = up.doBooters = up.doMisc = true;

    // Begin work on actual update :)	    [updateBoots vs. checkUpdateBoots?]
    errmsg = "trouble setting up DiskArb";
    if (!(up.dasession = DASessionCreate(nil)))  goto finish;
    DASessionScheduleWithRunLoop(up.dasession, CFRunLoopGetCurrent(),
	    kCFRunLoopDefaultMode);

    errmsg = "trouble updating one or more helper partitions";
    for (i = 0; i < bootcount; i++) {
	up.changestate = nothingSerious;		// init state
	if ((mountBoot(&up, i)))	goto bootfail; 	// sets curMount
	if (up.doRPS && ucopyRPS(&up))  goto bootfail;	// -> inactive
	if (up.doMisc) 	    	(void) ucopyMisc(&up);	// -> .new files

	if (nukeLabels(&up)) 		goto bootfail;  // always

	if (up.doBooters && ucopyBooters(&up))	        // .old still active
	    goto bootfail;
	if (up.doBooters && activateBooters(&up))	// oh boy
	    goto bootfail;
	// new booters remain mostly compatible with old kernels (power outage!)
	if (up.doRPS && activateRPS(&up))	  	// mv to safety
	    goto bootfail;
	if (activateMisc(&up, i))	goto bootfail;	// reverts label

	up.changestate = nothingSerious;
	bootupdates++;	    // loop success
	if (dashv > 1) {
	    kextd_log("successfully updated helper partition #%d", i);
	}

bootfail:
	if (dashv > 0 && up.changestate != nothingSerious) {
	    kextd_error_log("error updating helper partition #%d, state %d", i,
			    up.changestate);
	}
	// unroll any changes we may have made
	(void)revertState(&up);	    // smart enough to do nothing :)

	// always unmount
	if (nukeFallbacks(&up))	kextd_error_log("helper #%d may be untidy", i);
	if (unmountBoot(&up))  	kextd_error_log("unmount trouble??");
    }
    if (bootupdates != bootcount)  goto finish;

    errmsg = "trouble updating bootstamps";
    if (applyStamps(up.caches))	    goto finish;

    rval = 0;

finish:
    putVolumeForPath(volRoot, rval);		// handles not locked (& logs)

    if (bdict)		    CFRelease(bdict);
    if (up.curbootfd != -1) close(up.curbootfd);
    if (up.dasession) {
	DASessionUnscheduleFromRunLoop(up.dasession, CFRunLoopGetCurrent(),
		kCFRunLoopDefaultMode);
	CFRelease(up.dasession);
    }
    if (rval && errmsg) {
	    warnx("%s: %s", volRoot, errmsg);
    }

    return rval;
}

// ucopyBooters and activateBooters, backwards
static int revertState(struct updatingVol *up)
{
    int rval = 0;	// optimism to accumulate errors with |=
    char path[PATH_MAX], oldpath[PATH_MAX];
    struct bootCaches *caches = up->caches;
    Boolean doMisc;

    switch (up->changestate) {
	// inactive booters are still good
	case activatedBooters:
	    // we've blessed the new booters; so let's bless the old ones
	    pathcat(up->ofdst, OLDEXT);
	    pathcat(up->efidst, OLDEXT);
	    rval |= activateBooters(up);    // XX I hope this works
	case activatingEFIBooter:
    	case activatingOFBooter:	    // unneeded since 'bless' is one op
	case copiedBooters:
    	case copyingEFIBooter:
	if (caches->efibooter.rpath[0]) {
	    makebootpath(path, caches->efibooter.rpath);
	    pathcpy(oldpath, path);	    // old ones are blessed; rename
	    pathcat(oldpath, OLDEXT);
	    (void)sunlink(up->curbootfd, path);
	    rval |= srename(up->curbootfd, oldpath, path);
	}

    	case copyingOFBooter:
	if (caches->ofbooter.rpath[0]) {
	    makebootpath(path, caches->ofbooter.rpath);
	    pathcpy(oldpath, path);
	    pathcat(oldpath, OLDEXT);
	    (void)sunlink(up->curbootfd, path);
	    rval |= srename(up->curbootfd, oldpath, path);
	}

	// XX
	// case copyingMisc:
	// would clean up the .new turds

	case nukedLabels:
	    // XX hacky (c.f. nukeFallbacks which nukes .disabled label)
	    doMisc = up->doMisc;
	    up->doMisc = false;
	    rval |= activateMisc(up, 0);  // writes new label if !doMisc
	    up->doMisc = doMisc;

	case nothingSerious:
	    // everything is good
	    break;
    }

finish:
    return rval;
};

/*******************************************************************************
* mountBoot digs in for the root, and mounts up the Apple_Boots
* mountpoints are stored in up->bootparts
*******************************************************************************/
static int mountBoot(struct updatingVol *up, CFIndex bidx)
{
    int rval = ELAST + 1;
    char bsdname[DEVMAXPATHSIZE];
    CFStringRef mountargs[] = { CFSTR("perm"), CFSTR("nobrowse"), NULL };
    CFStringRef str;
    DADissenterRef dis = (void*)kCFNull;
    CFDictionaryRef ddesc = NULL;
    CFURLRef volURL;
    struct statfs bsfs;
    struct stat secsb;

    // request the Apple_Boot mount
    str = (CFStringRef)CFArrayGetValueAtIndex(up->boots, bidx);
    if (!str)  goto finish;
    if (!CFStringGetFileSystemRepresentation(str, bsdname, DEVMAXPATHSIZE))
	goto finish;
    if (!(up->curBoot = DADiskCreateFromBSDName(nil, up->dasession, bsdname)))
	goto finish;

    // 'prefmounturl' could contain bsdname?
    // DADiskMountWithArgument might call _daDone before it returns (e.g. if it
    // knows your request is impossible ... 
    // _daDone updates our 'dis[senter]'
    DADiskMountWithArguments(up->curBoot, NULL/*mnt*/,kDADiskMountOptionDefault,
   			     _daDone, &dis, mountargs);

    // ... so we use kCFNull and check the value before CFRunLoopRun()
    if (dis == (void*)kCFNull)
	CFRunLoopRun();		// stopped by _daDone (which updates 'dis')
    if (dis) {
	rval = DADissenterGetStatus(dis);
	// if it's already mounted, try to unmount it? (XX skank DEBUG(?) hack)
	if (rval == kDAReturnBusy && up->curMount[0] != '\1') {
	    up->curMount[0] = '\1';
	    if (0 == unmountBoot(up)) {
		// try again
		return mountBoot(up, bidx);
	    }
	}
	goto finish;
    }

    // get and stash the mountpoint of the boot partition
    if (!(ddesc = DADiskCopyDescription(up->curBoot)))  goto finish;
    volURL = CFDictionaryGetValue(ddesc, kDADiskDescriptionVolumePathKey);
    if (!volURL || CFGetTypeID(volURL) != CFURLGetTypeID())  goto finish;
    if (!CFURLGetFileSystemRepresentation(volURL, true /*resolve base*/,
	    (UInt8*)up->curMount, PATH_MAX))  	    goto finish;

    // Sec: get a non-spoofable handle to the current boot (trust moves)
    if (-1 == (up->curbootfd = open(up->curMount, O_RDONLY, 0)))   goto finish;
    if (fstat(up->caches->cachefd, &secsb))  goto finish;    // rootvol extant?

    // we only support 128 MB Apple_Boot partitions
    if (fstatfs(up->curbootfd, &bsfs))	goto finish;
    if (bsfs.f_blocks * bsfs.f_bsize < (128 * 1<<20)) {
	kextd_error_log("Apple_Boot < 128 MB; skipping");
	goto finish;
    }

    rval = 0;

finish:
    if (ddesc)	    CFRelease(ddesc);
    if (dis && dis != (void*)kCFNull) // for spurious CFRunLoopRun() return
	CFRelease(dis);

    if (rval != 0 && up->curBoot) {
	unmountBoot(up);	// unmount anything we managed to mount
    }
    if (rval) {
	kextd_error_log("couldn't mount helper: error %X (DA: %d)", rval,
			rval & ~(err_local|err_local_diskarbitration));
    }

    return rval;
}

/*******************************************************************************
* unmountBoot 
* works like mountBoot, but for unmount
*******************************************************************************/
static int unmountBoot(struct updatingVol *up)
{
    int rval = ELAST + 1;
    DADissenterRef dis = (void*)kCFNull;

    // bail if nothing to actually unmount (still free up curBoot below)
    if (!up->curBoot)  	    	goto finish;
    if (!up->curMount[0])   	goto finish;

    if (up->curbootfd != -1)	close(up->curbootfd);

    // _daDone populates 'dis'[senter]
    DADiskUnmount(up->curBoot, kDADiskMountOptionDefault, _daDone, &dis);
    if (dis == (void*)kCFNull)	    // in case _daDone already called
	CFRunLoopRun();

    // if that didn't work, try harder
    if (dis) {
	CFRelease(dis);
	dis = (void*)kCFNull;
	kextd_log("trouble unmounting boot partition; forcing...");
	DADiskUnmount(up->curBoot, kDADiskUnmountOptionForce, _daDone, &dis);
	if (dis == (void*)kCFNull)
	    CFRunLoopRun();
	if (dis)  goto finish;
    }

    rval = 0;

finish:
    up->curMount[0] = '\0';	// to keep tidy
    if (up->curBoot) {
	CFRelease(up->curBoot);
	up->curBoot = NULL;
    }
    if (dis && dis != (void*)kCFNull)
	CFRelease(dis);

    return rval;
}

/*******************************************************************************
* ucopyRPS unlinks old/copies new RPS content w/o activating
* RPS files are considered important -- non-zero file sizes only!
* XX could validate the kernel with Mach-o header
*******************************************************************************/
// if we were good, I'd be able to share "statRPS" with the efiboot sources
typedef int EFI_STATUS;
typedef struct stat EFI_FILE_HANDLE;
typedef char UINT16;
typedef Boolean BOOLEAN;
// typedef ...
/* 
:'a,'bs/EFI_ERROR//
:'a,'bs/L"/"/
:'a,'bs/%a/%s/
#define printf kextd_error_log
#define SPrint snprintf
#define EFI_NOT_FOUND ENOENT
#define BOOT_STRING_LEN PATH_MAX
*/
static int
FindRPSDir(struct updatingVol *up, char prev[PATH_MAX], char current[PATH_MAX],
	    char next[PATH_MAX])
{
     char rpath[PATH_MAX], ppath[PATH_MAX], spath[PATH_MAX];   
/*
 * FindRPSDir looks for a "rock," "paper," or "scissors" directory
 * - handle all permutations: 3 dirs, any 2 dirs, any 1 dir
 */
// static EFI_STATUS
// FindRPSDir(EFI_FILE_HANDLE BootDir, EFI_FILE_HANDLE *newBoot)
// 
    int rval = ELAST + 1, status;
    struct stat r, p, s;
    Boolean haveR, haveP, haveS;
    char *prevp, *curp, *nextp;

    haveR = haveP = haveS = false;
    prevp = curp = nextp = NULL;

    // set up full paths with intervening slash
    pathcpy(rpath, up->curMount);
    pathcat(rpath, "/");
    pathcpy(ppath, rpath);
    pathcpy(spath, rpath);

    pathcat(rpath, kBootDirR);
    pathcat(ppath, kBootDirP);
    pathcat(spath, kBootDirS);

    status = stat(rpath, &r);	// easier to let this fail
    haveR = (status == 0);
    status = stat(ppath, &p);
    haveP = (status == 0);
    status = stat(spath, &s);
    haveS = (status == 0);

    if (haveR && haveP && haveS) {    // NComb(3,3) = 1
        printf("WARNING: all of R,P,S exist: picking 'R'\n");
	curp = rpath;	nextp = ppath;	prevp = spath;
    }   else if (haveR && haveP) {          // NComb(3,2) = 3
        // p wins
	curp = ppath;	nextp = spath;	prevp = rpath;
    } else if (haveR && haveS) {
        // r wins
	curp = rpath;	nextp = ppath;	prevp = spath;
    } else if (haveP && haveS) {
        // s wins
	curp = spath; 	nextp = rpath;	prevp = ppath;
    } else if (haveR) {                     // NComb(3,1) = 3
        // r wins by default
	curp = rpath;	nextp = ppath;	prevp = spath;
    } else if (haveP) {
        // p wins by default
	curp = ppath;	nextp = spath;	prevp = rpath;
    } else if (haveS) {
        // s wins by default
	curp = spath; 	nextp = rpath;	prevp = ppath;
    } else {                                          // NComb(3,0) = 0
	// we'll start with rock
	curp = rpath;	nextp = ppath;	prevp = spath;
    }

    if (strlcpy(prev, prevp, PATH_MAX) >= PATH_MAX)	goto finish;
    if (strlcpy(current, curp, PATH_MAX) >= PATH_MAX)	goto finish;
    if (strlcpy(next, nextp, PATH_MAX) >= PATH_MAX)	goto finish;

    rval = 0;

finish:
    //DPRINTF("FindRPSDir returning %x (boot = %x)\n", rval, *newBoot);
    //DPAUSE();
    return rval;
}
// #undef printf

// UUID helper for ucopyRPS
static int insertUUID(struct updatingVol *up, char *srcpath, char *dstpath)
{
    int rval = ELAST + 1;
    int fd = -1;
    struct stat sb;
    void *buf;
    CFDataRef data = NULL;
    CFMutableDictionaryRef pldict = NULL;
    CFIndex len;

    mode_t dirmode;
    char dstparent[PATH_MAX];

    // suck in plist
    if (-1 == (fd = sopen(up->caches->cachefd, srcpath, O_RDONLY, 0)))
	goto finish;
    if (fstat(fd, &sb))	    			    	goto finish;
    if (!(buf = malloc(sb.st_size)))		    	goto finish;
    if (read(fd, buf, sb.st_size) != sb.st_size)    	goto finish;
    if (!(data = CFDataCreate(nil, buf, sb.st_size))) 	goto finish;
    // make mutable dictionary
    pldict = (CFMutableDictionaryRef)CFPropertyListCreateFromXMLData(nil, data,
	    kCFPropertyListMutableContainers, NULL /* errstring */);
    if (!pldict || CFGetTypeID(pldict)!=CFDictionaryGetTypeID()) {
	// maybe the plist is empty
	pldict = CFDictionaryCreateMutable(nil, 0 /* could be 1 */, 
	    &kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
	if (!pldict)	goto finish;
    }

    // insert key we got previously from DA
    CFDictionarySetValue(pldict, CFSTR(kRootUUIDKey), up->caches->volUUIDStr);


    // and write dictionary back

    (void)sunlink(up->curbootfd, dstpath);

    // figure out directory mode
    dirmode = ((sb.st_mode&~S_IFMT) | S_IWUSR | S_IXUSR /* u+wx */);
    if (dirmode & S_IRGRP)      dirmode |= S_IXGRP;     // add conditional o+x
    if (dirmode & S_IROTH)      dirmode |= S_IXOTH;

    // and recursively create the parent directory       
    if (strlcpy(dstparent, dirname(dstpath), PATH_MAX) >= PATH_MAX)  goto finish;
    if ((sdeepmkdir(up->curbootfd, dstparent, dirmode)))            goto finish;

    close(fd);
    if (-1 == (fd=sopen(up->curbootfd, dstpath, O_WRONLY|O_CREAT, sb.st_mode)))
	goto finish;
    CFRelease(data);
    if (!(data = CFPropertyListCreateXMLData(nil, pldict)))	goto finish;
    len = CFDataGetLength(data);
    if (write(fd, CFDataGetBytePtr(data), len) != len)		goto finish;

    rval = 0;

finish:
    if (data)	    CFRelease(data);
    if (pldict)     CFRelease(pldict);
    if (fd != -1)   close(fd);

    return rval;
}

// we can bail on any error because only a whole RPS dir makes sense
static int ucopyRPS(struct updatingVol *up)
{
    int rval = ELAST+1;
    char discard[PATH_MAX];
    struct stat sb;
    int i;
    char srcpath[PATH_MAX], dstpath[PATH_MAX];

    // we're going to copy into the currently-inactive directory
    if (FindRPSDir(up, up->curRPS, discard, discard))  goto finish;

    // erase if present (we expect to have removed it)
    if (stat(up->curRPS, &sb) == 0) {
	if (sdeepunlink(up->curbootfd, up->curRPS))   goto finish;
    }

    // create the directory
    if (smkdir(up->curbootfd, up->curRPS, kRPSDirMask))	    goto finish;

    // and loop
    for (i = 0; i < up->caches->nrps; i++) {
	pathcpy(srcpath, up->caches->root);
	pathcat(srcpath, up->caches->rpspaths[i].rpath);
	pathcpy(dstpath, up->curRPS);
	pathcat(dstpath, up->caches->rpspaths[i].rpath);

	// is it Boot.plist?
	if (&up->caches->rpspaths[i] == up->caches->bootconfig) {
	    if (insertUUID(up, srcpath, dstpath)) {
		kextd_error_log("error populating config file %s", dstpath);
		continue;
	    }
	} else {
	    // XX Leopard(?) other checks like is your Mach-O complete?
	    if (stat(srcpath, &sb) == 0 && sb.st_size == 0) {
		kextd_error_log("zero-size RPS file %s?", srcpath);
		goto finish;
	    }
	    // scopyfile creates any intermediate directories
	    if (scopyfile(up->caches->cachefd,srcpath,up->curbootfd,dstpath)) {
		kextd_error_log("error copying %s", srcpath);
		goto finish;
	    }
	}
    }

    rval = 0;

finish:

    return rval;
}

/*******************************************************************************
* ucopyMisc writes misc files (customizing labels ;?) to .new (inactive) names
* [redundant label copy would be easy to avoid]
*******************************************************************************/
static int ucopyMisc(struct updatingVol *up)
{
    int rval = -1;
    int i, nprocessed = 0;
    char srcpath[PATH_MAX], dstpath[PATH_MAX];
    struct stat sb;

    for (i = 0; i < up->caches->nmisc; i++) {
	pathcpy(srcpath, up->caches->root);
	pathcat(srcpath, up->caches->miscpaths[i].rpath);
	pathcpy(dstpath, up->curMount);
	pathcat(dstpath, up->caches->miscpaths[i].rpath);
	pathcat(dstpath, ".new");

	if (stat(srcpath, &sb) == 0) { 
	    if (scopyfile(up->caches->cachefd,srcpath,up->curbootfd,dstpath)) {
		kextd_error_log("error copying %s to %s", srcpath, dstpath);
	    }
	    continue;
	}

	nprocessed++;
    }

    rval = (nprocessed != i);

finish:
    return rval;
}

/*******************************************************************************
* since activateLabels will create a new label every time, we just nuke
* no label -> hint of indeterminate state (label key in plist/other file?)
* Leopard: put/switch in some sort of "(updating!)" label (see BL[ess] routines)
*******************************************************************************/
static int nukeLabels(struct updatingVol *up)
{
    int rval = 0;
    char labelp[PATH_MAX];
    struct stat sb;

    pathcpy(labelp, up->curMount);
    pathcat(labelp, up->caches->label->rpath);
    if (0 == (stat(labelp, &sb))) {
	rval |= sunlink(up->curbootfd, labelp);
    } 

    // now for the content details (if any)
    pathcat(labelp, CONTENTEXT);	// append extension

    if (0 == (stat(labelp, &sb))) {
	rval |= sunlink(up->curbootfd, labelp);
    }

    up->changestate = nukedLabels;

finish:
    return rval;
}

/*******************************************************************************
* ucopyBooters unlink/copies down booters but doesn't bless them
*******************************************************************************/
static int ucopyBooters(struct updatingVol *up)
{
    int rval = ELAST + 1;
    char srcpath[PATH_MAX], oldpath[PATH_MAX];

    // copy BootX, boot.efi
    up->changestate = copyingOFBooter;
    if (up->caches->ofbooter.rpath[0]) {
	pathcpy(srcpath, up->caches->root);
	pathcat(srcpath, up->caches->ofbooter.rpath);   // <root>/S/L/CS/BootX
	pathcpy(up->ofdst, up->curMount);
	pathcat(up->ofdst, up->caches->ofbooter.rpath); // <boot>/S/L/CS/BootX
	pathcpy(oldpath, up->ofdst);
	pathcat(oldpath, OLDEXT);	    	   // <boot>/S/L/CS/BootX.old

	(void)sunlink(up->curbootfd, oldpath);
	if (srename(up->curbootfd, up->ofdst, oldpath))	    goto finish;
	if (scopyfile(up->caches->cachefd, srcpath, up->curbootfd, up->ofdst)) {
	    kextd_error_log("failure copying booter %s", srcpath);
	    goto finish;
	}
    }

    up->changestate = copyingEFIBooter;
    if (up->caches->efibooter.rpath[0]) {
	pathcpy(srcpath, up->caches->root);
	pathcat(srcpath, up->caches->efibooter.rpath);   // ... boot.efi
	pathcpy(up->efidst, up->curMount);
	pathcat(up->efidst, up->caches->efibooter.rpath);
	pathcpy(oldpath, up->efidst);
	pathcat(oldpath, OLDEXT);

	(void)sunlink(up->curbootfd, oldpath);
	if (srename(up->curbootfd, up->efidst, oldpath) && errno != ENOENT)
	    goto finish;
	if (scopyfile(up->caches->cachefd, srcpath, up->curbootfd, up->efidst)){
	    kextd_error_log("failure copying booter %s", srcpath);
	    goto finish;
	}
    }

    up->changestate = copiedBooters;
    rval = 0;

finish:
    return rval;
}


// booters have worst critical:fragile ratio (basically point of no return)
/*******************************************************************************
* bless recently-copied booters
* operatens entirely on up->??dst which allows revertState to use it ..?
*******************************************************************************/
#define CLOSE(fd) do { (void)close(fd); fd = -1; } while(0)
enum blessIndices {
    kSystemFolderIdx = 0,
    kEFIBooterIdx = 1
    // Apple_Boot doesn't use 2-7
};
static int activateBooters(struct updatingVol *up)
{
    int rval = ELAST + 1;
    int fd = -1;
    uint32_t vinfo[8] = { 0, };
    struct stat sb;
    char parent[PATH_MAX];

    // activate BootX, boot.efi
    up->changestate = activatingOFBooter;
    if (up->caches->ofbooter.rpath[0]) {
	unsigned char tbxichrp[32] = {'t','b','x','i','c','h','r','p','\0',};

	// flush booter bytes to disk (really)
	if (-1 == (fd=sopen(up->curbootfd, up->ofdst, O_RDWR, 0)))  goto finish;
	if (fcntl(fd, F_FULLFSYNC))			    	    goto finish;

	// apply type/creator (assuming same folder as previous, now active)
	if(fsetxattr(fd,XATTR_FINDERINFO_NAME,&tbxichrp,sizeof(tbxichrp),0,0))
	    goto finish;
	CLOSE(fd);

	// get fileID of booter's enclosing folder 
	pathcpy(parent, dirname(up->ofdst));		    goto finish;
	if (-1 == (fd=sopen(up->curbootfd, parent, O_RDONLY, 0)))  goto finish;
	if (fstat(fd, &sb))				    goto finish;
	CLOSE(fd);
	vinfo[kSystemFolderIdx] = sb.st_ino;
    }

    up->changestate = activatingEFIBooter;
    if (up->caches->efibooter.rpath[0]) {
	// sync to disk
	if (-1==(fd=sopen(up->curbootfd, up->efidst, O_RDONLY, 0))) goto finish;
	if (fcntl(fd, F_FULLFSYNC))				    goto finish;

	// get file ID
	if (fstat(fd, &sb))	goto finish;
	CLOSE(fd);
	vinfo[kEFIBooterIdx] = sb.st_ino;

	// since Inca has only one booter, but we want a blessed folder
	if (!vinfo[0]) {
	    // get fileID of booter's enclosing folder 
	    pathcpy(parent, dirname(up->efidst));
	    if (-1 == (fd=sopen(up->curbootfd, parent, O_RDONLY, 0)))
		goto finish;
	    if (fstat(fd, &sb))				    goto finish;
	    CLOSE(fd);
	    vinfo[kSystemFolderIdx] = sb.st_ino;
	}
    }

    // blessing efiboot/sysfolder happens by updating the root of the volume
    if (schdir(up->curbootfd, up->curMount, &fd))	    goto finish;
    if ((rval = BLSetVolumeFinderInfo(NULL, ".", vinfo)))   goto finish;
    (void)restoredir(fd);	    // tidy up (closes fd)
    fd = -1;

    up->changestate = activatedBooters;

finish:
    if (fd != -1)   close(fd);
    return rval;
}

/*******************************************************************************
* leap-frog w/rename() :)
*******************************************************************************/
static int activateRPS(struct updatingVol *up)
{
    int rval = ELAST + 1;
    char prevRPS[PATH_MAX], curRPS[PATH_MAX], nextRPS[PATH_MAX];

    if (FindRPSDir(up, prevRPS, curRPS, nextRPS))   goto finish;

    // if current != the one we just populated
    if (strncmp(curRPS, up->curRPS, PATH_MAX) != 0) {
	// rename prev -> next ... done!?
	if (srename(up->curbootfd, prevRPS, nextRPS))   goto finish;
    }

    // thwunk everything to disk (now that essential boot files are in place)
    if (fcntl(up->curbootfd, F_FULLFSYNC))	    	goto finish;

    rval = 0;

finish:
    return rval;
}


/*******************************************************************************
* activateMisc renames .new files to final names
* active labels indicate an updated system
* - construct new labels with trailing numbers
* - use BLGenerateOFLabel() and overwrite any copied-down label
* X need to be consistent throughout regarding missing misc files (esp. label?)
*******************************************************************************/
#ifndef OPENSOURCE	// BLGenerateOFLabel uses CG
static int writeLabels(struct updatingVol *up, char *labelp, int bidx)
{
    int rval = ELAST + 1;
    CFDataRef lData = NULL;
    CFIndex len;
    int fd = -1;
    char bootname[NAME_MAX];
    char contentPath[PATH_MAX];

    if (NAME_MAX <= snprintf(bootname, NAME_MAX, "%s %d",
    			    up->caches->volname, bidx + 1))
	goto finish;
    if (BLGenerateOFLabel(NULL, bootname, &lData))	goto finish;

    // write the data
    if (-1 == (fd = sopen(up->curbootfd, labelp, O_CREAT|O_WRONLY, 0644)))
	goto finish;
    len = CFDataGetLength(lData);
    if (write(fd, CFDataGetBytePtr(lData), len) != len)	goto finish;

    // and write the content detail
    pathcpy(contentPath, labelp);
    pathcat(contentPath, CONTENTEXT);
    close(fd);
    if (-1 == (fd = sopen(up->curbootfd, contentPath, O_CREAT|O_WRONLY, 0644)))
	goto finish;
    len = strlen(up->caches->volname);
    if (write(fd, up->caches->volname, len) != len)	goto finish;

    rval = 0;

finish:
    if (fd != -1)   close(fd);
    if (lData)	    CFRelease(lData);

    return rval;
}
#endif	// OPENSOURCE

static int activateMisc(struct updatingVol *up, int bidx)   // rename any .new
{
    int rval = ELAST + 1;
    char labelp[PATH_MAX], path[PATH_MAX], opath[PATH_MAX];
    int i = 0, nprocessed = 0;
    int fd = -1;
    struct stat sb;
    unsigned char tbxjchrp[32] = { 't','b','x','j','c','h','r','p','\0', };

    if (up->doMisc) {
	// do them all
	for (i = 0; i < up->caches->nmisc; i++) {
	    if (strlcpy(path, up->curMount, PATH_MAX) >= PATH_MAX)   continue;
	    if (strlcat(path, up->caches->miscpaths[i].rpath, PATH_MAX) 
			> PATH_MAX)   continue;
	    if (strlcpy(opath, path, PATH_MAX) >= PATH_MAX)	continue;
	    if (strlcat(opath, NEWEXT, PATH_MAX) >= PATH_MAX)	continue;

	    if (stat(opath, &sb) == 0) {
		if (srename(up->curbootfd, opath, path))	continue;
	    }

	    nprocessed++;
	}

    }

    // write labels
    pathcpy(labelp, up->curMount);
    pathcat(labelp, up->caches->label->rpath);
#ifndef OPENSOURCE
    (void)sunlink(up->curbootfd, labelp);
    if (writeLabels(up, labelp, bidx))	    goto finish;
#endif

    // assign type/creator to the label (non-OPENSOURCE might have copied)
    if (0 == (stat(labelp, &sb))) {
	if (-1 == (fd = sopen(up->curbootfd, labelp, O_RDWR, 0)))   goto finish;

	if (fsetxattr(fd,XATTR_FINDERINFO_NAME,&tbxjchrp,sizeof(tbxjchrp),0,0))
	    goto finish;
    }

    rval = (i != nprocessed);

finish:
    if (fd != -1)   close(fd);
    return rval;
}

/*******************************************************************************
* get rid of everything "extra"
*******************************************************************************/
static int nukeFallbacks(struct updatingVol *up)
{
    int rval = 0;		// OR-ative return value
    int bsderr;
    char delpath[PATH_MAX];
    struct bootCaches *caches = up->caches;

    // using pathcpy b/c if that's failing, it's worth bailing
    // XX should probably only try to unlink if present

    // maybe mount failed (in which there aren't any fallbacks
    if (!up->curBoot)	goto finish;

    // if needed, unlink .old booters
    if (up->doBooters) {
	if (caches->ofbooter.rpath[0]) {
	    makebootpath(delpath, caches->ofbooter.rpath);
	    pathcat(delpath, OLDEXT);
	    if ((bsderr = sunlink(up->curbootfd, delpath)) && errno != ENOENT) {
		rval |= bsderr;
	    }
	}
	if (caches->efibooter.rpath[0]) {
	    makebootpath(delpath, caches->efibooter.rpath);
	    pathcat(delpath, OLDEXT);
	    if ((bsderr = sunlink(up->curbootfd, delpath)) && errno != ENOENT) {
		rval |= bsderr;
	    }
	}
    }

    // if needed, deepunlink prevRPS
    // which, conveniently, will be right regardless of whether we succeeded :)
    if (up->doRPS) {
	char toss[PATH_MAX];

	if (0 == FindRPSDir(up, delpath, toss, toss)) {
	    if ((bsderr=sdeepunlink(up->curbootfd,delpath)) && bsderr!=ENOENT) {
		rval |= bsderr;
	    }
	}
    }

finish:
    return rval;
}
