/*
 * FILE: bootcaches.c [is the correct name!]
 * AUTH: Soren Spies (sspies)
 * DATE: "spring" 2006
 * DESC: routines for bootcache data
 *
 */

#include <bless.h>
#include <bootfiles.h>		// eventually "new" bootcaches.h
#include <IOKit/IOKitLib.h>
#include <fcntl.h>
#include <libgen.h>
#include <notify.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <unistd.h>

#include <Kernel/IOKit/IOKitKeysPrivate.h>
#include <Kernel/libsa/mkext.h>
#include <DiskArbitration/DiskArbitration.h>	// for UUID fetching :P
#include <IOKit/kext/kextmanager_types.h>       // DEVMAXPATHSIZE    

#include "logging.h"
#include "fat_util.h"
#include "macho_util.h"
#include "mkext_util.h"
#include "bootroot.h"	    // includes CF
#include "safecalls.h"


// XX prototypes for external functions need to be in header files!
MkextCRCResult getMkextCRC(const char * file_path, uint32_t * crc_ptr);
char *         copyKernelVersion(const char * kernel_file);

#define NCHARSUUID (2*sizeof(CFUUIDBytes) + 5)	// hex with 4 -'s and one NUL

// X these could take a label/action as their third parameter
#define pathcpy(dst, src) do { \
        if (strlcpy(dst, src, PATH_MAX) >= PATH_MAX)  goto finish; \
    } while(0)
#define pathcat(dst, src) do { \
        if (strlcat(dst, src, PATH_MAX) >= PATH_MAX)  goto finish; \
    } while(0)

/******************************************************************************
* destroyCaches cleans up a bootCaches structure
******************************************************************************/
void destroyCaches(struct bootCaches *caches)
{
    if (caches->cachefd != -1)	close(caches->cachefd);
    if (caches->volUUIDStr)	CFRelease(caches->volUUIDStr);
    if (caches->cacheinfo)    	CFRelease(caches->cacheinfo);
    if (caches->miscpaths)  	free(caches->miscpaths);  // free all strings
    if (caches->rpspaths)	free(caches->rpspaths);
    free(caches);
}

/******************************************************************************
* readCaches checks for and reads bootcaches.plist
******************************************************************************/
// used for turning /foo/bar into :foo:bar for kTSCacheDir entries (see awk(1))
static void gsub(char old, char new, char *s)
{
    char *p;

    while((p = s++) && *p)
	if (*p == old)
	    *p = new;
}

// fillCachedPath is available for external callers (so no 'static')
int fillCachedPath(cachedPath *cpath, char *uuidchars, char *relpath)
{
    int rval = ELAST + 1;

    if (strlcat(cpath->tspath, kTSCacheDir, PATH_MAX) >= PATH_MAX) goto finish;
    pathcat(cpath->tspath, uuidchars);
    pathcat(cpath->tspath, "/");

    // now append the actual path and stamp name
    if (strlcat(cpath->rpath, relpath, PATH_MAX) >= PATH_MAX) goto finish;
    gsub('/', ':', relpath);
    if (strlcat(cpath->tspath, relpath, PATH_MAX) >= PATH_MAX) goto finish;

    rval = 0;

finish:
    return rval;
}

// wrap the published fillCachedPath with that which we always do
#define str2cachedPath(cpath, caches, relstr) \
do { \
    char relpath[PATH_MAX], uuidchars[NCHARSUUID]; \
\
    if (!CFStringGetFileSystemRepresentation(relstr, relpath, PATH_MAX)) \
	goto finish; \
    if(!CFStringGetCString(caches->volUUIDStr, uuidchars, NCHARSUUID, \
	    kCFStringEncodingASCII)) 	goto finish; \
    if (fillCachedPath(cpath, uuidchars, relpath))  goto finish; \
} while(0)

// dict -> struct bootCaches
static struct bootCaches*
parseDict(CFDictionaryRef bcDict, char *rootpath, char **errmsg,
	CFStringRef volUUIDStr, CFStringRef volName)
{
    // for the dictionary
    struct bootCaches *caches, *rval = NULL;
    CFDictionaryRef dict;	// don't release
    CFIndex keyCount;	// track whether we've handled all keys
    CFStringRef str;
    // char path[PATH_MAX];

    // XX could calloc should be in caller :P:P
    *errmsg = "allocation failure";	    	
    caches = calloc(1, sizeof(*caches));
    if (!caches)  goto finish;
    caches->cachefd = -1;			// so destroy knows what's up
    pathcpy(caches->root, rootpath);
    if (!volUUIDStr)	    goto finish;
    caches->volUUIDStr = CFRetain(volUUIDStr);
    if (!CFStringGetFileSystemRepresentation(volName,caches->volname,NAME_MAX))
	goto finish;


    *errmsg = "unsupported bootcaches data";	// covers most of parseDict()

    keyCount = CFDictionaryGetCount(bcDict);	// start with the top

    // process keys for paths read "before the booter"
    dict = (CFDictionaryRef)CFDictionaryGetValue(bcDict, kBCPreBootKey);
    if (dict) {
	CFArrayRef apaths;
	CFIndex miscindex = 0;

	if (CFGetTypeID(dict) != CFDictionaryGetTypeID())  goto finish;
	caches->nmisc = CFDictionaryGetCount(dict);	// >= 1 path / key
	keyCount += CFDictionaryGetCount(dict);

	// variable-sized member first
	apaths = (CFArrayRef)CFDictionaryGetValue(dict, kBCAdditionalPathsKey);
	if (apaths) {
	    CFIndex acount;

	    if (CFArrayGetTypeID() != CFGetTypeID(apaths))  goto finish;
	    acount = CFArrayGetCount(apaths);
	    // total "misc" paths = # of keyed paths + # additional paths
	    caches->nmisc += acount - 1;   // replacing array in misc count

	    if (caches->nmisc > INT_MAX/sizeof(*caches->miscpaths)) goto finish;
	    caches->miscpaths = (cachedPath*)calloc(caches->nmisc,
		    sizeof(*caches->miscpaths));
	    if (!caches->miscpaths)  goto finish;

	    for (/*miscindex = 0 (above)*/; miscindex < acount; miscindex++) {
		str = CFArrayGetValueAtIndex(apaths, miscindex);
		if (CFGetTypeID(str) != CFStringGetTypeID())  goto finish;

		str2cachedPath(&caches->miscpaths[miscindex], caches, str);  // M
	    }
	    keyCount--;	// AdditionalPaths sub-key
	} else {
	    // allocate enough for the top-level keys (nothing variable-sized)
	    if (caches->nmisc > INT_MAX/sizeof(*caches->miscpaths)) goto finish;
	    caches->miscpaths = calloc(caches->nmisc, sizeof(cachedPath));
	    if (!caches->miscpaths)	goto finish;
	}

	str = (CFStringRef)CFDictionaryGetValue(dict, kBCLabelKey);
	if (str) {
	    if (CFGetTypeID(str) != CFStringGetTypeID())  goto finish;
	    str2cachedPath(&caches->miscpaths[miscindex], caches, str); // macro
	    caches->label = &caches->miscpaths[miscindex];

	    miscindex++;	    // get ready for the next guy:)
	    keyCount--;	    // DiskLabel is dealt with
	}

	// add new keys here
	keyCount--;	// preboot dict
    }

    // process booter keys
    dict = (CFDictionaryRef)CFDictionaryGetValue(bcDict, kBCBootersKey);
    if (dict) {
	if (CFGetTypeID(dict) != CFDictionaryGetTypeID())  goto finish;
	keyCount += CFDictionaryGetCount(dict);

	str = (CFStringRef)CFDictionaryGetValue(dict, kBCEFIBooterKey);
	if (str) {
	    if (CFGetTypeID(str) != CFStringGetTypeID())  goto finish;
	    str2cachedPath(&caches->efibooter, caches, str);  // macro

	    keyCount--;	    // EFIBooter is dealt with
	}

	/*
	str = (CFStringRef)CFDictionaryGetValue(dict, kBCOFBooterKey);
	if (str) {
	    if (CFGetTypeID(str) != CFStringGetTypeID())  goto finish;
	    str2cachedPath(&caches->ofbooter, caches, str);  // macro

	    keyCount--;	    // hard to test BootX right now
	}
	*/

	// add new booters here
	keyCount--;	// booters dict
    }

    dict = (CFDictionaryRef)CFDictionaryGetValue(bcDict, kBCPostBootKey);
    if (dict) {
	CFDictionaryRef mkDict;
	CFArrayRef apaths;
	CFIndex rpsindex = 0;

	if (CFGetTypeID(dict) != CFDictionaryGetTypeID())  goto finish;
	keyCount += CFDictionaryGetCount(dict);
	caches->nrps = CFDictionaryGetCount(dict);	// >= 1 path / key

	// variable-sized member first
	apaths = (CFArrayRef)CFDictionaryGetValue(dict, kBCAdditionalPathsKey);
	if (apaths) {
	    CFIndex acount;

	    if (CFArrayGetTypeID() != CFGetTypeID(apaths))  goto finish;
	    acount = CFArrayGetCount(apaths);
	    // total rps paths = # of keyed paths + # additional paths
	    caches->nrps += acount - 1;   // replace array w/contents in nrps

	    if (caches->nrps > INT_MAX/sizeof(*caches->rpspaths)) goto finish;
	    caches->rpspaths = (cachedPath*)calloc(caches->nrps,
		    sizeof(*caches->rpspaths));
	    if (!caches->rpspaths)  goto finish;

	    for (; rpsindex < acount; rpsindex++) {
		str = CFArrayGetValueAtIndex(apaths, rpsindex);
		if (CFGetTypeID(str) != CFStringGetTypeID())  goto finish;

		str2cachedPath(&caches->rpspaths[rpsindex], caches, str); // M
	    }
	    keyCount--;	// AdditionalPaths sub-key
	} else {
	    // allocate enough for the top-level keys (nothing variable-sized)
	    if (caches->nrps > INT_MAX/sizeof(*caches->rpspaths)) goto finish;
	    caches->rpspaths = calloc(caches->nrps, sizeof(cachedPath));
	    if (!caches->rpspaths)	goto finish;
	}

	str = (CFStringRef)CFDictionaryGetValue(dict, kBCBootConfigKey);
	if (str) {
	    if (CFGetTypeID(str) != CFStringGetTypeID())  goto finish;
	    str2cachedPath(&caches->rpspaths[rpsindex], caches, str);  // M

	    caches->bootconfig = &caches->rpspaths[rpsindex++];
	    keyCount--;	    // handled BootConfig
	}

	mkDict = (CFDictionaryRef)CFDictionaryGetValue(dict, kBCMKextKey);
	if (mkDict) {
	    if (CFGetTypeID(mkDict) != CFDictionaryGetTypeID())  goto finish;

	    // path to mkext itself
	    str = (CFStringRef)CFDictionaryGetValue(mkDict, kBCPathKey);
	    if (CFGetTypeID(str) != CFStringGetTypeID())  goto finish;
	    str2cachedPath(&caches->rpspaths[rpsindex], caches, str);	// M

	    // get the Extensions folder path and set up exts by hand
	    str=(CFStringRef)CFDictionaryGetValue(mkDict, kBCExtensionsDirKey);
	    if (str) {
		char path[PATH_MAX];
		if (CFGetTypeID(str) != CFStringGetTypeID())  goto finish;
		if (!CFStringGetFileSystemRepresentation(str, path, PATH_MAX))
		    goto finish;

		if (strlcat(caches->exts, path, PATH_MAX) >= PATH_MAX)
		    goto finish;
	    }

	    // Archs are fetched from the cacheinfo dictionary when needed
	    caches->mkext = &caches->rpspaths[rpsindex++];
	    keyCount--;	    // mkext key handled
	}

	keyCount--;	// postBootPaths handled
    }


    if (keyCount) {
	*errmsg = "unknown (assumed required) keys in bootcaches.plist";
    } else {
	// hooray
	*errmsg = NULL;
	caches->cacheinfo = CFRetain(bcDict);	// for archs, etc
	rval = caches;
    }

finish:
    if (!rval) { 
	if (caches)  destroyCaches(caches);	// note close(cfd) in caller
    }

    return rval;
}

struct bootCaches* readCaches(char *rootpath)
{
    struct bootCaches *rval = NULL;
    char *errmsg;
    int errnum = 4;	
    char bcpath[PATH_MAX];
    int cfd = -1;
    void *bcbuf = NULL;
    struct stat bcsb;
    CFDictionaryRef bcProps = NULL;
    CFDataRef bcData = NULL;
    CFDictionaryRef bcDict = NULL;

    struct stat sb;
    char bsdname[DEVMAXPATHSIZE];
    DASessionRef dasession = NULL;
    DADiskRef disk = NULL;
    CFDictionaryRef ddesc = NULL;
    CFUUIDRef voluuid;
    CFStringRef volName, uuidStr = NULL;
    char bspath[PATH_MAX], uuidchars[NCHARSUUID];

    errmsg = "error reading " kBootCachesPath;
    if (strlcpy(bcpath, rootpath, PATH_MAX) >= PATH_MAX)  goto finish;
    if (strlcat(bcpath, kBootCachesPath, PATH_MAX) >= PATH_MAX)  goto finish;
    if (-1 == (cfd = open(bcpath, O_RDONLY|O_EVTONLY))) {
	if (errno == ENOENT)	errmsg = NULL;
	goto finish;
    }
    if (fstat(cfd, &bcsb)) 	goto finish;

    // check the owner and mode (switched from no-fd-avail CF lameness)
    // since root can see UID 99, we here ignore disrepected volumes
    // note: 'cp m_k /Volumes/disrespected/' already broken (shouldn't boot)
    if (bcsb.st_uid!= 0) {
	if (bcsb.st_uid != 99) {    // avoid spamming the log for ignored owners
	    errmsg = kBootCachesPath " not owned by root; no rebuilds";
	} else {
	    errmsg = NULL;
	}
	goto finish;
    }
    if (bcsb.st_mode & S_IWGRP || bcsb.st_mode & S_IWOTH) {
	errmsg = kBootCachesPath " writable by non-root";
	goto finish;
    }

    // okay, go ahead and read it
    if (!(bcbuf = malloc(bcsb.st_size)))  goto finish;
    if (read(cfd, bcbuf, bcsb.st_size) != bcsb.st_size)  goto finish;
    if (!(bcData = CFDataCreate(nil, bcbuf, bcsb.st_size)))  goto finish;

    errmsg = kBootCachesPath " doesn't contain a dictionary";
    // Sec: might want to switch XML parsers (see 4623105)
    bcDict = (CFDictionaryRef)CFPropertyListCreateFromXMLData(nil,
		bcData, kCFPropertyListImmutable, NULL);
    if (!bcDict || CFGetTypeID(bcDict)!=CFDictionaryGetTypeID())
	goto finish; 

    errmsg = "couldn't get volume UUID";
    // get and stash volume UUID from DA
    if (!(dasession = DASessionCreate(nil)))		goto finish;
    if (!(devname_r(bcsb.st_dev,S_IFBLK,bsdname,DEVMAXPATHSIZE))) goto finish;
    if (!(disk = DADiskCreateFromBSDName(nil, dasession, bsdname))) goto finish;
    if (!(ddesc = DADiskCopyDescription(disk)))         goto finish;
    if (!(voluuid=CFDictionaryGetValue(ddesc,kDADiskDescriptionVolumeUUIDKey)))
        goto finish;
    if (!(uuidStr = CFUUIDCreateString(nil, voluuid)))  goto finish;
    if (!(volName=CFDictionaryGetValue(ddesc,kDADiskDescriptionVolumeNameKey)))
	goto finish;

    errmsg = "bootstamps cache problem";
    if (strlcpy(bspath, rootpath, PATH_MAX) >= PATH_MAX)  goto finish;
    if (strlcat(bspath, kTSCacheDir, PATH_MAX) >= PATH_MAX)  goto finish;
    if(!CFStringGetCString(uuidStr,uuidchars,NCHARSUUID,kCFStringEncodingASCII))
	goto finish;
    pathcat(bspath, uuidchars);

    if ((errnum = stat(bspath, &sb))) {
	if (errno == ENOENT) {
	    // s..mkdir ensures the cache directory is on the volume
	    if ((errnum = sdeepmkdir(cfd, bspath, kTSCacheMask)))  goto finish;
	}
	else
	    goto finish;
    }

    // and turn the dictionary into a structure (XX messier and messier)
    rval = parseDict(bcDict, rootpath, &errmsg, uuidStr, volName);
    if (!rval)  goto finish;

    // pass along goodies from above (XX calloc should have been above)
    rval->cachefd = cfd;	// Sec: so we can make sure it's valid later

    errmsg = NULL;		// we made it!

finish:
    if (bcbuf)	    free(bcbuf);
    if (bcData)     CFRelease(bcData);
    if (bcProps)    CFRelease(bcProps);
    if (bcDict)     CFRelease(bcDict);	// retained for struct in parseDict ;p
    if (ddesc)      CFRelease(ddesc);
    if (disk)       CFRelease(disk);
    if (dasession)  CFRelease(dasession);

    if (errmsg) {
	if (errnum == -1)
	    kextd_error_log("%s: %s: %s", rootpath, errmsg, strerror(errno));
	else
	    kextd_error_log("%s: %s", rootpath, errmsg);
    }

    if (!rval) {
	// X should be destroyCaches and calloc should be in this func, etc
	if (cfd != -1)	close(cfd);
	if (uuidStr)	CFRelease(uuidStr);
    }

    return rval;
}

/*******************************************************************************
* needsUpdate checks a single path and timestamp; populates path->tstamp
* X: will we need a way to compare w/tstamp or can we just use the bootstamp?
*******************************************************************************/
int needsUpdate(char *root, cachedPath* cpath, Boolean *outofdate)
{
    Boolean ood;
    int bsderr = -1;
    struct stat rsb, tsb;
    char fullrp[PATH_MAX], fulltsp[PATH_MAX];

    // create full paths
    pathcpy(fullrp, root);
    pathcat(fullrp, cpath->rpath);
    pathcpy(fulltsp, root);
    pathcat(fulltsp, cpath->tspath);

    // stat resolved rpath -> tstamp
    if (stat(fullrp, &rsb)) {
	if (errno == ENOENT) {
	    bsderr = 0;
	} else {
	    kextd_error_log("cached file %s: %s", fullrp, strerror(errno));
	}
	goto finish;
    }

    cpath->tstamps[0].tv_sec = rsb.st_atimespec.tv_sec;	    // to apply later
    cpath->tstamps[0].tv_usec = rsb.st_atimespec.tv_nsec / 1000;
    cpath->tstamps[1].tv_sec = rsb.st_mtimespec.tv_sec;	    // don't ask ;p
    cpath->tstamps[1].tv_usec = rsb.st_mtimespec.tv_nsec / 1000;

    // stat tspath
    // and compare as appropriate
    if (stat(fulltsp, &tsb) == 0) {
	ood = (tsb.st_mtimespec.tv_sec != rsb.st_mtimespec.tv_sec ||
	       tsb.st_mtimespec.tv_nsec != tsb.st_mtimespec.tv_nsec);
    } else {
	if (errno == ENOENT) {
	    ood = true;	// nothing to compare with
	} else {
	    kextd_error_log("cached file %s: %s", fulltsp, strerror(errno));
	    goto finish;
	}
    }

    *outofdate = ood;
    bsderr = 0;

finish:
    return bsderr;
}

/*******************************************************************************
* needUpdates checks all paths and returns details if you want them
* expects callers only to call it on volumes that will have timestamp paths
* (e.g. BootRoot volumes! ;)
*******************************************************************************/
int needUpdates(struct bootCaches *caches, Boolean *any,
		    Boolean *rps, Boolean *booters, Boolean *misc)
{
    int rval = 0;	// looking for problems (any one will cause failure)
    Boolean needsUp, rpsOOD, bootersOOD, miscOOD, anyOOD;
    cachedPath *cp;

    // assume nothing needs updating (caller may interpret error -> needsUpdate)
    rpsOOD = bootersOOD = miscOOD = anyOOD = false;

    // in theory, all we have to do is find one "problem" (out of date file)
    // but in practice, there could be real problems (like missing sources)
    // we also like populating the tstamps
    for (cp = caches->rpspaths; cp < &caches->rpspaths[caches->nrps]; cp++) {
	if ((rval = needsUpdate(caches->root, cp, &needsUp)))    goto finish;
	if (needsUp) 					anyOOD = rpsOOD = true;
	// one is enough, but needsUpdate populates tstamps which we need later
    }
    if ((cp = &(caches->efibooter)), cp->rpath[0]) {
	if ((rval = needsUpdate(caches->root, cp, &needsUp)))    goto finish;
	if (needsUp)				    anyOOD = bootersOOD = true;
    }
    if ((cp = &(caches->ofbooter)), cp->rpath[0]) {
	if ((rval = needsUpdate(caches->root, cp, &needsUp)))    goto finish;
	if (needsUp)				    anyOOD = bootersOOD = true;
    }
    for (cp = caches->miscpaths; cp < &caches->miscpaths[caches->nmisc]; cp++){
	(void)needsUpdate(caches->root, cp, &needsUp);
	// could emit warnings in an appropriate verbose mode
	// no one cares if .VolumeIcon.icns is missing :)
	// though evidently (4487046) the label file is important
	if (needsUp)				    anyOOD = miscOOD = true;
    }


    if (rps)  	    *rps = rpsOOD;
    if (booters)    *booters = bootersOOD;
    if (misc)	    *misc = miscOOD;
    if (any)	    *any = anyOOD;

finish:
    return rval;
}

/*******************************************************************************
* applyStamps runs through all of the cached paths in a struct bootCaches
* and applies the timestamps captured before the update
* not going to bother with a re-stat() of the sources for now
*******************************************************************************/
// Sec review: no need to drop privs thanks to safecalls.[ch]
static int applyStamp(char *root, cachedPath *cpath, int fdvol)
{
    int bsderr = -1, fd;
    char tspath[PATH_MAX];

    pathcpy(tspath, root);
    pathcat(tspath, cpath->tspath);

    (void)sunlink(fdvol, tspath);    // since sopen passes O_EXCL
    if (-1 == (fd = sopen(fdvol, tspath, O_WRONLY|O_CREAT, kTSCacheMask)))
	goto finish;	    

    bsderr = futimes(fd, cpath->tstamps);

finish:
    return bsderr;
}

int applyStamps(struct bootCaches *caches)
{
    int rval = 0;
    cachedPath *cp;

    // run through all of the cached paths apply bootstamp
    for (cp = caches->rpspaths; cp < &caches->rpspaths[caches->nrps]; cp++) {
	rval |= applyStamp(caches->root, cp, caches->cachefd);
    }
    if ((cp = &(caches->efibooter)), cp->rpath[0]) {
	rval |= applyStamp(caches->root, cp, caches->cachefd);
    }
    if ((cp = &(caches->ofbooter)), cp->rpath[0]) {
	rval |= applyStamp(caches->root, cp, caches->cachefd);
    }
    for (cp = caches->miscpaths; cp < &caches->miscpaths[caches->nmisc]; cp++){
	rval |= applyStamp(caches->root, cp, caches->cachefd);
    }


    return rval;
}

/******************************************************************************
 * fork_kextcache lauches kc with the given (null-terminated) argv
 * - in child, set TMPDIR to volume's kTSCacheDir (we created it earlier)
 * - uses double-fork()/exec to avoid a zombie :P
 * - logs own errors
 *****************************************************************************/
int fork_kextcache(char *cacheRoot, char *argv[], Boolean wait)       
{
    int rval = -2;
    int status;
    pid_t pid;
    char tmpdir[PATH_MAX];

    if (strlcpy(tmpdir, cacheRoot, PATH_MAX) >= PATH_MAX)  goto finish; 
    // if we can't append kTSCacheDir, we'll accept using volume's root ;p
    strlcat(tmpdir, kTSCacheDir, PATH_MAX);

    switch (pid = fork()) {
        case -1:
            rval = pid;
            goto finish;

        case 0:  // child
            // give these children to the system (grr, linker-fork() in kextlib)
	    setenv("TMPDIR", tmpdir, 1);	// workaround

	    if (!wait) {
		if (-1 == (rval = daemon(0, 0)))   goto finish;
	    }
		
	    rval = execv("/usr/sbin/kextcache", argv);

            // if execv returns, we have an error (re-open log in child)
            kextd_openlog("kextd");
            kextd_error_log("couldn't launch kextcache! - %s", strerror(errno));
            exit(1);
            break;      // really shouldn't get here :)

        default:  // parent
            // kextd_log("DEBUG: launched kextcache w/pid %d", pid);
            waitpid(pid, &status, 0);
            status = WEXITSTATUS(status);
	    if (wait) {
		rval = status;
	    } else if (status) {
		    rval = -1;
		} else {
		    rval = pid;
		}

            break;
    }

finish:
    if (rval == -1)
        kextd_error_log("couldn't fork kextcache!");

    return rval;
}

/*******************************************************************************
* rebuild_mkext fires off kextcache on the given volume
*******************************************************************************/
int rebuild_mkext(struct bootCaches *caches, Boolean wait)
{   
    int rval = ELAST + 1;
    int pid = -1;
    CFIndex i, argi = 0, argc = 0, narchs = 0;
    CFDictionaryRef pbDict, mkDict;
    CFArrayRef archArray;
    char **kcargs = NULL, **archstrs = NULL;    // no [ARCH_MAX] anywhere? :P
    char fullmkextp[PATH_MAX], fullextsp[PATH_MAX];

    pbDict = CFDictionaryGetValue(caches->cacheinfo, kBCPostBootKey);
    if (!pbDict || CFGetTypeID(pbDict) != CFDictionaryGetTypeID())  goto finish;
    mkDict = CFDictionaryGetValue(pbDict, kBCMKextKey);
    if (!mkDict || CFGetTypeID(mkDict) != CFDictionaryGetTypeID())  goto finish;
    archArray = CFDictionaryGetValue(mkDict, kBCArchsKey);
    if (archArray) {
        narchs = CFArrayGetCount(archArray);
        archstrs = calloc(narchs, sizeof(char*));
        if (!archstrs)  goto finish;
    }

    //  argv[0] "-a x -a y" '-l'  '-m'  mkext  exts  NULL
    argc =  1  + narchs*2  +  1  +  1  +  1  +  1  +  1;
    kcargs = malloc(argc * sizeof(char*));
    if (!kcargs)  goto finish;
    kcargs[argi++] = "kextcache";

    // convert each -arch argument into a char* and add to the vector
    for(i = 0; i < narchs; i++) {
        CFStringRef archStr;
        size_t archSize;

        // get  arch
        archStr = CFArrayGetValueAtIndex(archArray, i);
        if (!archStr || CFGetTypeID(archStr)!=CFStringGetTypeID()) goto finish;
        // XX an arch is not a pathname; EncodingASCII might be more appropriate
        archSize = CFStringGetMaximumSizeOfFileSystemRepresentation(archStr);
        if (!archSize)  goto finish;
        // X marks the spot: over 800 lines written before I realized that
        // there were some serious security implications
        archstrs[i] = malloc(archSize);
        if (!archstrs[i])  goto finish;
        if (!CFStringGetFileSystemRepresentation(archStr,archstrs[i],archSize))
            goto finish;

        kcargs[argi++] = "-a";
        kcargs[argi++] = archstrs[i];
    }

    kcargs[argi++] = "-l";
    kcargs[argi++] = "-m";

    pathcpy(fullmkextp, caches->root);
    pathcat(fullmkextp, caches->mkext->rpath);
    kcargs[argi++] = fullmkextp;

    pathcpy(fullextsp, caches->root);
    pathcat(fullextsp, caches->exts);
    kcargs[argi++] = fullextsp;

    kcargs[argi] = NULL;

    rval = 0;
    pid = fork_kextcache(caches->root, kcargs, wait);  // logs its own errors

finish:
    if (rval) 	kextd_error_log("data error before mkext rebuild");
    if (wait || pid < 0)
        rval = pid;

    if (archstrs) {
        for (i = 0; i < narchs; i++) {
            if (archstrs[i])  free(archstrs[i]);
        }
        free(archstrs);
    }
    if (kcargs) free(kcargs);

    return rval;
}

Boolean check_mkext(struct bootCaches *caches)
{   
    Boolean needsrebuild = false;
    struct stat sb;
    char fullmkextp[PATH_MAX], fullextsp[PATH_MAX];

    // struct bootCaches paths are all *relative*
    pathcpy(fullmkextp, caches->root);
    pathcat(fullmkextp, caches->mkext->rpath);
    pathcpy(fullextsp, caches->root);
    pathcat(fullextsp, caches->exts);

    // mkext implies exts
    if (caches->mkext) {
        struct stat extsb;

        if (stat(fullextsp, &extsb) == -1) {
            kextd_log("couldn't stat %s: %s", caches->exts,
                strerror(errno));
            // assert(needsrebuild == false);   // we can't build w/o exts
            goto finish;
        }

        // Extensions.mkext
        needsrebuild = true;  // since this stat() will fail if mkext gone
        if (stat(fullmkextp, &sb) == -1)
            goto finish;
        needsrebuild = (sb.st_mtime != extsb.st_mtime + 1);
    }

finish:
    return needsrebuild;
}

/*******************************************************************************
* isBootRoot lets you know if a volume has boot partitions and if it's on EFI
*******************************************************************************/
Boolean isBootRoot(char *volroot, Boolean *isGPT)
{
    char bsdname[DEVMAXPATHSIZE];
    struct stat sb;  
    CFDictionaryRef binfo = NULL;
    Boolean rval = false, gpt = false;
    CFArrayRef ar;

    // if not BootRoot, we don't bother with kextcache -u    
    if (stat(volroot, &sb))                                         goto finish;
    if (!devname_r(sb.st_dev, S_IFBLK, bsdname, DEVMAXPATHSIZE))    goto finish;
    if (BLCreateBooterInformationDictionary(NULL,bsdname,&binfo))   goto finish;

    ar = CFDictionaryGetValue(binfo, kBLAuxiliaryPartitionsKey);   
    rval = (ar && CFArrayGetCount(ar) > 0);
    ar = CFDictionaryGetValue(binfo, kBLSystemPartitionsKey);
    gpt = (ar && CFArrayGetCount(ar) > 0);

finish:
    if (binfo)      CFRelease(binfo);

    if (isGPT)      *isGPT = gpt;
    return rval;
}
/*******************************************************************************
*
*******************************************************************************/
Boolean bootedFromDifferentMkext(void)
{
    Boolean result = true;
    MkextCRCResult startupCrcFound;
    MkextCRCResult onDiskCrcFound;
    uint32_t startupCrc;
    uint32_t onDiskCrc;

    startupCrcFound = getMkextCRC(NULL, &startupCrc);
    if (startupCrcFound != kMkextCRCFound) {
        result = false;
        goto finish;
    }

    onDiskCrcFound = getMkextCRC("/System/Library/Extensions.mkext",
        &onDiskCrc);
    if (onDiskCrcFound != kMkextCRCFound) {
        goto finish;
    }

    if (startupCrc == onDiskCrc) {
        result = false;
    }

finish:
    return result;
}

/*******************************************************************************
*
*******************************************************************************/
Boolean bootedFromDifferentKernel(void)
{
    Boolean result = true;
    char * runningVersion = NULL;  // must free
    char * onDiskVersion = NULL;   // must free

    runningVersion = copyKernelVersion(NULL);
    onDiskVersion  = copyKernelVersion("/mach_kernel");

    if (!runningVersion || !onDiskVersion) {
        goto finish;
    }

    if (0 == strcmp(runningVersion, onDiskVersion)) {
        result = false;
        goto finish;
    }

finish:
    if (runningVersion) free(runningVersion);
    if (onDiskVersion)  free(onDiskVersion);
    return result;
}

/*******************************************************************************
*
*******************************************************************************/
MkextCRCResult getMkextCRC(const char * file_path, uint32_t * crc_ptr)
{
    MkextCRCResult result = kMkextCRCError;
    fat_iterator iter = NULL;
    const void * file_start = NULL;
    void * file_end = NULL;
    mkext_header * mkext_hdr;
    io_registry_entry_t ioRegRoot = MACH_PORT_NULL;
    CFTypeRef   regObj = NULL;  // must release
    CFDataRef   dataObj = NULL; // must release
    CFIndex     numBytes;
    uint32_t    crc;

    if (!file_path) {
        ioRegRoot = IORegistryGetRootEntry(kIOMasterPortDefault);
        if (ioRegRoot != MACH_PORT_NULL) {
            regObj = IORegistryEntryCreateCFProperty(ioRegRoot,
                CFSTR(kIOStartupMkextCRC), kCFAllocatorDefault, kNilOptions);
            if (!regObj) {
                result = kMkextCRCNotFound;
                goto finish;
            }
            if (CFGetTypeID(regObj) != CFDataGetTypeID()) {
                goto finish;
            }
        }

        dataObj = (CFDataRef)regObj;
        numBytes = CFDataGetLength(dataObj);
        if (numBytes != sizeof(uint32_t)) {
            goto finish;
        }

        CFDataGetBytes(dataObj, CFRangeMake(0, numBytes), (void *)&crc);
    } else {

        iter = fat_iterator_open(file_path, 0);
        if (!iter) {
            goto finish;
        }
        file_start = fat_iterator_file_start(iter);
        if (!file_start) {
            goto finish;
        }

        if (ISMKEXT(MAGIC32(file_start))) {
            mkext_hdr = (struct mkext_header *)file_start;
        } else {
            file_start = fat_iterator_find_host_arch(
                iter, &file_end);
            if (!file_start) {
                goto finish;
            }
            if (!ISMKEXT(MAGIC32(file_start))) {
                goto finish;
            }
            mkext_hdr = (struct mkext_header *)file_start;
        }
        crc = OSSwapBigToHostInt32(mkext_hdr->adler32);
    }

    *crc_ptr = crc;
    result = kMkextCRCFound;

finish:
    if (ioRegRoot) IOObjectRelease(ioRegRoot);
    if (dataObj)   CFRelease(dataObj);
    return result;
}

/*******************************************************************************
* copyKernelVersion()
*
* Get the version string for a kernel. If kernel_filename is NULL, get the
* version of the running kernel via sysctl(); otherwise read it out of the
* mach-o file.
*
* The caller owns the pointer returned. For the sysctl(), we have to allocate a
* buffer; for reading from a mach-o file, which we unmap, we have to strdup()
* the found value.
*******************************************************************************/
#define KERNEL_VERSION_SYMBOL  "_version"

char * copyKernelVersion(const char * kernel_filename)
{
    char * result = NULL;
    fat_iterator iter = NULL;

    if (!kernel_filename) {

        size_t vers_length;
        int vers_mib_name[] = { CTL_KERN, KERN_VERSION };

       /* Get the size of the buffer we need to allocate.
        */
        if (sysctl(vers_mib_name, sizeof(vers_mib_name) / sizeof(int), NULL,
            &vers_length, NULL, 0) != 0) {

            kextd_error_log("sysctl for kernel version failed");
            goto finish;
        }

        result = malloc(vers_length * sizeof(char));
        if (result == NULL) {
            kextd_error_log("malloc failed");
            goto finish;
        }

       /* Now actually get the kernel version.
        */
        if (sysctl(vers_mib_name, sizeof(vers_mib_name) / sizeof(int), result,
            &vers_length, NULL, 0) != 0) {

            kextd_error_log("sysctl for kernel version failed");
            goto finish;
        }

    } else {
        struct mach_header * kernel_file = NULL;
        void * kernel_file_end = NULL;
        macho_seek_result sym_result;

        iter = fat_iterator_open(kernel_filename, 1);
        if (!iter) {
            goto finish;
        }
        kernel_file = (struct mach_header *)fat_iterator_find_host_arch(
            iter, &kernel_file_end);
        if (!kernel_file) {
            goto finish;
        }
        sym_result = macho_find_symbol(
            kernel_file, kernel_file_end,
            KERNEL_VERSION_SYMBOL, (const void **)&result);
        if (sym_result != macho_seek_result_found) {
            goto finish;
        }

        if (result) {
            result = strdup(result);
        }
    }

finish:
    if (iter) fat_iterator_close(iter);

    return result;
}

void _daDone(DADiskRef disk, DADissenterRef dissenter, void *ctx)
{
    if (dissenter)
	CFRetain(dissenter);
    *(DADissenterRef*)ctx = dissenter;
    CFRunLoopStop(CFRunLoopGetCurrent());   // assumed okay even if not running
}
