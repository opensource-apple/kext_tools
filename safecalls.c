/*
 * FILE: safecalls.c
 * AUTH: Soren Spies (sspies)
 * DATE: 16 June 2006 (Copyright Apple Computer, Inc)
 * DESC: picky/safe syscalls
 *
 * Security functions
 * the first argument limits the scope of the operation
 *
 * Pretty much every function is implemented as
 * savedir = open(".", O_RDONLY);
 * schdirparent()->sopen()->spolicy()
 * <operation>(child)
 * fchdir(savedir)
 * 
 */

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <sys/param.h>	// MAXBSIZE
#include <sys/stat.h>
#include <string.h>
#include <stdio.h>	// rename(2)?
#include <stdlib.h>	// malloc(3)
#include <sys/types.h>
#include <unistd.h>

#include <fts.h>

#define STRICT_SAFETY 0	    // since we have to wrap the real calls
#include "safecalls.h"
#include "logging.h"

#define RESTOREDIR(savedir) do { if (savedir != -1 && restoredir(savedir))  \
		        	 kextd_error_log("%s: lost CWD!?", __func__); \
		    	    } while(0)

// current checks to make sure on same volume
// other checks could include:
// * "really owned by <foo> on root/<foo>-mounted volume"
static int spolicy(int scopefd, int candfd)
{
    int bsderr = -1;
    struct stat dirsb, volsb;

    if ((bsderr = fstat(candfd, &dirsb)))  goto finish;	    // trusty fstat()
    if ((bsderr = fstat(scopefd, &volsb)))  goto finish;    // still there?

    // simple st_dev policy for now
    if (volsb.st_dev != dirsb.st_dev) {
	kextd_error_log("spolicy: ALERT: dev_t mismatch");
	bsderr = EPERM;
	goto finish;
    }

finish:
    return bsderr;

}


int schdirparent(int fdvol, const char *path, int *olddir, char child[PATH_MAX])
{
    int bsderr = -1;
    int dirfd = -1, savedir = -1;
    char parent[PATH_MAX];

    if (olddir)	    *olddir = -1;
    if (!path)	    goto finish;

    if (strlcpy(parent, dirname(path), PATH_MAX) >= PATH_MAX)    goto finish;

    // make sure parent is on specified volume
    if (-1 == (dirfd = open(parent, O_RDONLY, 0)))  goto finish;
    if (spolicy(fdvol, dirfd))	    goto finish;

    // output parameters
    if (child) {
	if (strlcpy(child, basename(path), PATH_MAX) >= PATH_MAX)
	    goto finish;
    }
    if (olddir) {
	if (-1 == (savedir = open(".", O_RDONLY)))  goto finish;
	*olddir = savedir;
    }

    if ((bsderr = fchdir(dirfd)))  		goto finish;

finish:
    if (bsderr) {
	if (savedir != -1)		close(savedir);
	if (olddir && *olddir != -1)	close(*olddir);
    }
    if (dirfd != -1)	close(dirfd);

    return bsderr;
}

// have to rely on schdirparent so we don't accidentally O_CREAT
int sopen(int fdvol, char *path, int flags, mode_t mode /*should be '...' */)
{
    int rfd = -1;
    int candfd = -1;
    char child[PATH_MAX];
    int savedir = -1;

    if (flags & O_CREAT)    flags |= O_EXCL;

    if (schdirparent(fdvol, path, &savedir, child))	goto finish;
    if (-1 == (candfd = open(child, flags, mode)))	goto finish;

    // if we can't trust schdirparent(), then we can't implement O_CREAT
    // if (spolicy(fdvol, candfd))		    		goto finish;

    rfd = candfd;

finish:
    if (candfd != -1 && rfd != candfd) {
	close(candfd);
    }
    RESTOREDIR(savedir);

    return rfd;
}

int schdir(int fdvol, const char *path, int *savedir)
{
    char cpath[PATH_MAX];

    // X could switch to snprintf()
    if (strlcpy(cpath, path, PATH_MAX) >= PATH_MAX ||
        strlcat(cpath, "/.", PATH_MAX) >= PATH_MAX)   return -1;

    return schdirparent(fdvol, cpath, savedir, NULL);
}

int restoredir(int savedir)
{
    int cherr = -1, clerr = -1;

    if (savedir != -1) {
	cherr = fchdir(savedir);
	clerr = close(savedir);
    }

    return cherr ? cherr : clerr;
}

int smkdir(int fdvol, const char *path, mode_t mode)
{
    int bsderr = -1;
    int savedir = -1;
    char child[PATH_MAX];

    if (schdirparent(fdvol, path, &savedir, child))  goto finish;
    if ((bsderr = mkdir(child, mode)))      goto finish;

finish:
    RESTOREDIR(savedir);
    return bsderr;
}

int srmdir(int fdvol, const char *path)
{
    int bsderr = -1;
    char child[PATH_MAX];
    int savedir = -1;

    if (schdirparent(fdvol, path, &savedir, child))  goto finish;

    bsderr = rmdir(child);

finish:
    RESTOREDIR(savedir);
    return bsderr;
}

int sunlink(int fdvol, const char *path)
{
    int bsderr = -1;
    char child[PATH_MAX];
    int savedir = -1;

    if (schdirparent(fdvol, path, &savedir, child))  goto finish;

    bsderr = unlink(child);

finish:
    RESTOREDIR(savedir);
    return bsderr;
}

// taking a path and a filename is sort of annoying for clients
// so we "auto-strip" newname if it happens to be a path
int srename(int fdvol, const char *oldpath, const char *newpath)
{
    int bsderr = -1;
    int savedir = -1;
    char oldname[PATH_MAX];
    char newname[PATH_MAX];

    // calculate netname first since schdirparent uses basename :P
    if (strlcpy(newname, basename(newpath), PATH_MAX) >= PATH_MAX)goto finish;
    if (schdirparent(fdvol, oldpath, &savedir, oldname))   	goto finish;

    bsderr = rename(oldname, newname);

finish:
    RESTOREDIR(savedir);
    return bsderr;
}

// stolen with gratitude from TAOcommon's TAOCFURLDelete :)
int sdeepunlink(int fdvol, char *path)
{
    int             rval = ELAST + 1;

    char  	*   const pathv[2] = { path, NULL };
    int             ftsoptions = 0;
    FTS         *   fts;
    FTSENT      *   fent;

    // opting for security, of course :)
    ftsoptions |= FTS_PHYSICAL;		// see symlinks
    ftsoptions |= FTS_XDEV;		// don't cross devices
    ftsoptions |= FTS_NOSTAT;		// fts_info tells us enough
//  ftsoptions |= FTS_COMFOLLOW;	// if 'path' is symlink, remove link
//  ftsoptions |= FTS_NOCHDIR;		// chdir is fine
//  ftsoptions |= FTS_SEEDOT;		// we don't need "."

    if ((fts = fts_open(pathv, ftsoptions, NULL)) == NULL)  goto finish;

    // and here we go (accumulating errors, though that usu ends in ENOTEMPTY)
    rval = 0;
    while ((fent = fts_read(fts)) /* && !rval ?? */) {
        switch (fent->fts_info) {
            case FTS_DC:        // directory that causes a cycle in the tree
            case FTS_D:         // directory being visited in pre-order
            case FTS_DOT:       // file named `.' or `..' (not requested :P)
                break;

            case FTS_DNR:       // directory which cannot be read
            case FTS_ERR:	// generic fcts_errno-borne error
            case FTS_NS:        // file for which stat(s) failed (not requested)
                rval |= fent->fts_errno;
                break;

            case FTS_SL:        // symbolic link
            case FTS_SLNONE:    // symbolic link with a non-existent target
            case FTS_DEFAULT:   // good file of type unknown to FTS (block? ;)
            case FTS_F:         // regular file
            case FTS_NSOK:      // no stat(2) requested (but not a dir?)
            default:		// in case FTS gets smarter in the future
                rval |= sunlink(fdvol, fent->fts_accpath);
                break;

            case FTS_DP:        // directory being visited in post-order
                rval |= srmdir(fdvol, fent->fts_accpath);
                break;
        } // switch
    } // while

    if (!rval) 	rval = errno;	// fts_read() clears if all went well

    // close the iterator now
    if (fts_close(fts) < 0) {
        kextd_error_log("fts_close failed? - %s", strerror(errno));
    }

finish:

    return rval;
}

int sdeepmkdir(int fdvol, const char *path, mode_t mode)
{
    int bsderr = -1;
    struct stat sb;
    char parent[PATH_MAX];

    if (strlen(path) == 0)	goto finish;	    // protection?

    // trusting that stat(".") will always do the right thing
    if (0 == stat(path, &sb)) {
	if (sb.st_mode & S_IFDIR == 0) {
	    bsderr = ENOTDIR;
	    goto finish;
	} else {
	    bsderr = 0;		    // base case (dir exists) 
	    goto finish;
	}
    } else if (errno != ENOENT) {
	goto finish;		    // bsderr = -1 -> errno
    } else {
	if (strlcpy(parent, dirname(path), PATH_MAX) >= PATH_MAX)    goto finish;

	// and recurse since it wasn't there
	if ((bsderr = sdeepmkdir(fdvol, parent, mode)))	    goto finish;
    }

    // all parents made; top-level still needed
    bsderr = smkdir(fdvol, path, mode);

finish:
    return bsderr;
}

#define     min(a,b)        ((a) < (b) ? (a) : (b))
int scopyfile(int srcfdvol, char *srcpath, int dstfdvol, char *dstpath)
{
    int bsderr = -1;
    int srcfd = -1, dstfd = -1;
    struct stat srcsb;
    char dstparent[PATH_MAX];
    mode_t dirmode;
    void *buf = NULL;	    // MAXBSIZE on the stack is a bad idea :)
    off_t bytesLeft, thisTime;

    // figure out directory mode
    if (-1 == (srcfd = sopen(srcfdvol, srcpath, O_RDONLY, 0)))    goto finish;
    if (fstat(srcfd, &srcsb))			    goto finish;
    dirmode = ((srcsb.st_mode&~S_IFMT) | S_IWUSR | S_IXUSR /* u+wx */);
    if (dirmode & S_IRGRP)	dirmode |= S_IXGRP;	// add conditional o+x
    if (dirmode & S_IROTH)	dirmode |= S_IXOTH;

    // and recursively create the parent directory
    if (strlcpy(dstparent, dirname(dstpath), PATH_MAX) >= PATH_MAX) goto finish;
    if ((sdeepmkdir(dstfdvol, dstparent, dirmode)))	    goto finish;

    // nuke/open the destination
    (void)sunlink(dstfdvol, dstpath);
    dstfd = sopen(dstfdvol, dstpath, O_CREAT|O_WRONLY, srcsb.st_mode | S_IWUSR);
    if (dstfd == -1)	    goto finish;

    // and loop with our handy buffer
    if (!(buf = malloc(MAXBSIZE)))	goto finish;;
    for (bytesLeft = srcsb.st_size; bytesLeft > 0; bytesLeft -= thisTime) {
	thisTime = min(bytesLeft, MAXBSIZE);

	if (read(srcfd, buf, thisTime) != thisTime)	goto finish;
	if (write(dstfd, buf, thisTime) != thisTime)	goto finish;
    }

    // apply final permissions
    if (bsderr = fchmod(dstfd, srcsb.st_mode))	goto finish;
    // kextcache doesn't currently look into the Apple_Boot, so we'll skip times

finish:
    if (srcfd != -1)	close(srcfd);
    if (dstfd != -1)	close(dstfd);

    if (buf)	    	free(buf);

    return bsderr;
}
