/*
 * FILE: bootcaches.h
 * AUTH: Soren Spies (sspies)
 * DATE: 22 March 2006 (Copyright Apple Computer, Inc)
 * DESC: constants for boot caches
 */

#ifndef __BOOTCACHES_H__
#define __BOOTCACHES_H__

/* XXX bootcaches.h going away in favor of bootfiles.h
 * once efiboot is switched to bootfiles.h, it can be removed
 */


#define kBootDirR "com.apple.boot.R"
#define kBootDirP "com.apple.boot.P"
#define kBootDirS "com.apple.boot.S"

/* kernel, mkext, /S/L/E constants should eventually be shared
#define kSystemExtensionsDir "System/Library/Extensions"
#define kDefaultKernel "mach_kernel"
#define kDefaultMkext "System/Library/Extensions.mkext"
#define kPrelinkedCacheDir "System/Library/Caches/com.apple.kernelcaches"
#define kPrelinkedCacheBase "kernelcache"
*/

#endif __BOOTCACHES_H__
