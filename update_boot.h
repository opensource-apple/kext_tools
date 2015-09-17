/*
 * FILE: update_boot.h
 * AUTH: Soren Spies (sspies)
 * DATE: 8 June 2006
 * DESC: routines for implementing 'kextcache -u' functionality (4252674)
 *	 in which bootcaches.plist files get copied to any Apple_Boots
 */

#include <sys/types.h>	    // mode_t

// additional RPS files (e.g. from the command-line)
int updateBoots(char *volRoot, int extraRPSc, const char *extraRPS[],
		Boolean force, int dashv);

// sharing between kextcache_main.c and update_boot.c
// locking routine needs to be shared out to updateBoots
int takeVolumeForPaths(char *volPath, int filec, const char *files[]);
int putVolumeForPath(const char *path, int status);
