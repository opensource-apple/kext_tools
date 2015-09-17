/*
 * XX APSL?
 * 
 * FILE: watchvol.h
 * AUTH: Soren Spies (sspies)
 * DATE: 6 March 2006
 * DESC: header for volume watching routines
 *
 * $NoLog$
 */

// for kextd_main
int kextd_watch_volumes(int sourcePriority/*, CFRunLoopRef runloop*/);
int kextd_giveup_volwatch();
void kextd_stop_volwatch();

void updateRAIDSet(
    CFNotificationCenterRef center,
    void * observer,
    CFStringRef name,
    const void * object,
    CFDictionaryRef userInfo);
