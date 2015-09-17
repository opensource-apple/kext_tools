#ifndef __MKEXT_UTIL_H__
#define __MKEXT_UTIL_H__

#include <Kernel/libsa/mkext.h> 

#define ISMKEXT(magic)  ((magic) == OSSwapHostToBigInt32(MKEXT_MAGIC))

#endif /* __MKEXT_UTIL_H__ */
