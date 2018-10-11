/*
 * SubstrateMacro.h
 *
 *  Created on: 2017Äê5ÔÂ22ÈÕ
 *      Author: sev
 */

#ifndef SUBSTRATEMACRO_H_
#define SUBSTRATEMACRO_H_

#include <stdlib.h>
typedef struct __SubstrateProcess *SubstrateProcessRef;
typedef void *SubstrateAllocatorRef;
typedef struct SubstrateMemory {
    void *address_;
    size_t width_;
	SubstrateMemory(void *address, size_t width):address_(address), width_(width) {}
}*SubstrateMemoryRef;

#endif /* SUBSTRATEMACRO_H_ */
