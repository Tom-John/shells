

#ifndef MACROS_H
#define MACROS_H

#include <stdint.h>
#include <string.h>

#include "portable.h"

#define XCHG(x, y) (t) = (x); (x) = (y); (y) = (t);

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

#endif
