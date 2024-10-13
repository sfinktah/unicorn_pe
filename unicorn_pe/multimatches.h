#pragma once
#ifdef USE_BOOST
#include <vector>
#include "MultiMatch.h"

extern std::vector<MultiMatch> multimatches;
void init_multimatches();
#endif
