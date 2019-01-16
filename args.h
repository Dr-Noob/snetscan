#ifndef __ARGS__
#define __ARGS__

#include <stdbool.h>

bool showHelp();
bool showVersion();
char* getDevice();
void parseArgs(int argc, char* argv[]);

#endif
