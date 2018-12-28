#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#define ARG_STR_HELP     "help"
#define ARG_STR_DEVICE   "dev"
#define ARG_CHAR_HELP     'h'
#define ARG_CHAR_DEVICE   'd'

struct args_struct {
  bool help_flag;
  char* device;
};

static struct args_struct args;

void parseArgs(int argc, char* argv[]) {
  int c;
  int digit_optind = 0;
  int option_index = 0;
  bool device_set = false;
  opterr = 0;

  args.help_flag = false;
  args.device = NULL;

  static struct option long_options[] = {
      {ARG_STR_HELP,     no_argument,       0, ARG_CHAR_HELP    },
      {ARG_STR_DEVICE,   required_argument, 0, ARG_CHAR_DEVICE  },
      {0, 0, 0, 0}
  };

  c = getopt_long(argc, argv,"",long_options, &option_index);

  while (c != -1) {
     if(c == ARG_CHAR_HELP)
       args.help_flag  = true;
     else if (c == ARG_CHAR_DEVICE)
       args.device = optarg;
     else if(c == '?') {
       printf("WARNING: Invalid options\n");
       args.help_flag  = true;
       break;
     }
     else
      printf("Bug at line number %d in file %s\n", __LINE__, __FILE__);

    option_index = 0;
    c = getopt_long(argc, argv,"",long_options, &option_index);
  }

  if (optind < argc) {
    printf("WARNING: Invalid options\n");
    args.help_flag  = true;
  }
}

bool showHelp() {
  return args.help_flag;
}

char* getDevice() {
  return args.device;
}
