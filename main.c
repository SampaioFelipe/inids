#include <getopt.h>
#include <stdlib.h>
#include <memory.h>
#include "capture/capture.h"
#include "utils/error_handler.h"

int main(int argc, char **argv)
{
    int opt;
    int capture_mode = ONLINE_MODE;
    char *filename = NULL, *filter_expr = NULL;

    // Options and arguments handler
    while ((opt = getopt(argc, argv, "f:e:")) != -1)
    {
        switch (opt)
        {
            case 'f': // OFFLINE MODE
            {
                capture_mode = OFFLINE_MODE;
                filename = (char *) malloc(sizeof(char) * strlen(optarg));
                strcpy(filename, optarg);
                break;
            }

            case 'e': // Expression specification
            {
                filter_expr = (char *) malloc(sizeof(char) * strlen(optarg));
                strcpy(filter_expr, optarg);
                break;
            }

            default:
                print_error(USAGE_MSG);
                exit(EXIT_FAILURE);
        }
    }

    capture_init(capture_mode, filename, filter_expr);

    capture_start_loop();

    return 0;
}