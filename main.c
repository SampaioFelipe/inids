#include <getopt.h>
#include <stdlib.h>
#include <memory.h>
#include <pthread.h>

#include "globals/threads_manager.h"
#include "globals/encoding.h"
#include "globals/error_handler.h"

#include "capture/capture.h"
#include "analysis/analysis.h"


/* Thread sync */
pthread_mutex_t mutex_processing;
pthread_cond_t cond_processing;

/* antigens buffers */
antigen_buffer *cap_buf;     // capture buffer
antigen_buffer *proc_buf;    // process buffer

int main(int argc, char **argv)
{
    int opt;
    int capture_mode = ONLINE_MODE;
    char *filename = NULL, *filter_expr = NULL;

    pthread_t analysis_thread;

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

    cap_buf = (antigen_buffer*) malloc(sizeof(antigen_buffer));
    proc_buf = (antigen_buffer*) malloc(sizeof(antigen_buffer));

    pthread_mutex_init(&mutex_processing, NULL);
    pthread_cond_init(&cond_processing, NULL);

    // Set up the capture variables and options
    capture_init(capture_mode, filename, filter_expr);

    // Set up and run analysis thread
    if(pthread_create(&analysis_thread, NULL, analysis_init, NULL)){
        print_error("erro de thread");
        exit(EXIT_FAILURE);
    }

    capture_start_loop();

    pthread_mutex_destroy(&mutex_processing);
    pthread_cond_destroy(&cond_processing);

    free(proc_buf);
    free(cap_buf);

    return 0;
}