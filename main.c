#include "capture/capture.h"


int main(int argc, char **argv) {

    // Options and arguments handler

//    for(int i = 0; i < argc; i++){
//
//    }

    capture_init();

    capture_start_loop();

    return 0;
}