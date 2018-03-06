#ifndef INIDS_ERROR_HANDLER_H
#define INIDS_ERROR_HANDLER_H

/* Error show */
#define print_error(str) fprintf(stderr,"%s\n", str);

/* Error messages */
#define USAGE_MSG "Usage: inids [-f file...] [-e \"filter expression\"]"

#define DEVICE_NOT_FOUND "no network device found"


#endif //INIDS_ERROR_HANDLER_H
