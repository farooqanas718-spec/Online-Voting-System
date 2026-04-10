#include "mongoose.h"
#include <time.h>

void get_iso_time(char *buffer, size_t size) {
    time_t now = time(NULL);
    struct tm *t = gmtime(&now);
    strftime(buffer, size, "%Y-%m-%dT%H:%M:%SZ", t);
}
