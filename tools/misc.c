#include <stdio.h>
#include "misc.h"

void
open_section(const char *name) {
    printf("  ['%s'] = {\n",name);
}

void
close_section(void) {
    printf("  },\n");
}

void
dump_table(const char *name, unsigned char *data, size_t length) {
    size_t i = 0;
    printf("    ['%s'] = {",name);
    for(i=0;i<length;i++) {
        if(i % 8 == 0) {
            printf("\n      ");
        }
        printf(" %u,",data[i]);
    }
    printf("\n    },\n");
}

