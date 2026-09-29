#include <stdio.h>
#include <string.h>

// NX + ASLR

void vuln(const char *in){
    char buf[120];
    strcpy(buf, in); // overflow volontaire
    printf("%s\n", buf);
}


int main(int argc, char **argv){
    vuln(argc > 1 ? argv[1] : "hello");
    return 0;
}



