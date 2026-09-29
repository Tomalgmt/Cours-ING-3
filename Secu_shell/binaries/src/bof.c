#include <stdio.h>
#include <string.h>
#include <sys/personality.h>

// Aucune protection

void vuln(const char *in){
    char buf[120];
    strcpy(buf, in); // overflow volontaire
    printf("%s\n", buf);
}


int main(int argc, char **argv){
    // desactivation de l'ASLR uniquement pour cet executable
    // car casse couilles de desactiver sur tout le systeme
    int old = personality(0xffffffff);
    personality(old | ADDR_NO_RANDOMIZE);
    
    vuln(argc > 1 ? argv[1] : "hello");
    return 0;
}



