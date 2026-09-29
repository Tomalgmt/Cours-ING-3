#include <stdio.h>
#include <string.h>

// NX + ASLR + PIE

void vuln(){
    char buf[120];
    printf("Bonjour, je suis Giuseppe le Perroquet ! Posez-moi une question :\n");
    scanf("%s", &buf);  
    printf(buf);
}


int main(int argc, char **argv){
    vuln();
    return 0;
}



