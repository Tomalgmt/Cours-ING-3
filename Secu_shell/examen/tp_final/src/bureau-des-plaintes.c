#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>

char name[20];
const char password[] = "ClearText_CheatCode101";

__attribute__((noinline, used))
void cadeau_bisous(void) {
    __asm__ volatile (
        "pop %rdi\n"
        "ret\n"
        "pop %rsi\n"
        "ret\n"
        "pop %rdx\n"
        "ret\n"
        "pop %rax\n"
        "ret\n"
        "syscall\n"
        "ret\n"
        "mov %rsi, %rdi\n"
        "ret\n"
    );
}



// désactivée
static int anti_debug() {
    errno = 0;
    long r = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    if (r == -1 && errno) return 1;
    if (getenv("LD_PRELOAD") || !isatty(0)) {}
    return 0;
}

void easter_egg(){
    printf("\n\tSimularbre lance \"Gravité\".\n");
    printf("\tC'est super efficace !\n");
    printf("\tBatochef est KO.\n\n");
    system("touch .batochef_on_the_ground");

}

int welcome(){
    char commentaire[128];
    char password[] = "ClearText_CheatCode101";
    printf("Bonjour et bienvenue !\n\n");
    printf("Vous avez souhaité déposer une réclamation suite au comportement honteux de votre formateur.\n");
    printf("Pour commencer, quel est votre nom ?\n");
    scanf(" %[^\n]", &name);

    if(!strcmp(name, "Batochef"))
        easter_egg();

    printf("\nMerci, %s. Veuillez saisir votre réclamation ci-dessous (128 caractères maximum) :\n", name);
    scanf(" %[^\n]", &commentaire);

    printf("\nMerci, %s. Voici donc votre réclamation :\n\n", name);
    printf("\"");
    printf(commentaire);
    printf("\"");
    printf("\n\n");
    printf("Traitement de votre requête ...\n");
    sleep(2);

    if(!strcmp(password,name))
        printf("\nFélicitations ! Vous avez trouvé le cheatcode. 18/20.\n");
    else
        printf("\nFélicitations ! Votre note est désormais de 2/20.\n");
    printf("Belle journée ! (noob)\n");
    return 0;
}

int main() {
    //int ret = 0;
    //if (ret = anti_debug()) return ret;
    welcome();
    return 0;
}
