# Compilateur et options
CC      := gcc
CFLAGS_NOSEC  := -O0 -g -no-pie -fno-stack-protector -Wl,-z,execstack 	# désactive les optimisations et options de sécurité
CFLAGS_ASLR  := -O0 -g -no-pie -fno-stack-protector -Wl,-z,noexecstack 	# désactive les optimisations et options de sécurité
CFLAGS_PIE  := -O0 -g -fno-stack-protector -Wl,-z,noexecstack 	# désactive les optimisations et options de sécurité
LDFLAGS :=                     			# si besoin d’options de link

# Tous les .c du dossier src
SRC := $(wildcard src/*.c)

# Remplace src/xxx.c par bin/xxx
BIN := $(patsubst src/%.c,bin/%,$(SRC))

# Cible par défaut : tout compiler
all: $(BIN)

bin/bof: src/bof.c | bin
	$(CC) $(CFLAGS_NOSEC) $< -o $@ $(LDFLAGS)

bin/aslr: src/aslr.c | bin
	$(CC) $(CFLAGS_ASLR) $< -o $@ $(LDFLAGS)

bin/pie: src/pie.c | bin
	$(CC) $(CFLAGS_PIE) $< -o $@ $(LDFLAGS)

# Crée le dossier bin/ s’il n’existe pas
bin:
	mkdir -p bin

# Nettoyage
clean:
	rm -rf bin/*

.PHONY: all clean

