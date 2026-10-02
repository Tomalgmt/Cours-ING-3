# Compilateur et options
CC      := gcc
CFLAGS  := -fPIC -Wl,-z,relro -Wl,-z,now -O0 -fno-stack-protector -Wl,-z,noexecstack -no-pie
LDFLAGS :=                     			# si besoin d’options de link


# Tous les .c du dossier src
SRC := $(wildcard src/*.c)

# Remplace src/xxx.c par bin/xxx
BIN := $(patsubst src/%.c,bin/%,$(SRC))

# Cible par défaut : tout compiler
all: $(BIN)

# Règle générique pour compiler chaque .c en exécutable dans bin/
bin/%: src/%.c | bin
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

# Crée le dossier bin/ s’il n’existe pas
bin:
	mkdir -p bin

# Nettoyage
clean:
	rm -rf bin/*

.PHONY: all clean

