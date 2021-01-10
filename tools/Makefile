.PHONY: all clean

PKGCONFIG = pkg-config

EXE =
OBJ = .o

CFLAGS = -Wall -Wextra $(shell $(PKGCONFIG) --cflags libsodium)
LDFLAGS = $(shell $(PKGCONFIG) --libs libsodium)

MODS = \
  crypto_auth

PROGS = $(addprefix create-results-,$(MODS))
OBJS  = $(addsuffix $(OBJ),$(PROGS))
EXES  = $(addsuffix $(EXE),$(PROGS))

all: $(PROGS)

create-results-%: create-results-%$(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

create-results-%$(OBJ): create-results-%.c
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f $(OBJS)
	rm -f $(EXES)
