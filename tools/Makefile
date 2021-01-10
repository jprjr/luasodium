.PHONY: all clean

PKGCONFIG = pkg-config

EXE =
OBJ = .o

CFLAGS = -Wall -Wextra $(shell $(PKGCONFIG) --cflags libsodium)
LDFLAGS = $(shell $(PKGCONFIG) --libs libsodium)

MODS = \
  crypto_auth \
  crypto_box

PROGS = $(addprefix create-results-,$(MODS))
OBJS  = $(addsuffix $(OBJ),$(PROGS)) misc$(OBJ)
EXES  = $(addsuffix $(EXE),$(PROGS))

all: $(PROGS)

create-results-%: create-results-%$(OBJ) misc$(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

%$(OBJ): %.c
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f $(OBJS)
	rm -f $(EXES)
