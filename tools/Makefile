.PHONY: all clean

PKGCONFIG = pkg-config

EXE =
OBJ = .o

CFLAGS = -Wall -Wextra $(shell $(PKGCONFIG) --cflags libsodium)
LDFLAGS = $(shell $(PKGCONFIG) --libs libsodium)

MODS = \
  crypto_aead \
  crypto_auth \
  crypto_box \
  crypto_generichash \
  crypto_hash \
  crypto_onetimeauth \
  crypto_scalarmult \
  crypto_secretbox \
  crypto_shorthash \
  crypto_stream \
  crypto_sign

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
