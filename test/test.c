#include <stdlib.h>
#include <stdio.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

int main(int argc, const char *argv[]) {
    int r = 0;
    lua_State *L = NULL;
    if(argc < 2) {
        return 1;
    }

    L = luaL_newstate();
    if(L == NULL) abort();
    luaL_openlibs(L);

    r = luaL_dofile(L,argv[1]);
    if(r) {
        printf("%s\n",lua_tostring(L,-1));
    }

    lua_close(L);

    return r;
}
