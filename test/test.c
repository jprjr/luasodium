#include <stdlib.h>
#include <stdio.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

int main(int argc, const char *argv[]) {
	const char *errmsg = NULL;
    int r = 0;
    lua_State *L = NULL;
    if(argc < 2) {
        return 1;
    }

    L = luaL_newstate();
    if(L == NULL) abort();
    luaL_openlibs(L);

    r = luaL_loadfile(L,argv[1]);
	switch(r) {
		case 0: break;
		case LUA_ERRSYNTAX: {
			fprintf(stderr,"error loading %s - syntax error\n",argv[1]);
			return 1;
		}
		case LUA_ERRMEM: {
			fprintf(stderr,"error loading %s - memory allocation error\n",argv[1]);
			return 1;
		}
		case LUA_ERRFILE: {
			fprintf(stderr,"error loading %s - unable to open/read file\n",argv[1]);
			return 1;
		}
		default: {
			fprintf(stderr,"error loading %s - unknown error %d\n",argv[1],r);
			return 1;
		}
	}
	
	r = lua_pcall(L, 0, LUA_MULTRET, 0);
	if(r != 0) {
		errmsg = lua_tostring(L,-1);
		fprintf(stderr,"%s\n",errmsg);
	}
    lua_close(L);
    return r;
}
