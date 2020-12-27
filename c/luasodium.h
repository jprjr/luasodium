#ifndef LUASODIUM_H
#define LUASODIUM_H

#include <sodium.h>
#include <lua.h>
#include <lauxlib.h>
#include <assert.h>

typedef void * ffi_pointer_t;

typedef struct luasodium_constant_s {
    const char *name;
    size_t value;
} luasodium_constant_t;

#if !defined(luaL_newlibtable) \
  && (!defined LUA_VERSION_NUM || LUA_VERSION_NUM==501)
static void luaL_setfuncs (lua_State *L, const luaL_Reg *l, int nup) {
  luaL_checkstack(L, nup+1, "too many upvalues");
  for (; l->name != NULL; l++) {  /* fill the table with given functions */
    int i;
    lua_pushstring(L, l->name);
    for (i = 0; i < nup; i++)  /* copy upvalues to the top */
      lua_pushvalue(L, -(nup+1));
    lua_pushcclosure(L, l->func, nup);  /* closure with those upvalues */
    lua_settable(L, -(nup + 3));
  }
  lua_pop(L, nup);  /* remove upvalues */
}
#endif

static void
luasodium_set_constants(lua_State *L, const luasodium_constant_t *c) {
    for(; c->name != NULL; c++) {
        lua_pushstring(L,c->name);
        lua_pushinteger(L,c->value);
        lua_settable(L,-3);
    }
}

static int
luasodium_push_constants(lua_State *L, const luasodium_constant_t *c) {
    int i = 0;
    for(; c->name != NULL; i++, c++) {
        lua_pushinteger(L,c->value);
    }
    return i;
}

#endif
