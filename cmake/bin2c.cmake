cmake_minimum_required (VERSION 2.8.12)

# requires 3 paramters
# OUTPUT_C - output filename
# INPUT_FILE - input filename
# IDENT - what symbol to use

string(TOUPPER ${IDENT} UPPER_IDENT)

# Create header for C file
file(WRITE ${OUTPUT_C} "#ifndef ${UPPER_IDENT}\n")
file(APPEND ${OUTPUT_C} "#define ${UPPER_IDENT}\n\n")

file(READ ${INPUT_FILE} filedata HEX)
string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1," filedata ${filedata})
file(APPEND ${OUTPUT_C} "static const char ${IDENT}[] = {${filedata}};\n\n")
file(APPEND ${OUTPUT_C} "static const int ${IDENT}_length = sizeof(${IDENT});\n\n")

file(APPEND ${OUTPUT_C} "#endif\n")
