#!/bin/bash

LIB_DIR="../../../node_modules/KXSmartTokenSdk"

emcc -I "$LIB_DIR/src/KXAPDUKit" \
     -I "$LIB_DIR/src/KXUtilLib" \
     -I "$LIB_DIR/src/KXLogLib" \
     -O3 \
     KXSEAPDUKit.cpp \
     $LIB_DIR/src/KXAPDUKit/*.cpp \
     $LIB_DIR/src/KXUtilLib/*.cpp \
     $LIB_DIR/src/KXLogLib/*.cpp \
     -o ../KXSEAPDUKit.js \
     -s ENVIRONMENT=web \
     -s EXPORTED_RUNTIME_METHODS='["cwrap", "ccall", "lengthBytesUTF8", "stringToUTF8"]' \
     -s EXPORTED_FUNCTIONS="['_free', '_malloc']" \
     -s EXPORT_ES6=1 \
     -s MODULARIZE=1 \
     -s ASYNCIFY \
     -s ASYNCIFY_IMPORTS='["ctap_apdu_exchange"]'