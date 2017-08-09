@echo off
cl /IC:\openssl\include /nologo /O2 /Os /GS- /c s5.c
cl /IC:\openssl\include /nologo /O2 /Os /GS- /c server.c
cl /IC:\openssl\include /nologo /O2 /Os /GS- /c spp.c
cl /nologo /O2 /Os /GS- /c aes.c
cl /nologo /O2 /Os /GS- /c sha3.c
cl /nologo s5.obj server.obj spp.obj aes.obj sha3.obj lib\x86\libeay32.lib
del *.obj