@echo off
cl /O2 /Os /GS- tlscmd.c cmd.c tls.c tcp.c
del *.obj