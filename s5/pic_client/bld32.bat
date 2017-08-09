@echo off
yasm -fwin32 cs32.asm -ocs32.obj
cl.exe -c -nologo -Os -O2 -Gm- -GR- -EHa- -Oi -GS- aes.c
cl.exe -c -nologo -Os -O2 -Gm- -GR- -EHa- -Oi -GS- sha3.c
cl.exe -c -nologo -Os -O2 -Gm- -GR- -EHa- -Oi -GS- modexp.c
cl.exe -c -nologo -Os -O2 -Gm- -GR- -EHa- -Oi -GS- -DXALONE spz.c
link /order:@order.txt /base:0 spz.obj sha3.obj aes.obj modexp.obj cs32.obj -subsystem:console -nodefaultlib kernel32.lib -stack:0x100000,0x100000
xbin spz.exe .text
del *.obj