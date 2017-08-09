
# About

This is a Windows PIC (Position Independent Code) using RSA key exchange, AES-256 for symmetric encryption and SHA3-256 for Message Authentication Code. It's intended to demonstrate the use of C for writing shellcodes/PICs.

# Stack Limit

If you intend to make modifications to the source in spz.c, bear in mind that if increasing **SPP_DATA_LEN** in include.h or **BIT_LEN** in modexp.h that you must also do the same for the server component. I'd prefer to simplify this but right now this code is just experimental. Also, you should be aware the stack has limits which is why cs32.asm and cs64.asm are required after allocation of stack. However, even with this code, the host application PIC runs in can behave unexpectedly. My recommendation is to minimize as much stack use as possible. In the future, I will try use the heap instead.

For x64, the stack limit is checked each time a routine allocates stack memory. This is required to avoid generating exceptions.

![alt text](https://github.com/odzhan/shells/blob/master/s5/pic_client/stack_limit.jpg)

# Compiling pic_client

See bld32.bat to generate x86 code or bld64.bat for x64. cs32.asm and cs64.asm both require YASM or NASM to assemble. A binary is compiled with no imports and xbin.exe then extracts the .text section to file. The IP v4 address and Port number are hardcoded to 127.0.0.1:1234 and must be altered if testing between 2 remote systems. runsc can be used to execute the PIC for testing locally.

    runsc -x -f spz32.exe.bin 
    
To generate a C array for further manipulation, use bin2sc
    
    bin2sc spz32.exe.bin >spz32.h

This will generate a C array of binary (bin2sc requires udis86)
To compile an EXE file for debugging purposes, uncomment DEBUG in include.h and use MSVC with the following command line.

    cl /O2 /Os /GS- spz.c aes.c sha3.c modexp.c

# Screenshots

Only the DEBUG version of pic_client displays anything to screen so the following is just output of runsc executing spz.bin on localhost.

![alt text](https://github.com/odzhan/shells/blob/master/s5/pic_client/pic_client_ss.png)

And here's screen shot of session with client PIC

![alt text](https://github.com/odzhan/shells/blob/master/s5/pic_client/s5_server_ss.png)

# Operating systems tested

Both include x86 and x64 versions

1. Windows NT (unlikely without changes to API, specifically winsock)
2. Windows 2000 (depending on service pack, requires changes like NT)
3. Windows XP (working on SP1)
4. Windows 7 (presumably Vista works but untested)
5. Windows 10

# Known problems

1. Client does not verify public key is sent by trusted party.
2. The underlying protocol most likely has as yet unidentified security problems

# Author

[@odzhancode](https://www.twitter.com/odzhancode "Follow me on Twitter")
