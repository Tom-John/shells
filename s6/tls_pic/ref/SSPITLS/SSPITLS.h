/*
 * libfcgi2.h 
 *
 *     Prototype Definitions for SSPI Library SSPITLS.dll
 *
 *     www.coastrd.com Coast Research © 2010
 *
 * NOTES:
 * CDECL Calling Convention 
 * All Strings are ANSI *NOT* Unicode
 */



#ifndef _SSPITLS_H
#define _SSPITLS_H
//    
//#ifdef __cplusplus // for C++ compilers
extern "C" { // (cdecl calling convention)
//#endif


// Connection Codes
#define  SP_DEFAULT    = 0  
#define  SP_PROT_PCT1  = 3  
#define  SP_PROT_SSL2  = 12 
#define  SP_PROT_SSL3  = 48 
#define  SP_PROT_TLS1  = 192 
   

/*----------------------------------------------------------------------
 * TLSInit
 *
 *	Initialize the SSPITLS Library
 *
 * Return:
 * 	hLib upon success
 *      -ve if an error occurred - Call TLSGetLastError() for Error description
 *
 * Comments:
 * 	Creates the TLS_SESSION structure and VirtualAlloc() memory for it
 * 	calls InitSecurityInterface()
 *  calls WSAStartup()
 */
int	FCGX_InitRequestz(const char *zServerName, int TCPport, DWORD dwProtocol, int dwProtocol, const char *zDebug);


/*----------------------------------------------------------------------
 * TLSConnect
 *
 *      Connect to the Server and establish a secure connection
 *
 * Return:
 *	1 for success, -ve for Error - Call TLSGetLastError() for Error description
 *
 * Comments:
 *  Create credentials
 *  Connect to the server
 *  Perform handshake
 *  Authenticate server's credentials. 
 *  Get server's certificate.
 *  Validate the server certificate.
 *  Free the server certificate context.
 *  Read stream encryption properties. 
 *  Calculate Buffer Length. 
 */
int	TLSConnect(DWORD pIn, DWORD pBuff, int BufLen);

/*----------------------------------------------------------------------
 * TLSClose
 *
 *      Close the Connection, free memory
 *
 * Return:
 *	1 regardless
 *
 * Comments:
 *      Send a close_notify alert to the server and close down the connection
 *      Free the SERVER certificate context.
 *      Free SSPI context HANDLE.
 *      Free SSPI credentials HANDLE.
 *      Close socket.
 *      Shutdown WinSock subsystem.
 *      Close "MY" certificate store.
 *      Free Memory
 */
int TLSClose(DWORD pIn);

/*----------------------------------------------------------------------
 * TLSEncryptSend 
 *
 * 	Send bytes to the server over the connection
 *
 * Return:
 *	cbData - Number of bytes of encrypted data sent
 *      -ve for Error - Call TLSGetLastError() for Error description
 *
 * Comments:
 *  The message is encrypted in place
 *  Message is sent to the server via the socket
 */
int TLSEncryptSendz(DWORD pIn, const char *zBuffer); 

/*----------------------------------------------------------------------
 * TLSReadDecrypt 
 *
 * 	Read response from the server
 *
 * Return:
 *	cbData - Number of bytes of decrypted data received
 *      -ve for Error - Call TLSGetLastError() for Error description
 *
 * Comments:
 *	The response is decrypted in place
 */
int TLSReadDecryptz(DWORD pIn, const char *zBuffer); 


/*----------------------------------------------------------------------
 * FCGX_PutStr 
 *
 * 	Recover last error to the buffer
 *
 * Return:
 *	Length of error message
 */
int TLSGetLastErrorz(DWORD pIn, const char *zBuffer); 

}
#endif // _SSPITLS_H

