
' Complete SMTPS session using SSPITLS.dll

#COMPILE EXE "TLSEx.exe"
#DIM ALL

#INCLUDE "WIN32API.inc"     

#INCLUDE "SSPI_Header.inc"

  
$DEBUG_FILE       = "DLL_dbg.txt"
          
$MailHost         = "smtp.gmail.com"   ' SMTP Host - alias for gmail-smtp.l.google.com
$MailFrom         = "automail@aol.com" ' your email FROM addresse                                                              
$UserName         = "you@aol.com"      ' your gmail account
$Password         = "my"               ' your gmail account
$MailTo           = "John@yahoo.com"   '


'いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい'
FUNCTION MimeEncode( BYVAL sFileData AS STRING ) AS STRING ' Base 64 Encoding

  LOCAL Blk, TotBlk, bX, bY, bZ, ix1, ix2, ix3, ix4  AS LONG
  LOCAL pIn, pOut, pTable AS BYTE PTR
  LOCAL sBase64, sResult, sPad AS STRING
  
    
    sBase64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" ' Set up Base64 translation table
    sPad    = STRING$(2 - (LEN(sFileData) - 1) MOD 3, "=") ' Calculate padding for Base64 stream
    TotBlk  = (LEN(sFileData) + 2) \ 3 ' Round up the length of the input data to a multiple of three
    IF TotBlk * 3 > LEN(sFileData) THEN sFileData = LSET$(sFileData, TotBlk * 3 USING $NUL)
    
    sResult = SPACE$(TotBlk * 4) ' Allocate the space for the output string
    pIn     = STRPTR(sFileData)  ' Set up pointers so we can treat the data as byte streams
    pOut    = STRPTR(sResult)
    pTable  = STRPTR(sBase64)
    FOR Blk = 1 TO TotBlk  ' Loop through our entire input buffer
      bX = @pIn : INCR pIn ' Get the next three binary data bytes to process
      bY = @pIn : INCR pIn
      bZ = @pIn : INCR pIn
      ix1  =  bX \ 4  ' Translate the three data bytes into four Base64 table indices
      ix2  = (bX AND 3) * 16 + bY \ 16
      ix3  = (bY AND 15)* 4  + bZ \ 64
      ix4  =  bZ AND 63
      @pOut = @pTable[ix1] : INCR pOut ' Use the Base64 table to encode the output string
      @pOut = @pTable[ix2] : INCR pOut
      @pOut = @pTable[ix3] : INCR pOut
      @pOut = @pTable[ix4] : INCR pOut
    NEXT
    RSET ABS sResult = sPad ' Merge in the padding bytes 

  FUNCTION = sResult 

END FUNCTION
      

'**************************************************************************************** 
FUNCTION SMTPSsend( sSrvr AS STRING,_ 
                    sUser AS STRING,_ 
                    sPass AS STRING,_ 
                    sFrom AS STRING,_ 
                    sTo   AS STRING,_                                         
                    sBody AS STRING,_  
                    sERR  AS STRING ) AS LONG 
												
  LOCAL RetVal AS LONG				
  LOCAL sBuff AS STRING 
  LOCAL sRequest, sReply AS STRING
  LOCAL pSC AS DWORD ' TLS_SESSION PTR ' TCPport AS LONG, dwProtocol AS DWORD, fVerbose


    '- Init 
    pSC = TLSInit( sSrvr, 465, 192, 2, $DEBUG_FILE ) ' %SP_PROT_TLS1 = 192
    IF pSC = 0 THEN sERR = "Init Failed" : FUNCTION = -1 : EXIT FUNCTION  

    DO   
      '- Connect     
      sBuff  = "12345" + sBody + "1234567890123456" ' Data Buffer + 5 Bytes Head, 16 Bytes Tail
      IF TLSConnect( pSC, STRPTR(sBuff), LEN(sBuff) ) < 0 THEN RetVal = -2 : EXIT DO     

  
      '- Discard initial response from gmail 
      IF TLSReadDecrypt(pSC, sReply)  <> %SEC_E_OK             THEN RetVal = -10 : EXIT DO

                                                    
      '- Conduct SMTP session  
      sRequest = "EHLO " + $CRLF                              
      IF TLSEncryptSend(pSC, sRequest) = %SEC_E_INTERNAL_ERROR THEN RetVal = -11 : EXIT DO
      WHILE pSC
        IF TLSReadDecrypt(pSC, sReply)  <> %SEC_E_OK           THEN RetVal = -12 : EXIT DO 
        IF VAL(sReply) <> 250 THEN 
          IF VAL(sReply) = 220 AND INSTR(sReply, "mx.google.com") THEN ITERATE ' The welcome message was late
          sERR = "EHLO Failed" : RetVal = -54 : EXIT DO
        END IF 
        EXIT LOOP
      WEND

                       
      sRequest = "AUTH LOGIN " + $CRLF  
      IF TLSEncryptSend(pSC, sRequest) = %SEC_E_INTERNAL_ERROR THEN RetVal = -13 : EXIT DO
      IF TLSReadDecrypt(pSC, sReply)  <> %SEC_E_OK             THEN RetVal = -14 : EXIT DO
      IF VAL(sReply) <> 334 THEN sERR = "AUTH LOGIN Failed" : RetVal = -55 : EXIT DO

      sRequest = MimeEncode(sUser) + $CRLF ' Username 
      IF TLSEncryptSend(pSC, sRequest) = %SEC_E_INTERNAL_ERROR THEN RetVal = -15 : EXIT DO
      IF TLSReadDecrypt(pSC, sReply)  <> %SEC_E_OK             THEN RetVal = -16 : EXIT DO
      IF VAL(sReply) <> 334 THEN sERR = "Username Failed" : RetVal = -56 : EXIT DO 

      sRequest = MimeEncode(sPass) + $CRLF ' Password  
      IF TLSEncryptSend(pSC, sRequest) = %SEC_E_INTERNAL_ERROR THEN RetVal = -17 : EXIT DO
      IF TLSReadDecrypt(pSC, sReply)  <> %SEC_E_OK             THEN RetVal = -18 : EXIT DO
      IF VAL(sReply) <> 235 THEN sERR = "Password Failed" : RetVal = -57 : EXIT DO  

      sRequest = "MAIL FROM: <" + sFrom + ">" + $CRLF '
      IF TLSEncryptSend(pSC, sRequest) = %SEC_E_INTERNAL_ERROR THEN RetVal = -19 : EXIT DO
      IF TLSReadDecrypt(pSC, sReply)  <> %SEC_E_OK             THEN RetVal = -20 : EXIT DO
      IF VAL(sReply) <> 250 THEN sERR = "MAIL FROM Failed" : RetVal = -58 : EXIT DO  

      sRequest = "RCPT TO: <" + sTo + ">" + $CRLF ' Rec
      IF TLSEncryptSend(pSC, sRequest) = %SEC_E_INTERNAL_ERROR THEN RetVal = -21 : EXIT DO
      IF TLSReadDecrypt(pSC, sReply)  <> %SEC_E_OK             THEN RetVal = -22 : EXIT DO
      IF VAL(sReply) <> 250 THEN sERR = "RCPT TO Failed" : RetVal = -59 : EXIT DO   

      sRequest = "DATA " + $CRLF ' Body begins  
      IF TLSEncryptSend(pSC, sRequest) = %SEC_E_INTERNAL_ERROR THEN RetVal = -23 : EXIT DO
      IF TLSReadDecrypt(pSC, sReply)  <> %SEC_E_OK             THEN RetVal = -24 : EXIT DO
      IF VAL(sReply) <> 354 THEN sERR = "DATA Failed" : RetVal = -60 : EXIT DO   
    
      sRequest = sBody + $CRLF + "." + $CRLF ' Body
      IF TLSEncryptSend(pSC, sRequest) = %SEC_E_INTERNAL_ERROR THEN RetVal = -25 : EXIT DO
      IF TLSReadDecrypt(pSC, sReply)  <> %SEC_E_OK             THEN RetVal = -26 : EXIT DO
      IF VAL(sReply) <> 250 THEN sERR = "Sending Body Failed" : RetVal = -61 : EXIT DO 

      sRequest = "QUIT " + $CRLF               
      IF TLSEncryptSend(pSC, sRequest) = %SEC_E_INTERNAL_ERROR THEN RetVal = -27 : EXIT DO
      IF TLSReadDecrypt(pSC, sReply)  <> %SEC_E_OK             THEN RetVal = -28 : EXIT DO
      IF VAL(sReply) <> 221 THEN sERR = "QUIT Failed" : RetVal = -62 : EXIT DO 

      EXIT LOOP ' done
    LOOP 
           
    IF RetVal < 0 AND TLSGetLastError(pSC, sErr) THEN sERR = sERR + TRIM$(sErr)

    CALL TLSClose(pSC) ' Close the Connection 
             

END FUNCTION   
               


'****************************************************************************************
FUNCTION PBMAIN()
                  
  LOCAL RetVal AS LONG 
  LOCAL sBody, sRet AS STRING                
     

    sBody = sBody + "From: "    + $MailFrom + $CRLF
    sBody = sBody + "To: "      + $MailTo   + $CRLF
    sBody = sBody + "Subject: " + "DLL SChannel"  + $CRLF
    sBody = sBody + "X-Mailer: cgimail at " + $MailFrom + $CRLF + $CRLF
    sBody = sBody + "SSPI SChannel email using alalal" 


    RetVal = SMTPSsend( $MailHost, $UserName, $Password, $MailFrom, $MailTo, sBody, sRet )   
    IF RetVal < 0 THEN
      MSGBOX "Error = "+STR$(RetVal),16,"Gmail"
    ELSE
      MSGBOX "Email Sent OK",64,"Gmail"
    END IF  


END FUNCTION 

