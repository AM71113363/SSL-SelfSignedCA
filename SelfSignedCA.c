/*
 *  Certificate generation and signing
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/*
 Original source code can be found in Mbedtls->programs->->x509->cert_write.c
*/


#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <commctrl.h>
#include "mbedtls/config.h"
#include "mbedtls/platform.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/oid.h"
#include "mbedtls/asn1write.h"

#define ID_MX_CA_PATH       8002

#define ISCHECKED(_h_) SendMessage(_h_,BM_GETCHECK,0,0)==BST_CHECKED
#define SETCHECKED(_h_) SendMessage(_h_,BM_SETCHECK,(WPARAM)BST_CHECKED,(LPARAM)0)
#define SETUNCHECKED(_h_) SendMessage(_h_,BM_SETCHECK,(WPARAM)BST_UNCHECKED,(LPARAM)0)

#define FONT_SET(_h_)        SendMessage(_h_, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(1, 0))
#define WS_BOXCENTER         WS_CHILD|WS_VISIBLE|BS_GROUPBOX|BS_CENTER
#define COMBO_ADD(_h_,_a_)   SendMessage(_h_,CB_ADDSTRING,0,(LPARAM)(LPCSTR)_a_)
#define COMBO_SET(_h_,_i_)   SendMessage(_h_,CB_SETCURSEL, (WPARAM)_i_,0)
#define COMBO_GET(_h_)       SendMessage(_h_, CB_GETCURSEL, 0, 0)
#define WSCHECKBOXCENTER     WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX|BS_TEXT

#define NOT_BEFORE "20200101000000"
#define NOT_AFTER  "20500101000000"


void CenterOnScreen();
void ReadCertificate();
static char szClassName[ ] = "SelfSignedCA";
HINSTANCE ins;
HWND hWnd;
HFONT hFont;

typedef struct DATA_
{
    UCHAR KeyName[MAX_PATH];
    UCHAR CertName[MAX_PATH];
    UCHAR IssuerName[MAX_PATH];
    UCHAR SerialNumber[32];
    UINT KeyUsage;
    int max_pathlen;
    mbedtls_md_type_t md;
}DATA;

DATA data;

HWND CN_INFO;
HWND C_INFO;
HWND O_INFO;
HWND OU_INFO;
HWND CA_MAX_LEN;

HWND DIGITAL_SIGNATURE_TYPE;    
HWND NON_REPUDIATION_TYPE;           
HWND KEY_ENCIPHERMENT_TYPE; 
HWND DATA_ENCIPHERMENT_TYPE;  
HWND KEY_AGREEMENT_TYPE;         
HWND KEY_CERT_SIGN_TYPE;          
HWND CRL_SIGN_TYPE;
     
HWND hDigest;

#define MAKEINFO(_h_,_n_,_t_,_w_,_v_) _n_##_INFO = HWND_HELP_INFO(_h_,#_n_,_v_,_t_,_w_); FONT_SET(_n_##_INFO)

HWND HWND_HELP_INFO(HWND hnd,UCHAR *Name,UCHAR *value,UINT top,UINT width)
{
     FONT_SET(CreateWindow("STATIC",Name,WS_CHILD|WS_VISIBLE,188,top,20,15,hnd,0,ins,NULL));
     return CreateWindow("EDIT",value,WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL,212,top,width, 15, hnd, NULL,ins, NULL);
} 

#define MAKETYPE(_h_,_n_,_t_) _n_##_TYPE = HWND_HELP_TYPE(_h_,#_n_,_t_); FONT_SET(_n_##_TYPE)

HWND HWND_HELP_TYPE(HWND hnd,UCHAR *Name,UINT top)
{
     return CreateWindow("BUTTON",Name,WSCHECKBOXCENTER,10,top,158,15,hnd,NULL,ins,NULL);
}

void ErrorMsgHandle(UCHAR *txt,int error)
{
    UCHAR buffer[64]="ERROR";
    if(error != 0)
    {
       sprintf(buffer,"ErrorCode: %i ( -0x%04X )\0",error,-error);
    }
    MessageBox(NULL,txt,buffer, MB_ICONEXCLAMATION|MB_SYSTEMMODAL|MB_OK);
}


void AddDigestAlgorith(const char *md_name)
{
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_string(md_name);
    if(md_info != NULL)
         COMBO_ADD(hDigest,md_name); 
}


int write_certificate( mbedtls_x509write_cert *crt, UCHAR *output_file,  void *p_rng )
{
    int ret;
    FILE *f;
    UCHAR output_buf[4096];
    size_t len = 0;

    memset( output_buf, 0, 4096 );
    ret = mbedtls_x509write_crt_pem( crt, output_buf, 4096,  mbedtls_ctr_drbg_random, p_rng );
    if(ret < 0 ){
        ErrorMsgHandle("Error: mbedtls_x509write_crt_pem",ret);
      return( ret );
    }

    len = strlen( output_buf );

    if( ( f = fopen( output_file, "wb" ) ) == NULL )
    {
        SetWindowText(hWnd,"ERROR: write_certificate fopen");
        return( -1 );
     }
    if( fwrite( output_buf, 1, len, f ) != len )
    {
        fclose( f );
        SetWindowText(hWnd,"ERROR: write_certificate fwrite");
        return( -1 );
    }

    fclose( f );

    return( 0 );
}


int CreateSelfsignedCert( DATA *input)
{
    int ret = 0;
    mbedtls_x509write_cert NewCert;
    mbedtls_mpi serial;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_pk_context CA_Key;
    
    mbedtls_pk_init( &CA_Key );
    ret = mbedtls_pk_parse_keyfile( &CA_Key, input->KeyName, NULL );
    if(ret != 0 )
    {
        ErrorMsgHandle("Error: mbedtls_pk_parse_keyfile",ret);
        mbedtls_pk_free( &CA_Key );
      return ret;
    }
    
    mbedtls_x509write_crt_init( &NewCert );
    mbedtls_mpi_init( &serial );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );
    SetWindowText(hWnd,"Running...");
    do
    {
        ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,input->SerialNumber,strlen(input->SerialNumber) );
        if(ret != 0 ){ ErrorMsgHandle("ERROR: mbedtls_ctr_drbg_seed",ret); break; }

        ret = mbedtls_mpi_read_string( &serial, 10, input->SerialNumber);
        if(ret != 0 ){ ErrorMsgHandle("ERROR: mbedtls_mpi_read_string",ret); break; }
        
        mbedtls_x509write_crt_set_subject_key( &NewCert, &CA_Key );
        mbedtls_x509write_crt_set_issuer_key( &NewCert, &CA_Key );
    
        ret = mbedtls_x509write_crt_set_subject_name( &NewCert, input->IssuerName );
        if(ret != 0 ){ ErrorMsgHandle("ERROR: mbedtls_x509write_crt_set_subject_name",ret); break; }

        ret = mbedtls_x509write_crt_set_issuer_name( &NewCert, input->IssuerName );
        if(ret != 0 ){ ErrorMsgHandle("ERROR: mbedtls_x509write_crt_set_issuer_name",ret); break; }
    
        mbedtls_x509write_crt_set_version( &NewCert, MBEDTLS_X509_CRT_VERSION_3);
        mbedtls_x509write_crt_set_md_alg( &NewCert, input->md);

        ret = mbedtls_x509write_crt_set_serial( &NewCert, &serial );
        if(ret != 0 ){ ErrorMsgHandle("ERROR: mbedtls_x509write_crt_set_serial",ret); break; }

        ret = mbedtls_x509write_crt_set_validity( &NewCert, NOT_BEFORE, NOT_AFTER );
        if(ret != 0 ){ ErrorMsgHandle("ERROR: mbedtls_x509write_crt_set_validity",ret);  break; }

        ret = mbedtls_x509write_crt_set_basic_constraints( &NewCert, 1, input->max_pathlen );
        if(ret != 0 ){ ErrorMsgHandle("ERROR: mbedtls_x509write_crt_set_basic_constraints",ret); break; }

        ret = mbedtls_x509write_crt_set_subject_key_identifier( &NewCert );
        if(ret != 0 ){ ErrorMsgHandle("ERROR: mbedtls_x509write_crt_set_subject_key_identifier",ret); break; }

        ret = mbedtls_x509write_crt_set_authority_key_identifier( &NewCert );
        if(ret != 0 ){ ErrorMsgHandle("ERROR: mbedtls_x509write_crt_set_authority_key_identifier",ret); break; }

        if( input->KeyUsage != 0 )
        {
           ret = mbedtls_x509write_crt_set_key_usage( &NewCert, input->KeyUsage );
           if(ret != 0 ){ ErrorMsgHandle("ERROR: mbedtls_x509write_crt_set_key_usage",ret); break; }
        }
        SetWindowText(hWnd,"Write To File. . .");
        ret= write_certificate( &NewCert, input->CertName, &ctr_drbg);
    }while(0);
    
    mbedtls_pk_free( &CA_Key );
    mbedtls_mpi_free( &serial );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    mbedtls_x509write_crt_free( &NewCert );
return ret;
}


void CreateCACertificate()
{
    UCHAR *p; UINT type;
    UCHAR buffer[64]; UCHAR delimiter[2]="\0\0";
    p=data.IssuerName;

//info
    memset(buffer, 0, 64);
    if(GetWindowText(C_INFO,buffer,4))   //get Country CODE (C)
	{
         p += sprintf(p,"C=%s\0",buffer); delimiter[0]=',';
         memset(buffer, 0, 64);
    }
    if(GetWindowText(O_INFO,buffer,64))    //get OrgName (O)
	{
         p += sprintf(p,"%sO=%s\0",delimiter,buffer);  delimiter[0]=',';
         memset(buffer, 0, 64);
    }
    if(GetWindowText(OU_INFO,buffer,64))   //get OrgUnitName (OU)
	{
         p += sprintf(p,"%sOU=%s\0",delimiter,buffer);  delimiter[0]=',';
         memset(buffer, 0, 64);
    }
    if(!GetWindowText(CN_INFO,buffer,64))    //get CommonName (CN)
	{
         ErrorMsgHandle("Common Name(CN) is Empty",0);
         return;
    }
    sprintf(p,"%sCN=%s\0",delimiter,buffer);
  
//set serialnumber
    sprintf(data.SerialNumber,"%d\0",GetTickCount());
//set CA max len
    if(ISCHECKED(GetDlgItem(hWnd,ID_MX_CA_PATH)))
    {
        data.max_pathlen = -1;                 
    }
    else
    {
        memset(buffer, 0, 8); 
        if(GetWindowText(CA_MAX_LEN,buffer,4)) 
        {
             data.max_pathlen = atoi(buffer);                                
        }else{ data.max_pathlen = 0; } 
    }
    if(data.max_pathlen > 127){ data.max_pathlen=127; }
//set cert type
    type = 0;
 
    if(ISCHECKED(DIGITAL_SIGNATURE_TYPE)){ type |= MBEDTLS_X509_KU_DIGITAL_SIGNATURE; }
    if(ISCHECKED(NON_REPUDIATION_TYPE))  { type |= MBEDTLS_X509_KU_NON_REPUDIATION;   }
    if(ISCHECKED(KEY_ENCIPHERMENT_TYPE)) { type |= MBEDTLS_X509_KU_KEY_ENCIPHERMENT;  }
    if(ISCHECKED(DATA_ENCIPHERMENT_TYPE)){ type |= MBEDTLS_X509_KU_DATA_ENCIPHERMENT; }
    if(ISCHECKED(KEY_AGREEMENT_TYPE))    { type |= MBEDTLS_X509_KU_KEY_AGREEMENT;     }
    if(ISCHECKED(KEY_CERT_SIGN_TYPE))    { type |= MBEDTLS_X509_KU_KEY_CERT_SIGN;     }
    if(ISCHECKED(CRL_SIGN_TYPE))         { type |= MBEDTLS_X509_KU_CRL_SIGN;          }
    data.KeyUsage = type;
//digest algorithm
    memset(buffer, 0, 64);
    if(!GetWindowText(hDigest,buffer,64))
	{
         ErrorMsgHandle("BUG: Get Digest Selection",0);
         return;
    }
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_string((const char*)buffer);
    if (md_info == NULL)
	{
         ErrorMsgHandle("ERROR: mbedtls_md_info_from_string",0);
         return;
    }
    data.md = mbedtls_md_get_type(md_info);

    if(CreateSelfsignedCert(&data) == 0)
    {
       SetWindowText(hWnd,"OK");
    }
                  
}

LRESULT CALLBACK WindowProcedure (HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
 switch (message)                  /* handle the messages */
 {
   case WM_CREATE:
   { 
     hWnd = hwnd;
     InitCommonControls();
     hFont = CreateFont(15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "Comic Sans MS");
        
     FONT_SET(CreateWindow("BUTTON","Key Usage",WS_BOXCENTER,4,4,170,142,hwnd,0,ins,NULL));      
     FONT_SET(CreateWindow("BUTTON","Info",WS_BOXCENTER,180,4,188,92,hwnd,0,ins,NULL));      
     FONT_SET(CreateWindow("BUTTON","CA MaxPath",WS_BOXCENTER,180,100,88,57,hwnd,0,ins,NULL));      
     FONT_SET(CreateWindow("BUTTON","Algorithm",WS_CHILD|WS_VISIBLE|BS_GROUPBOX|BS_CENTER,277,100,90,50,hwnd,0,ins,NULL));
     FONT_SET(CreateWindow("STATIC","*NOTE: Most ROOT CA's use 2048 Bits RSA Key with SHA1 Algorithm",WS_CHILD|WS_VISIBLE,2,160,368,17,hwnd,0,ins,NULL));

     MAKETYPE(hwnd,DIGITAL_SIGNATURE,24);
     MAKETYPE(hwnd,NON_REPUDIATION,  41);
     MAKETYPE(hwnd,KEY_ENCIPHERMENT, 58);
     MAKETYPE(hwnd,DATA_ENCIPHERMENT,75);
     MAKETYPE(hwnd,KEY_AGREEMENT,    92);
     MAKETYPE(hwnd,KEY_CERT_SIGN,   109);
     MAKETYPE(hwnd,CRL_SIGN,        126);
     SETCHECKED(KEY_CERT_SIGN_TYPE);
     SETCHECKED(CRL_SIGN_TYPE);

     MAKEINFO(hwnd,CN,24,150,"myCA");  SendMessage(CN_INFO,EM_SETLIMITTEXT,(WPARAM)64,(LPARAM)0); 
     MAKEINFO(hwnd,O,41,150,"mbed TLS");  SendMessage(O_INFO,EM_SETLIMITTEXT,(WPARAM)64,(LPARAM)0); 
     MAKEINFO(hwnd,C,58,20,"UK");  SendMessage(C_INFO,EM_SETLIMITTEXT,(WPARAM)2,(LPARAM)0); 
     MAKEINFO(hwnd,OU,75,150,""); SendMessage(OU_INFO,EM_SETLIMITTEXT,(WPARAM)64,(LPARAM)0); 
     FONT_SET(CreateWindow("STATIC"," (Two Country Letters)",WS_CHILD|WS_VISIBLE,240,58,122,15,hwnd,0,ins,NULL));
     
     FONT_SET(CreateWindow("BUTTON","UnLimited",WSCHECKBOXCENTER,188,120,74,15,hwnd,(HMENU)ID_MX_CA_PATH,ins,NULL));
	 
     FONT_SET(CreateWindow("STATIC","MaxPath",WS_CHILD|WS_VISIBLE,188,137,45,15,hwnd,0,ins,NULL));
     CA_MAX_LEN=CreateWindow("EDIT","0",WS_CHILD|WS_VISIBLE|ES_NUMBER,235, 137,27, 15, hwnd, NULL,ins, NULL);  	
     FONT_SET(CA_MAX_LEN); 

     hDigest=CreateWindow("combobox", "",WS_CHILD|WS_VISIBLE |CBS_DROPDOWNLIST | WS_VSCROLL | WS_TABSTOP,284, 119, 77, 280, hwnd, NULL,ins, NULL);  	
     
     AddDigestAlgorith("MD2");
     AddDigestAlgorith("MD4");
     AddDigestAlgorith("MD5");
     AddDigestAlgorith("SHA1");
     AddDigestAlgorith("SHA224");
     AddDigestAlgorith("SHA256");
     AddDigestAlgorith("SHA384");
     AddDigestAlgorith("SHA512");
     COMBO_SET(hDigest,0);
     
     CenterOnScreen();
     DragAcceptFiles(hwnd,1);  
   }
   break;
   case WM_COMMAND:
        switch(LOWORD(wParam))
        {  
              case ID_MX_CA_PATH:
              {
                   if(ISCHECKED(GetDlgItem(hwnd,ID_MX_CA_PATH)))
                   {
                       EnableWindow(CA_MAX_LEN,FALSE);                  
                   }
                   else
                   {
                       EnableWindow(CA_MAX_LEN,TRUE);  
                   }
              }break;                               
         }
   break;
   case WM_DROPFILES:
   { 	
       UCHAR DropFile[MAX_PATH];
       UCHAR *p;
       memset(DropFile,0,MAX_PATH);
       memset(&data,0,sizeof(DATA));
  
       DragQueryFile((HDROP)wParam, 0, DropFile, MAX_PATH);
       DragFinish((HDROP) wParam);
	   if((GetFileAttributes(DropFile) & FILE_ATTRIBUTE_DIRECTORY)==FILE_ATTRIBUTE_DIRECTORY) //its a file
       {  
      	   MessageBox(NULL,"Drop a File not a Dir","ERROR", MB_ICONINFORMATION|MB_SYSTEMMODAL|MB_OK);
           break;
       }
       p=(UCHAR*)strrchr(DropFile,'.');
       if(p == NULL)
       {  
      	   MessageBox(NULL,"The File Must Have [ .key ] extention.","ERROR", MB_ICONINFORMATION|MB_SYSTEMMODAL|MB_OK);
           break;
       }
       p++;
       strcpy(data.KeyName,DropFile);
             
	   if(p[0] != 'k' && p[1] != 'e' && p[2] != 'y') //its not a key
       {  
      	     CreateThread(0,0,(LPTHREAD_START_ROUTINE)ReadCertificate,0,0,0);
             break;
       }
       *p++ = 'c';
       *p++ = 'r';
       *p   = 't';
       strcpy(data.CertName,DropFile);
       CreateThread(0,0,(LPTHREAD_START_ROUTINE)CreateCACertificate,0,0,0);	 
   }
   break;
   case WM_DESTROY:
            PostQuitMessage (0);
   break;
   default:  
      return DefWindowProc (hwnd, message, wParam, lParam);
    }
    return 0;
}


//------------------------------------------------------------------------------------------
int WINAPI WinMain (HINSTANCE _a_,HINSTANCE _b_,LPSTR _c_,int _d_)
{
    HWND hwnd;
    MSG messages;
    WNDCLASSEX wincl;
    ins = _a_;
    wincl.hInstance = _a_;
    wincl.lpszClassName = szClassName;
    wincl.lpfnWndProc = WindowProcedure;
    wincl.style = CS_DBLCLKS; 
    wincl.cbSize = sizeof (WNDCLASSEX);

    wincl.hIcon = LoadIcon (ins,MAKEINTRESOURCE(200));
    wincl.hIconSm = LoadIcon (ins,MAKEINTRESOURCE(200));
    wincl.hCursor = LoadCursor (NULL, IDC_ARROW);
    wincl.lpszMenuName = NULL;               
    wincl.cbClsExtra = 0;  
    wincl.cbWndExtra = 0;
    wincl.hbrBackground = (HBRUSH) COLOR_BACKGROUND;

    if (!RegisterClassEx (&wincl))
        return 0;

    hwnd = CreateWindowEx (0,szClassName,"SelfSigned CA",WS_OVERLAPPED|WS_SYSMENU, CW_USEDEFAULT,CW_USEDEFAULT,
           378,210,HWND_DESKTOP,NULL,_a_,NULL);

    ShowWindow (hwnd, _d_);
    while (GetMessage (&messages, NULL, 0, 0))
    {
        TranslateMessage(&messages);
        DispatchMessage(&messages);
    }
   return messages.wParam;
}

void CenterOnScreen()
{
     RECT rcClient, rcDesktop;
	 int nX, nY;
     SystemParametersInfo(SPI_GETWORKAREA, 0, &rcDesktop, 0);
     GetWindowRect(hWnd, &rcClient);
     nX=((rcDesktop.right - rcDesktop.left) / 2) -((rcClient.right - rcClient.left) / 2);
     nY=((rcDesktop.bottom - rcDesktop.top) / 2) -((rcClient.bottom - rcClient.top) / 2);
     SetWindowPos(hWnd, NULL, nX, nY, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
     SetWindowPos(hWnd, HWND_TOPMOST,0,0,0,0, SWP_NOACTIVATE | SWP_NOSIZE | SWP_NOMOVE);						
  return;
}
//############################## read certificate ###################

//----------------------- info -------------------------------------
int getCertSubjectInfo(UCHAR *buffer)
{
    UCHAR *cn,*o,*c,*ou,*p;

    cn=strstr(buffer,"CN=");
    if(!cn)
    {
        ErrorMsgHandle("ERROR: Can't find CommonName!!",0);
        return (-1);
    }
    o=strstr(buffer,"O=");
    c=strstr(buffer,"C=");
    ou=strstr(buffer,"OU=");
    p=buffer;
    p=strchr(p,',');
    while(p){*p=0; p=strchr(p+1,','); }
    SetWindowText(CN_INFO,cn+3);
    if(o){ SetWindowText(O_INFO,o+2); }else{ SetWindowText(O_INFO,""); }
    if(c){ SetWindowText(C_INFO,c+2); }else{ SetWindowText(C_INFO,""); }
    if(ou){ SetWindowText(OU_INFO,ou+3); }else{ SetWindowText(OU_INFO,""); }
  
   return 0;
}
//----------------------------------------------------------------------
#define KEY_USAGE(code,_n_)    \
    if( crt->key_usage & (code) ){ SETCHECKED(_n_##_TYPE);}else{ SETUNCHECKED(_n_##_TYPE); }


int mbedtls_x509_crt_infoA(const mbedtls_x509_crt *crt )
{
    UCHAR buffer[1024];
    int ret;
   
    memset(buffer,0,1024);
    ret = mbedtls_x509_dn_gets(buffer, 1024, &crt->subject);
    if(ret < 0 )
    {
        ErrorMsgHandle("ERROR: mbedtls_x509_dn_gets",ret);
      return ret;
    }
    ret = getCertSubjectInfo(buffer);
    if(ret != 0)
      return ret;
    memset(buffer,0,1024);
    ret = mbedtls_x509_sig_alg_gets((char *)buffer, 1024,&crt->sig_oid,0, 0,NULL);
    sprintf(&buffer[ret], " - KEY[ %s: %d bits ] %s\0",mbedtls_pk_get_name( &crt->pk ),
                               (int) mbedtls_pk_get_bitlen( &crt->pk ),
                               crt->ca_istrue?"isCA":"isNotCA" );
    SetWindowText(hWnd,buffer);
    
    //key type
    KEY_USAGE( MBEDTLS_X509_KU_DIGITAL_SIGNATURE, DIGITAL_SIGNATURE);
    KEY_USAGE( MBEDTLS_X509_KU_NON_REPUDIATION,   NON_REPUDIATION );
    KEY_USAGE( MBEDTLS_X509_KU_KEY_ENCIPHERMENT,  KEY_ENCIPHERMENT );
    KEY_USAGE( MBEDTLS_X509_KU_DATA_ENCIPHERMENT, DATA_ENCIPHERMENT );
    KEY_USAGE( MBEDTLS_X509_KU_KEY_AGREEMENT,     KEY_AGREEMENT );
    KEY_USAGE( MBEDTLS_X509_KU_KEY_CERT_SIGN,     KEY_CERT_SIGN );
    KEY_USAGE( MBEDTLS_X509_KU_CRL_SIGN,          CRL_SIGN);
    if(!crt->ca_istrue)
    {
       EnableWindow(CA_MAX_LEN,TRUE);
       SETUNCHECKED(GetDlgItem(hWnd,ID_MX_CA_PATH)); 
       SetWindowText(CA_MAX_LEN,"");
      return 0;                
    }
    ret = crt->max_pathlen-1;
    if(ret == -1)
    {
          EnableWindow(CA_MAX_LEN,FALSE);  
          SETCHECKED(GetDlgItem(hWnd,ID_MX_CA_PATH));          
    }
    else
    {
        EnableWindow(CA_MAX_LEN,TRUE);  
        SETUNCHECKED(GetDlgItem(hWnd,ID_MX_CA_PATH)); 
        sprintf(buffer,"%i\0",ret);
        SetWindowText(CA_MAX_LEN,buffer);
    }
  return 0;
}

void ReadCertificate()
{
    int ret;
    mbedtls_x509_crt crt; 
     
    mbedtls_x509_crt_init( &crt ); 
     
    ret = mbedtls_x509_crt_parse_file( &crt,data.KeyName);
    if(ret != 0 )
    {
        ErrorMsgHandle("ERROR: mbedtls_x509_crt_parse_file",ret);
        mbedtls_x509_crt_free( &crt ); 
      return;
    }
    if(crt.version != 3)
    {
        ErrorMsgHandle("INFO: Certificate Version must be V3.",ret);
        mbedtls_x509_crt_free( &crt ); 
      return;
    }
    mbedtls_x509_crt_infoA(&crt);
    mbedtls_x509_crt_free( &crt );                   
}

