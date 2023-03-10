#include "nprobe.h"

#include <windows.h>
#include <winsock2.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <stdarg.h>
#include <tchar.h>


char thisIsAservice;

/*
  See also:
  http://www.muukka.net/programming/service.html
  http://www.mailbag.com/users/pengel/index.html
*/


/* *************************************************************

   Windown NT/2K Service Registration Routines

   Copyright 2001 by Bill Giel/KC Multimedia and Design Group, Inc.

   ************************************************************* */


#ifdef __cplusplus
extern "C" {
#endif


  //
  //  FUNCTION: convertArgStringToArgList()
  //
  //  PURPOSE: Return an array of strings containing all arguments that
  //           are parsed from a tab-delimited argument string.
  //
  //  PARAMETERS:
  //    args  - The string array address to be allocated and receive the data
  //    len - pointer to an int that will contain the returned array length
  //    argstring - string containing arguments to be parsed.
  //
  //  RETURN VALUE:
  //    String array address containing the filtered arguments
  //    NULL on failure
  //
  LPTSTR* convertArgStringToArgList(LPTSTR *args, PDWORD pdwLen, LPTSTR lpszArgstring);

  //
  //  FUNCTION: convertArgListToArgString()
  //
  //  PURPOSE: Create a single tab-delimited string of arguments from
  //           an argument list
  //
  //  PARAMETERS:
  //    target - pointer to the string to be allocated and created
  //    start  - zero-based offest into the list to the first arg value used to
  //             build the list.
  //    argc - length of the argument list
  //    argv - array of strings, the argument list.
  //
  //  RETURN VALUE:
  //    Character pointer to the target string.
  //    NULL on failure
  //
  LPTSTR convertArgListToArgString(LPTSTR lpszTarget, DWORD dwStart, DWORD dwArgc, LPTSTR *lpszArgv);

#ifdef __cplusplus
}
#endif




#ifdef __cplusplus
extern "C" {
#endif

  //
  //  FUNCTION: getStringValue()
  //
  //  PURPOSE: Fetches a REG_SZ or REG_EXPAND_SZ string value
  //           from a specified registry key
  //
  //  PARAMETERS:
  //    lpVal - a string buffer for the desired value
  //    lpcbLen  - pointer to LONG value with buffer length
  //    hkRoot - the primary root key, e.g. HKEY_LOCAL_MACHINE
  //    lpszPath - the registry path to the subkey containing th desired value
  //    lpszValue - the name of the desired value
  //
  //  RETURN VALUE:
  //    0 on success, 1 on failure
  //
  int getStringValue(LPBYTE lpVal, LPDWORD lpcbLen, HKEY hkRoot, LPCTSTR lpszPath, LPTSTR lpszValue);

  //
  //  FUNCTION: setStringValue()
  //
  //  PURPOSE: Assigns a REG_SZ value to a
  //           specified registry key
  //
  //  PARAMETERS:
  //    lpVal - Constant byte array containing the value
  //    cbLen  - data length
  //    hkRoot - the primary root key, e.g. HKEY_LOCAL_MACHINE
  //    lpszPath - the registry path to the subkey containing th desired value
  //    lpszValue - the name of the desired value
  //
  //  RETURN VALUE:
  //    0 on success, 1 on failure
  //
  int setStringValue(CONST BYTE *lpVal, DWORD cbLen, HKEY hkRoot, LPCTSTR lpszPath, LPCTSTR lpszValue);


  //
  //  FUNCTION: makeNewKey()
  //
  //  PURPOSE: Creates a new key at the specified path
  //
  //  PARAMETERS:
  //    hkRoot - the primary root key, e.g. HKEY_LOCAL_MACHINE
  //    lpszPath - the registry path to the new subkey
  //
  //  RETURN VALUE:
  //    0 on success, 1 on failure
  //
  int makeNewKey(HKEY hkRoot, LPCTSTR lpszPath);

  int setDwordValue(DWORD data, HKEY hkRoot, LPCTSTR lpszPath, LPCTSTR lpszValue);

#ifdef __cplusplus
}
#endif



#ifdef __cplusplus
extern "C" {
#endif

  // =========================================================
  // TO DO: change as needed for specific Java app and service
  // =========================================================

  // internal name of the service
#define SZSERVICENAME        "nProbe"

  // displayed name of the service
#define SZSERVICEDISPLAYNAME "nProbe for Win32"

  // Service TYPE Permissable values:
  //		SERVICE_AUTO_START
  //		SERVICE_DEMAND_START
  //		SERVICE_DISABLED
#define SERVICESTARTTYPE SERVICE_AUTO_START


  // =========================================================
  // You should not need any changes below this line
  // =========================================================

  // Value name for app parameters
#define SZAPPPARAMS "AppParameters"

  // list of service dependencies - "dep1\0dep2\0\0"
  // If none, use ""
#define SZDEPENDENCIES ""

  //
  //  FUNCTION: getConsoleMode()
  //
  //  PURPOSE: Is the app running as a service or a console app.
  //
  //  RETURN VALUE:
  //    TRUE  - if running as a console application
  //    FALSE - if running as a service
  //
  BOOL getConsoleMode();

  //
  //  FUNCTION: ReportStatusToSCMgr()
  //
  //  PURPOSE: Sets the current status of the service and
  //           reports it to the Service Control Manager
  //
  //  PARAMETERS:
  //    dwCurrentState - the state of the service
  //    dwWin32ExitCode - error code to report
  //    dwWaitHint - worst case estimate to next checkpoint
  //
  //  RETURN VALUE:
  //    TRUE  - success
  //    FALSE - failure
  //
  BOOL ReportStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint);


  //
  //  FUNCTION: AddToMessageLog(LPTSTR lpszMsg)
  //
  //  PURPOSE: Allows any thread to log an error message
  //
  //  PARAMETERS:
  //    lpszMsg - text for message
  //
  //  RETURN VALUE:
  //    none
  //
  void AddToMessageLog(LPTSTR lpszMsg);

  VOID ServiceStart(DWORD dwArgc, LPTSTR *lpszArgv);
  VOID ServiceStop();

#ifdef __cplusplus
}
#endif

//
//  Values are 32 bit values layed out as follows:
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//  +---+-+-+-----------------------+-------------------------------+
//  |Sev|C|R|     Facility          |               Code            |
//  +---+-+-+-----------------------+-------------------------------+
//
//  where
//
//      Sev - is the severity code
//
//          00 - Success
//          01 - Informational
//          10 - Warning
//          11 - Error
//
//      C - is the Customer code flag
//
//      R - is a reserved bit
//
//      Facility - is the facility code
//
//      Code - is the facility's status code
//
//
// Define the facility codes
//


//
// Define the severity codes
//


//
// MessageId: EVENT_GENERIC_INFORMATION
//
// MessageText:
//
//  %1
//
#define EVENT_GENERIC_INFORMATION        0x40000001L

//global variables
SERVICE_STATUS          ssStatus;
SERVICE_STATUS_HANDLE   sshStatusHandle;
DWORD                   dwErr = 0;
BOOL                    bConsole = FALSE;
TCHAR                   szErr[256];


#define SZFAILURE "StartServiceControlDispatcher failed!"
#define SZSCMGRFAILURE "OpenSCManager failed - %s\n"


int getStringValue(LPBYTE lpVal, LPDWORD lpcbLen, HKEY hkRoot, LPCTSTR lpszPath, LPTSTR lpszValue)
{

  LONG result;
  HKEY hKey;

  DWORD dwType;

  result = RegOpenKeyEx(
			hkRoot,
			lpszPath,
			(DWORD)0,
			KEY_EXECUTE | KEY_QUERY_VALUE,
			(PHKEY)&hKey);

  if(result != ERROR_SUCCESS){
    return 1;
  }

  result = RegQueryValueEx(
			   hKey,
			   lpszValue,
			   NULL,
			   (LPDWORD)&dwType,
			   lpVal,
			   lpcbLen);

  RegCloseKey(hKey);

  return !(result == ERROR_SUCCESS &&
	   (dwType == REG_SZ || dwType == REG_EXPAND_SZ));
}

int setStringValue(CONST BYTE *lpVal, DWORD cbLen, HKEY hkRoot, LPCTSTR lpszPath, LPCTSTR lpszValue)
{

  LONG result;
  HKEY hKey;

  DWORD dwType = REG_SZ;

  result = RegOpenKeyEx(
			hkRoot,
			lpszPath,
			(DWORD)0,
			KEY_WRITE,
			(PHKEY)&hKey);

  if(result != ERROR_SUCCESS){
    return 1;
  }

  result = RegSetValueEx(
			 hKey,
			 lpszValue,
			 (DWORD)0,
			 dwType,
			 lpVal,
			 cbLen);

  RegCloseKey(hKey);

  return !(result == ERROR_SUCCESS);
}

int makeNewKey(HKEY hkRoot, LPCTSTR lpszPath)
{
  char *classname = "LocalSystem";

  LONG result;
  HKEY hKey;
  DWORD disposition;


  result = RegCreateKeyEx(
			  hkRoot,
			  lpszPath,
			  (DWORD)0,
			  classname,
			  REG_OPTION_NON_VOLATILE,
			  KEY_ALL_ACCESS,
			  NULL,
			  (PHKEY)&hKey,
			  (LPDWORD) &disposition);

  if(result != ERROR_SUCCESS){
    return 1;
  }


  RegCloseKey(hKey);

  return !(result == ERROR_SUCCESS);
}


int setDwordValue(DWORD data, HKEY hkRoot, LPCTSTR lpszPath, LPCTSTR lpszValue)
{

  LONG	result;
  HKEY	hKey;

  result = RegOpenKeyEx(hkRoot, lpszPath, (DWORD) 0, KEY_WRITE, (PHKEY) & hKey);

  if(result != ERROR_SUCCESS)
    {
      return 1;
    }

  result = RegSetValueEx(
			 hKey,
			 lpszValue,
			 0,
			 REG_DWORD,
			 (CONST BYTE*)&data,
			 sizeof(DWORD));

  RegCloseKey(hKey);

  return !(result == ERROR_SUCCESS);
}


BOOL getConsoleMode()
{
  return bConsole;
}

// Create an error message from GetLastError() using the
// FormatMessage API Call...
LPTSTR GetLastErrorText( LPTSTR lpszBuf, DWORD dwSize )
{
  DWORD dwRet;
  LPTSTR lpszTemp = NULL;



  dwRet = FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER |
			 FORMAT_MESSAGE_FROM_SYSTEM |FORMAT_MESSAGE_ARGUMENT_ARRAY,
			 NULL,
			 GetLastError(),
			 LANG_NEUTRAL,
			 (LPTSTR)&lpszTemp,
			 0,
			 NULL);

  // supplied buffer is not long enough
  if (!dwRet || ((long)dwSize < (long)dwRet+14)){
    lpszBuf[0] = TEXT('\0');
  }
  else{
    lpszTemp[lstrlen(lpszTemp)-2] = TEXT('\0');  //remove cr and newline character
    _stprintf( lpszBuf, TEXT("%s (0x%x)"), lpszTemp, GetLastError());
  }

  if (lpszTemp){
    GlobalFree((HGLOBAL) lpszTemp);
  }

  return lpszBuf;
}


// We'll try to install the service with this function, and save any
// runtime args for the service itself as a REG_SZ value in a registry
// subkey

void installService(char *service_name, int argc, char **argv)
{
  SC_HANDLE   schService;
  SC_HANDLE   schSCManager;
  TCHAR szPath[512], szDescr[256];
  TCHAR szAppParameters[8192];
  SERVICE_DESCRIPTION sdBuf;
  char szParamKey[1025], szParamKey2[1025];

#if 0
  thisIsAservice = 1; bConsole = 0;
  if(argc >=1) traceEvent(TRACE_ERROR, "argv[1] = %s", argv[1]);
  if(argc >=2) traceEvent(TRACE_ERROR, "argv[2] = %s", argv[2]);
  if(argc >=3) traceEvent(TRACE_ERROR, "argv[3] = %s", argv[3]);
#endif

  sprintf(szParamKey, "SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters", service_name);

  // Get the full path and filename of this program
  if ( GetModuleFileName( NULL, szPath, 512 ) == 0 ){
    _tprintf(TEXT("Unable to install %s - %s\n"), TEXT(service_name),
	     GetLastErrorText(szErr, 256));
    return;
  }

  // Next, get a handle to the service control manager
  schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

  if ( schSCManager ) {

    schService = CreateService(schSCManager,   // SCManager database
			       TEXT(service_name),        // name of service
			       TEXT(service_name), // name to display
			       SERVICE_ALL_ACCESS,         // desired access
			       SERVICE_WIN32_OWN_PROCESS,  // service type
			       SERVICESTARTTYPE,           // start type
			       SERVICE_ERROR_NORMAL,       // error control type
			       szPath,                     // service's binary
			       NULL,                       // no load ordering group
			       NULL,                       // no tag identifier
			       TEXT(SZDEPENDENCIES),       // dependencies
			       NULL,                       // LocalSystem account
			       NULL);                      // no password

    if (schService){
      _tprintf(TEXT("%s installed.\n"), TEXT(service_name) );

      //Create an argument string from the argument list
      // J. R. Duarte: modified it to store the full command line
      convertArgListToArgString((LPTSTR) szAppParameters, 0, argc, argv);

      /* Modify the service description string */
      if(szAppParameters != NULL) {
	sdBuf.lpDescription = szAppParameters;

	if( !ChangeServiceConfig2(
				  schService,                 // handle to service
				  SERVICE_CONFIG_DESCRIPTION, // change: description
				  &sdBuf) )                   // value: new description
	  {
	    ; /* Failed */
	  }
      }

      // Close the handle to this service object
      CloseServiceHandle(schService);

      /* ****************************************** */
      // Set the service name. Courtesy of Yuri Francalacci <yuri@ntop.org>
      sprintf(szParamKey2, "SYSTEM\\CurrentControlSet\\Services\\%s",service_name);
      snprintf(szDescr, sizeof(szDescr), "nProbe v.%s - NetFlow/IPFIX Probe. http://www.ntop.org/",
	       version);

      // Set the file value (where the message resources are located.... in this case, our runfile.)
      if(0 != setStringValue((const unsigned char *)szDescr,
			     strlen(szDescr) + 1,HKEY_LOCAL_MACHINE, szParamKey2,TEXT("Description")))
	{
	  _tprintf(TEXT("Unable to set service description .\n"));
	}
      /* ********************************************** */



      //Make a registry key to support logging messages using the service name.
      sprintf(szParamKey2, "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\%s", service_name);
      if(0 != makeNewKey(HKEY_LOCAL_MACHINE, szParamKey2)){
	_tprintf(TEXT("The EventLog subkey could not be created.\n"));
      }

      // Set the file value (where the message resources are located.... in this case, our runfile.)
      if(0 != setStringValue((const unsigned char *) szPath,
			     strlen(szPath) + 1,HKEY_LOCAL_MACHINE,
			     szParamKey2,TEXT("EventMessageFile")))
	{
	  _tprintf(TEXT("The Message File value could\nnot be assigned.\n"));
	}

      // Set the supported types flags.
      if(0 != setDwordValue(EVENTLOG_INFORMATION_TYPE,HKEY_LOCAL_MACHINE, szParamKey2,TEXT("TypesSupported"))){
	_tprintf(TEXT("The Types Supported value could\nnot be assigned.\n"));
      }

      // Try to create a subkey to hold the runtime args for the JavaVM and
      // Java application
      if(0 != makeNewKey(HKEY_LOCAL_MACHINE, szParamKey)){
	_tprintf(TEXT("Could not create Parameters subkey.\n"));
      } else {
	if(NULL == szAppParameters){
	  _tprintf(TEXT("Could not create AppParameters string.\n"));
	} else{
	  // Try to save the argument string under the new subkey
	  if(0 != setStringValue(szAppParameters, strlen(szAppParameters)+1,
				 HKEY_LOCAL_MACHINE, szParamKey, SZAPPPARAMS)){
	    _tprintf(TEXT("Could not save AppParameters value.\n"));
	  }
	}
      }
    }
    else{
      _tprintf(TEXT("CreateService failed - %s\n"), GetLastErrorText(szErr, 256));
    }

    // Close the handle to the service control manager database
    CloseServiceHandle(schSCManager);
  }
  else{
    _tprintf(TEXT(SZSCMGRFAILURE), GetLastErrorText(szErr,256));
  }
}


// We'll try to stop, and then remove the service using this function.
void removeService(char *service_name)
{
  SC_HANDLE   schService;
  SC_HANDLE   schSCManager;
  char szParamKey2[1025];


  // First, get a handle to the service control manager
  schSCManager = OpenSCManager(NULL,
			       NULL,
			       SC_MANAGER_ALL_ACCESS);
  if (schSCManager){

    // Next get the handle to this service...
    schService = OpenService(schSCManager, TEXT(service_name), SERVICE_ALL_ACCESS);

    if (schService){
      // Now, try to stop the service by passing a STOP code thru the control manager
      if (ControlService( schService, SERVICE_CONTROL_STOP, &ssStatus)){

	_tprintf(TEXT("Stopping %s."), TEXT(service_name));
	// Wait a second...
	Sleep( 1000 );

	// Poll the status of the service for SERVICE_STOP_PENDING
	while(QueryServiceStatus( schService, &ssStatus)){

	  // If the service has not stopped, wait another second
	  if ( ssStatus.dwCurrentState == SERVICE_STOP_PENDING ){
	    _tprintf(TEXT("."));
	    Sleep( 1000 );
	  }
	  else
	    break;
	}

	if ( ssStatus.dwCurrentState == SERVICE_STOPPED )
	  _tprintf(TEXT("\n%s stopped.\n"), TEXT(service_name) );
	else
	  _tprintf(TEXT("\n%s failed to stop.\n"), TEXT(service_name) );
      }

      // Now try to remove the service...
      if(DeleteService(schService)){
	_tprintf(TEXT("%s removed.\n"), TEXT(service_name) );

	// Delete our eventlog registry key
	sprintf(szParamKey2, "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\%s", service_name);
	RegDeleteKey(HKEY_LOCAL_MACHINE,szParamKey2);
      }else{
	_tprintf(TEXT("DeleteService failed - %s\n"), GetLastErrorText(szErr,256));
      }

      //Close this service object's handle to the service control manager
      CloseServiceHandle(schService);
    }
    else{
      _tprintf(TEXT("OpenService failed - %s\n"), GetLastErrorText(szErr,256));
    }

    // Finally, close the handle to the service control manager's database
    CloseServiceHandle(schSCManager);


  }
  else{
    _tprintf(TEXT(SZSCMGRFAILURE), GetLastErrorText(szErr,256));
  }
}

/* ********************************************* */

extern int nprobe_main(int argc, char *argv[]);
extern void usage (FILE * fd);

DWORD _dwArgc;
LPTSTR *_lpszArgv;
HANDLE  hServerStopEvent = NULL;


void* invokenProbe(LPTSTR szAppParameters) {
  DWORD dwNewArgc, i;
  LPTSTR *lpszNewArgv = NULL;
  LPTSTR *lpszTmpArgv;


  // SetConsoleCtrlHandler(logoffHandler, TRUE);

  // J. R. Duarte: convert the string argument back to argc & argv
  lpszNewArgv = convertArgStringToArgList(lpszNewArgv, &dwNewArgc, szAppParameters);

  // J. R. Duarte: to handle removing the Windows-specific command
  // line option when running from the command line or as a service

  if (!stricmp(lpszNewArgv[1],"/c") || !stricmp(lpszNewArgv[1],"/i")  || !stricmp(lpszNewArgv[1],"/r"))
    {
      int displ;
      lpszTmpArgv = lpszNewArgv;		// make a copy of argv

      if(!stricmp(lpszNewArgv[1],"/c")) displ = 1; else displ = 2;

      for(i=0; i < dwNewArgc ;i++)	{
	if (i == 0)
	  lpszNewArgv[0] = lpszTmpArgv[0];
	else if (i > displ)
	  lpszNewArgv[i - displ] = lpszTmpArgv[i];
      }

      dwNewArgc--;
    }

  nprobe_main(dwNewArgc, lpszNewArgv);
  SetEvent(hServerStopEvent); // Signal main thread that we're leaving
  return(NULL);
}

// This method is called from ServiceMain() when NT starts the service
// or by runService() if run from the console.

VOID ServiceStart (DWORD dwArgc, LPTSTR *lpszArgv)
{
  HANDLE nProbeThread;
  TCHAR szAppParameters[8192];

  // Let the service control manager know that the service is
  // initializing.
  if (!ReportStatus(SERVICE_START_PENDING,
		    NO_ERROR,
		    3000))
    //goto cleanup;
    return;


  // Create a Stop Event
  hServerStopEvent = CreateEvent(
				 NULL,
				 TRUE,
				 FALSE,
				 NULL);


  if ( hServerStopEvent == NULL)
    goto cleanup;

  if(dwArgc > 0)
    _dwArgc = dwArgc, _lpszArgv = lpszArgv;
  else {
    char *progName = SZSERVICENAME;
    _dwArgc = 1, _lpszArgv = &progName;
  }

  if (!ReportStatus(SERVICE_RUNNING,NO_ERROR,0)){
    goto cleanup;
  }

  // createThread(&nProbeThread, invokenProbe, NULL);
  // J. R. Duarte: Create an argument string from the argument list
  convertArgListToArgString((LPTSTR) szAppParameters,0, dwArgc, lpszArgv);
  if(NULL == szAppParameters){
    _tprintf(TEXT("Could not create AppParameters string.\n"));
  }
  pthread_create(&nProbeThread, NULL, invokenProbe, szAppParameters);

  // Wait for the stop event to be signalled.
  WaitForSingleObject(hServerStopEvent,INFINITE);

 cleanup:
  if (hServerStopEvent)
    CloseHandle(hServerStopEvent);
}

/* ********************************************* */

VOID ServiceStop() {
  SetEvent(hServerStopEvent);
}

/* ************************************ */

// This function permits running the application from the
// console.

void runService(int argc, char ** argv)
{
  DWORD dwArgc;
  LPTSTR *lpszArgv;

#ifdef UNICODE
  lpszArgv = CommandLineToArgvW(GetCommandLineW(), &(dwArgc) );
#else
  dwArgc   = (DWORD) argc;
  lpszArgv = argv;
#endif

  _tprintf(TEXT("Running %s.\n"), TEXT(SZSERVICEDISPLAYNAME));

  ServiceStart( dwArgc, lpszArgv);
}

/* ************************************ */

// If running as a service, use event logging to post a message
// If not, display the message on the console.

VOID AddToMessageLog(LPTSTR lpszMsg)
{
  HANDLE  hEventSource;
  TCHAR	szMsg[4096];

#ifdef UNICODE
  LPCWSTR  lpszStrings[1];
#else
  LPCSTR   lpszStrings[1];
#endif

  if(!isWinNT()) {
    char *msg = (char*)lpszMsg;
    printf("%s", msg);
    if(msg[strlen(msg)-1] != '\n')
      printf("\n");
    return;
  }

  if (!bConsole)
    {
      hEventSource = RegisterEventSource(NULL, TEXT(SZSERVICENAME));

      _stprintf(szMsg, TEXT("%s: %s"), SZSERVICENAME, lpszMsg);

      lpszStrings[0] = szMsg;

      if (hEventSource != NULL) {
	ReportEvent(hEventSource,
		    EVENTLOG_INFORMATION_TYPE,
		    0,
		    EVENT_GENERIC_INFORMATION,
		    NULL,
		    1,
		    0,
		    lpszStrings,
		    NULL);

	DeregisterEventSource(hEventSource);
      }
    } else {
    _tprintf(TEXT("%s\n"), lpszMsg);
  }
}

/* ************************************ */

// Throughout the program, calls to SetServiceStatus are required
// which are handled by calling this function. Here, the non-constant
// members of the SERVICE_STATUS struct are assigned and SetServiceStatus
// is called with the struct. Note that we will not report to the service
// control manager if we are running as  console application.

BOOL ReportStatus(DWORD dwCurrentState,
		  DWORD dwWin32ExitCode,
		  DWORD dwWaitHint)
{
  static DWORD dwCheckPoint = 1;
  BOOL bResult = TRUE;


  if ( !bConsole )
    {
      if (dwCurrentState == SERVICE_START_PENDING)
	ssStatus.dwControlsAccepted = 0;
      else
	ssStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;

      ssStatus.dwCurrentState = dwCurrentState;
      ssStatus.dwWin32ExitCode = dwWin32ExitCode;
      ssStatus.dwWaitHint = dwWaitHint;

      if ( ( dwCurrentState == SERVICE_RUNNING ) ||
	   ( dwCurrentState == SERVICE_STOPPED ) )
	ssStatus.dwCheckPoint = 0;
      else
	ssStatus.dwCheckPoint = dwCheckPoint++;

      if (!(bResult = SetServiceStatus( sshStatusHandle, &ssStatus))) {
	AddToMessageLog(TEXT("SetServiceStatus"));
      }
    }

  return bResult;
}

/* ************************************ */

// Each Win32 service must have a control handler to respond to
// control requests from the dispatcher.

VOID WINAPI controlHandler(DWORD dwCtrlCode)
{

  switch(dwCtrlCode)
    {
    case SERVICE_CONTROL_SHUTDOWN:
    case SERVICE_CONTROL_STOP:
      // Request to stop the service. Report SERVICE_STOP_PENDING
      // to the service control manager before calling ServiceStop()
      // to avoid a "Service did not respond" error.
      ReportStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);
      ServiceStop();
      return;


    case SERVICE_CONTROL_INTERROGATE:
      // This case MUST be processed, even though we are not
      // obligated to do anything substantial in the process.
      break;

    default:
      // Any other cases...
      break;

    }

  // After invocation of this function, we MUST call the SetServiceStatus
  // function, which is accomplished through our ReportStatus function. We
  // must do this even if the current status has not changed.
  ReportStatus(ssStatus.dwCurrentState, NO_ERROR, 0);
}

/* ************************************ */

// The ServiceMain function is the entry point for the service.
void WINAPI serviceMain(DWORD dwArgc, LPTSTR *lpszArgv)
{
  TCHAR szAppParameters[8192];
  LONG lLen = 8192;
  LPTSTR *lpszNewArgv = NULL;
  DWORD dwNewArgc;
  UINT i;
  char szParamKey[1025];

  sprintf(szParamKey,"SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters", lpszArgv[0]);
  // Call RegisterServiceCtrlHandler immediately to register a service control
  // handler function. The returned SERVICE_STATUS_HANDLE is saved with global
  // scope, and used as a service id in calls to SetServiceStatus.
  sshStatusHandle = RegisterServiceCtrlHandler( TEXT(SZSERVICENAME), controlHandler);
  if (!sshStatusHandle)
    goto finally;

  // The global ssStatus SERVICE_STATUS structure contains information about the
  // service, and is used throughout the program in calls made to SetStatus through
  // the ReportStatus function.
  ssStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  ssStatus.dwServiceSpecificExitCode = 0;

  // If we could guarantee that all initialization would occur in less than one
  // second, we would not have to report our status to the service control manager.
  // For good measure, we will assign SERVICE_START_PENDING to the current service
  // state and inform the service control manager through our ReportStatus function.
  if (!ReportStatus(SERVICE_START_PENDING, NO_ERROR, 3000))
    goto finally;
  // When we installed this service, we probably saved a list of runtime args
  // in the registry as a subkey of the key for this service. We'll try to get
  // it here...
  if(0 != getStringValue(szAppParameters,(LPDWORD)&lLen, HKEY_LOCAL_MACHINE, szParamKey, SZAPPPARAMS)){
    dwNewArgc = 0;
    lpszNewArgv = NULL;
  } else {
    //If we have an argument string, convert it to a list of argc/argv type...
    lpszNewArgv = convertArgStringToArgList(lpszNewArgv, &dwNewArgc, szAppParameters);
  }
  // Do it! In ServiceStart, we'll send additional status reports to the
  // service control manager, especially the SERVICE_RUNNING report once
  // our JVM is initiallized and ready to be invoked.
  ServiceStart(dwNewArgc, lpszNewArgv);

  // Release the allocated storage used by our arg list. Java programmers
  // might remember this kind of stuff.
  for(i=0; i<dwNewArgc; i++){
    GlobalFree((HGLOBAL)lpszNewArgv[i]);
  }
  if(dwNewArgc > 0)
    GlobalFree((HGLOBAL)lpszNewArgv);
 finally:
  // Report the stopped status to the service control manager, if we have
  // a valid server status handle.
  if (sshStatusHandle)
    (VOID)ReportStatus( SERVICE_STOPPED, dwErr, 0);
}

/* ************************************ */

void main(int argc, char **argv)
{
  // The StartServiceCtrlDispatcher requires this table to specify
  // the ServiceMain function to run in the calling process. The first
  // member in this example is actually ignored, since we will install
  // our service as a SERVICE_WIN32_OWN_PROCESS service type. The NULL
  // members of the last entry are necessary to indicate the end of
  // the table;
  SERVICE_TABLE_ENTRY serviceTable[] =
    {
      { TEXT(SZSERVICENAME), (LPSERVICE_MAIN_FUNCTION)serviceMain },
      { NULL, NULL }
    };

  TCHAR szAppParameters[8192];

  if(!isWinNT()) {
    convertArgListToArgString((LPTSTR) szAppParameters,0, argc, argv);
    if(NULL == szAppParameters){
      _tprintf(TEXT("Could not create AppParameters string.\n"));
    }
    invokenProbe(szAppParameters);
    return;
  }
  thisIsAservice = 0;

  // This app may be started with one of three arguments, /i, /r, and
  // /c, or /?, followed by actual program arguments. These arguments
  // indicate if the program is to be installed, removed, run as a
  // console application, or to display a usage message.
  if(argc > 1){
    char *service_name = "nProbe for Win32";

    if(!stricmp(argv[1],"/i")){
      if(argc >2)
	installService(argv[2], argc, argv);
      else
	_tprintf(TEXT("/i requires the service name as parameter\n"));
    }
    else if(!stricmp(argv[1],"/r")){
      if(argc >1)
	removeService(argv[2]);
      else
	_tprintf(TEXT("/r requires the service name as parameter\n"));
    }
    else if(!stricmp(argv[1],"/c")){
      bConsole = TRUE;
      runService(argc,argv);
    }
    else{
      if(stricmp(argv[1],"/h")) printf("\nUnrecognized option: %s\n", argv[1]);
      printf("Available options:\n");
      printf("/i <service name> [nprobe options] - Install nprobe as service\n");
      printf("/c [nprobe options]                - Run nprobe on a console\n");
      printf("/r <service name>                  - Deinstall the service\n\n");
      printf("Example:\n"
	     "Install nprobe as a service: 'nprobe /i my_nProbe -i 0 -n 192.168.0.1:2055'\n"
	     "Remove the nprobe service:   'nprobe /r my_nProbe'\n\n");
      printf("Notes:\n"
	     "1. Type 'nprobe /c -h' to see all options\n"
	     "1. In order to reinstall a service with new options\n"
	     "   it is necessary to first remove the service, then add it\n"
	     "   again with the new options.\n"
	     "2. Services are started/stopped using the Services\n"
	     "   control panel item.\n"
	     "3. You can install the nProbe service multiple times\n"
	     "   as long as you use different service names.\n\n");
    }
    exit(0);
  }
  thisIsAservice = 1;

  // If main is called without any arguments, it will probably be by the
  // service control manager, in which case StartServiceCtrlDispatcher
  // must be called here. A message will be printed just in case this
  // happens from the console.
  printf("\nNOTE:\nUnder your version of Windows, nprobe is started as a service.\n");
  printf("Please open the services control panel to start/stop nprobe,\n");
  printf("or type nprobe /h to see all the available options.\n");

  if(!StartServiceCtrlDispatcher(serviceTable)) {
    printf("\n%s\n", SZFAILURE);
    AddToMessageLog(TEXT(SZFAILURE));
  }
}

/* ************************************ */

LPTSTR *convertArgStringToArgList(LPTSTR *lpszArgs, PDWORD pdwLen,
				  LPTSTR lpszArgstring)
{
  UINT uCount;
  LPTSTR lpszArg, lpszToken;


  if(strlen(lpszArgstring) == 0){
    *pdwLen = 0;
    //lpszArgs = NULL;
    return NULL;
  }

  if(NULL == (lpszArg = (LPTSTR)GlobalAlloc(GMEM_FIXED,strlen(lpszArgstring)+1))){
    *pdwLen = 0;
    //lpszArgs = NULL;
    return NULL;
  }

  strcpy(lpszArg, lpszArgstring);

  lpszToken = strtok( lpszArg, "\t" );
  uCount = 0;
  while( lpszToken != NULL ){
    uCount++;
    lpszToken = strtok( NULL, "\t");
  }

  GlobalFree((HGLOBAL)lpszArg);

  lpszArgs = (LPTSTR *)GlobalAlloc(GMEM_FIXED,uCount * sizeof(LPTSTR));
  *pdwLen = uCount;

  lpszToken = strtok(lpszArgstring,"\t");
  uCount = 0;
  while(lpszToken != NULL){
    lpszArgs[uCount] = (LPTSTR)GlobalAlloc(GMEM_FIXED,strlen(lpszToken)+1);
    strcpy(lpszArgs[uCount],lpszToken);
    uCount++;
    lpszToken = strtok( NULL, "\t");
  }

  return lpszArgs;
}

/* ************************************ */

LPTSTR convertArgListToArgString(LPTSTR lpszTarget,
				 DWORD dwStart, DWORD dwArgc,
				 LPTSTR *lpszArgv)
{
  UINT i;

  if(dwStart >= dwArgc){
    return NULL;
  }

  *lpszTarget = 0;

  for(i=dwStart; i<dwArgc; i++){

    if(i != dwStart){
      strcat(lpszTarget,  "\t" /* " " */);
    }
    strcat(lpszTarget,lpszArgv[i]);
  }

  return lpszTarget;
}
