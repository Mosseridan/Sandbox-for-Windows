#include "token_utils.h"
#include "job_and_desktop_utils.h"
#include "ipc_utils.h"

int _tmain(int argc, TCHAR *argv[]);

DWORD SpawnTarget(
	__in PHANDLE lockdown_token,
	__in PHANDLE initial_token,
	__in PHANDLE job_handle,
	__in HDESK* target_desktop,
	__in IPC* ipc,
	__in TCHAR* command_line,
	__in TCHAR* allowed_folder,
	__out PPROCESS_INFORMATION process_info);

DWORD CreateAllowedFolder(TCHAR* DirectoryName);


// Specify white list of handles to inherit 
// taken from https://blogs.msdn.microsoft.com/oldnewthing/20111216-00/?p=8873-f
BOOL CreateProcessAsUserWithExplicitHandles(
	__in		 HANDLE hToken,
	__in_opt     LPCTSTR lpApplicationName,
	__inout_opt  LPTSTR lpCommandLine,
	__in_opt     LPSECURITY_ATTRIBUTES lpProcessAttributes,
	__in_opt     LPSECURITY_ATTRIBUTES lpThreadAttributes,
	__in         BOOL bInheritHandles,
	__in         DWORD dwCreationFlags,
	__in_opt     LPVOID lpEnvironment,
	__in_opt     LPCTSTR lpCurrentDirectory,
	__in         LPSTARTUPINFO lpStartupInfo,
	__out        LPPROCESS_INFORMATION lpProcessInformation,
	__in         DWORD numOfHandlesToInherit,
	__in_ecount(cHandlesToInherit) HANDLE *rgHandlesToInherit);
