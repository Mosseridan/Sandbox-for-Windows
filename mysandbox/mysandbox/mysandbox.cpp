// mysandbox.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "mysandbox.h"

int _tmain(int argc, TCHAR *argv[]){

	DWORD result = 0, size = 0;
	TCHAR* command_line = NULL;
	TCHAR* allowed_folder = NULL;
	HWINSTA target_station;
	HDESK target_desktop;
	HANDLE job_handle = NULL;
	HANDLE effective_token = NULL;
	HANDLE lockdown_token = NULL;
	HANDLE initial_token = NULL;
	IPC* ipc;
	PROCESS_INFORMATION process_info;

	// parse command line.
	if (argc != 5 || _tcscmp(TEXT("-torun"), argv[1]) || _tcscmp(TEXT("-folder"), argv[3])) {
		fprintf(stderr, "Usage: -torun <TargetPath> -folder <AllowedFolderPath>\n");
		return -1;
	}

	command_line = argv[2];
	allowed_folder = argv[4];

	// create allowed folder this folder will be the targets current directory
	if ((result = CreateAllowedFolder(allowed_folder)) != 0)
		goto BAD;

	// create new station and desktop for the target process to run in 
	if ((result = createStationAndDesktop(&target_station, &target_desktop)) != 0)
		goto BAD;

	// Create Job object
	if ((result = CreateJob(&job_handle)) != 0)
		goto BAD;

	// Create IPC
	ipc = new IPC();
	if ((result = ipc->init()) != 0)
		goto BAD;

	// Obtain a handle to the current process's primary token
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &effective_token)){
		fprintf(stderr, "OpenProcessToken Error %u\n", GetLastError());
		goto BAD;
	}
	
	// Create the restricted token that will be used as the target process's primary token
	if ((result = CreateLockdownToken(&effective_token, &lockdown_token)) != 0)
		goto BAD;

	// Create a more "loose" token that will be used in the target process startup
	if ((result = CreateInitialToken(&effective_token, &initial_token)) != 0)
		goto BAD;

	if ((result = SpawnTarget(&lockdown_token, &initial_token, &job_handle, &target_desktop, ipc, command_line, allowed_folder, &process_info)) != 0)
		goto BAD;


	WaitForSingleObject(process_info.hProcess, INFINITE);

	if (process_info.hProcess)
		TerminateProcess(process_info.hProcess, 0);
	if (target_desktop)
		CloseDesktop(target_desktop);
	if (target_station)
		CloseWindowStation(target_station);
	if (job_handle)
		CloseHandle(job_handle);
	if (effective_token)
		CloseHandle(effective_token);
	if (lockdown_token)
		CloseHandle(lockdown_token);
	if (initial_token)
		CloseHandle(initial_token);
	if (allowed_folder)
		RemoveDirectory(allowed_folder);
	if (ipc)
		ipc->~IPC();
	return 0;
	
	BAD:
		fprintf(stderr, "Broken Main Error %u\n",result);
		if (process_info.hProcess)
			TerminateProcess(process_info.hProcess, 0);
		if (target_desktop)
			CloseDesktop(target_desktop);
		if (target_station)
			CloseWindowStation(target_station);
		if (job_handle)
			CloseHandle(job_handle);
		if (effective_token)
			CloseHandle(effective_token);
		if (lockdown_token)
			CloseHandle(lockdown_token);
		if (initial_token)
			CloseHandle(initial_token);
		if(allowed_folder)
			RemoveDirectory(allowed_folder);
		return result;
}



// Spawns a target process with lockdown_token as a primary token 
// and initial token as an impersonation token used for the process startup
// the target process is started suspended and is forced to call reverToSelf after startup (before main())
// thus reunning with the lockdown token
DWORD SpawnTarget(
	__in PHANDLE lockdown_token,
	__in PHANDLE initial_token,
	__in PHANDLE job_handle,
	__in HDESK* target_desktop,
	__in IPC* ipc,
	__in TCHAR* command_line,
	__in TCHAR* allowed_folder,
	__out PPROCESS_INFORMATION process_info) {

	DWORD result = 0, old_protection = 0, target_desktop_name_length = 0;
	HANDLE target_token = NULL;
	STARTUPINFO startup_info;
	WCHAR* target_desktop_name;
	CONTEXT context = { 0 };
	LPVOID entry_point = 0;
	BYTE first_two_bytes[2] = { 0 };
	SIZE_T size = 0;

	ZeroMemory(process_info, sizeof(PROCESS_INFORMATION));
	ZeroMemory(&startup_info, sizeof(STARTUPINFO));

	GetStartupInfo(&startup_info);

	// get the new desktops name length
	GetUserObjectInformation(
		*target_desktop,
		UOI_NAME,
		NULL,
		0,
		&target_desktop_name_length
	);

	// get the new desktops name
	target_desktop_name = new WCHAR[target_desktop_name_length];
	GetUserObjectInformation(
		*target_desktop,
		UOI_NAME,
		target_desktop_name,
		target_desktop_name_length,
		&target_desktop_name_length
	);

	//// set targets desktop
	startup_info.lpDesktop = target_desktop_name;

	// set targets standard in, out and error
	startup_info.hStdError = ipc->target_write;
	startup_info.hStdOutput = ipc->target_write;
	startup_info.hStdInput = ipc->target_read;
	startup_info.dwFlags |= STARTF_USESTDHANDLES;

	// select handles to inherit
	HANDLE* handles_to_inherit = new HANDLE[2];
	handles_to_inherit[0] = ipc->target_read;
	handles_to_inherit[1] = ipc->target_write;

	// create the target process suspended whithin the new station and desktop
	// and whith the lockdown token as a primary token
	if (!CreateProcessAsUserWithExplicitHandles(*lockdown_token, // the process token
		NULL,				// application path
		command_line,			// command line - 1st token is executable
		NULL,					// default security attirubtes on process
		NULL,					// default security attributes on thread
		TRUE,					// inherit handles from parent
		CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB,					// use normal priority class
		NULL,					// inherit environment from parent
		allowed_folder,				// use the current directory of parent
		&startup_info,					// pointer to the STARTUPINFO
		process_info,				// pointer to the PROCESSINFROMATION
		2,
		handles_to_inherit)) {
		fprintf(stderr, "CreateProcessAsUser Error %u\n", result = GetLastError());
		goto BAD;
	}

	// assign target to restricting job
	if (!AssignProcessToJobObject(*job_handle, process_info->hProcess)) {
		fprintf(stderr, "AssignProcessToJobObject Error %u\n", result = GetLastError());
		goto BAD;
	}

	// Set targets main thead Impersonation token to initial_token to allow proper process startup
	if (!(SetThreadToken(&process_info->hThread, *initial_token))) {
		fprintf(stderr, "SetThreadToken Error %u\n", result = GetLastError());
		goto BAD;
	}

	// Obtain target thread context
	context.ContextFlags = CONTEXT_ALL;
	if (!GetThreadContext(process_info->hThread, &context)) {
		fprintf(stderr, "GetThreadContext Error %u\n", result = GetLastError());
		goto BAD;
	}

	// Obtain target process's entry point which is the main threads eax on startup 
	entry_point = (LPVOID)context.Eax;

	// Changes the protection in target process memory in order to hook targets main
	if (!VirtualProtectEx(process_info->hProcess, entry_point, 2, PAGE_EXECUTE_READWRITE, &old_protection)) {
		fprintf(stderr, "VirtualProtectEx Error %u\n", result = GetLastError());
		goto BAD;
	}

	// Save first two bytes of op code from targets main
	if (!ReadProcessMemory(process_info->hProcess, entry_point, first_two_bytes, 2, &size)) {
		fprintf(stderr, "ReadProcessMemory Error %u\n", result = GetLastError());
		goto BAD;
	}

	// Change first two bytes of targets main to a jump two bytes back thus entering a loop
	if (!WriteProcessMemory(process_info->hProcess, entry_point, "\xEB\xFE", 2, &size)) {
		fprintf(stderr, "WriteProcessMemory Error %u\n", result = GetLastError());
		goto BAD;
	}

	// Start target process which is currently in an infinate loop
	// this allows proper startup whith the initial token without running the targets code 
	if (ResumeThread(process_info->hThread) == -1) {
		fprintf(stderr, "ResumeThread Error %u\n", result = GetLastError());
		goto BAD;
	}

	// Wait abit for target startup
	Sleep(2000);

	// Suspend target again in order revert it to the lockdown token and repair its first two bytes 
	if (SuspendThread(process_info->hThread) == -1) {
		fprintf(stderr, "SuspendThread Error %u\n", result = GetLastError());
		goto BAD;
	}

	// Revert target token to lockdown token (same as calling revert to self)
	if (!(SetThreadToken(&process_info->hThread, NULL))) {
		fprintf(stderr, "SetThreadToken (revertToSelf) Error %u\n", result = GetLastError());
		goto BAD;
	}

	//  Repair first two bytes
	if (!WriteProcessMemory(process_info->hProcess, entry_point, first_two_bytes, 2, &size)) {
		fprintf(stderr, "WriteProcessMemory (repair first two bytes) Error %u\n", result = GetLastError());
		goto BAD;
	}

	// Obtain targets token
	if (!OpenProcessToken(process_info->hProcess, TOKEN_ADJUST_DEFAULT, &target_token)) {
		fprintf(stderr, "OpenProcessToken Error %u\n", result = GetLastError());
		goto BAD;
	}

	// Set targets mandatory integrity level to untrusted
	if ((result = SetUntrustedIntegrityLevel(&target_token)) != 0){
		fprintf(stderr, "OpenProcessToken Error %u\n", result);
		goto BAD;
	}

	// Resume target now with the lockdown token and with untrusted mandatory integrity level
	if (ResumeThread(process_info->hThread) == -1) {
		fprintf(stderr, "ResumeThread (with lockdown token) Error %u\n", result = GetLastError());
		goto BAD;
	}
	
	if (target_token)
		CloseHandle(target_token);
	return 0;

	BAD:
		
		if (target_token)
			CloseHandle(target_token);
		fprintf(stderr, "SpawnTarget Error %u\n", result);
		return result;
}


DWORD CreateAllowedFolder(TCHAR* DirectoryName){
	DWORD result = 0;
	ULONG cb = MAX_SID_SIZE;
	PACL Sacl = NULL;
	PSID untrusted_sid = NULL;

	untrusted_sid = (PSID)alloca(MAX_SID_SIZE);
	if (!CreateWellKnownSid(WinUntrustedLabelSid, nullptr, untrusted_sid, &cb)) {
		fprintf(stderr, "CreateWellKnownSid Error %u\n", result = GetLastError());
		goto BAD;
	}
	
	Sacl = (PACL)alloca(cb += sizeof(ACL) + sizeof(ACE_HEADER) + sizeof(ACCESS_MASK));
	InitializeAcl(Sacl, cb, ACL_REVISION);
	if (!AddMandatoryAce(Sacl, ACL_REVISION, 0, 0, untrusted_sid)) {
		fprintf(stderr, "AddMandatoryAce Error %u\n", result = GetLastError());
		goto BAD;
	}
	
	SECURITY_ATTRIBUTES sa;
	SECURITY_DESCRIPTOR sd;
	InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
	SetSecurityDescriptorDacl(&sd, TRUE, nullptr, FALSE);
	SetSecurityDescriptorSacl(&sd, TRUE, Sacl, FALSE);
	sa.lpSecurityDescriptor = &sd;
	sa.bInheritHandle = TRUE;
	sa.nLength = sizeof sa;
	if (!CreateDirectory(DirectoryName, &sa) && (result = GetLastError()) != ERROR_ALREADY_EXISTS) {
		fprintf(stderr, "CreateDirectory Error %u\n", result = GetLastError());
		goto BAD;
	}

	return 0;

	BAD:
		fprintf(stderr, "CreateUntrustedFolder Error %u\n", result);
		return result;
}



// Specify white list of handles to inherit 
// taken from https://blogs.msdn.microsoft.com/oldnewthing/20111216-00/?p=8873
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
	__in_ecount(cHandlesToInherit) HANDLE *rgHandlesToInherit)
{
	BOOL fInitialized = FALSE;
	SIZE_T size = 0;
	LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList = nullptr;

	BOOL fSuccess = numOfHandlesToInherit < 0xFFFFFFFF / sizeof(HANDLE) &&
		lpStartupInfo->cb == sizeof*lpStartupInfo;
	if (!fSuccess) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	if (fSuccess) {
		fSuccess = InitializeProcThreadAttributeList(nullptr, 1, 0, &size) ||
			GetLastError() == ERROR_INSUFFICIENT_BUFFER;
	}
	if (fSuccess) {
		lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>
			(HeapAlloc(GetProcessHeap(), 0, size));
		fSuccess = lpAttributeList != nullptr;
	}
	if (fSuccess) {
		fSuccess = InitializeProcThreadAttributeList(lpAttributeList,
			1, 0, &size);
	}
	if (fSuccess) {
		fInitialized = TRUE;
		fSuccess = UpdateProcThreadAttribute(lpAttributeList,
			0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
			rgHandlesToInherit,
			numOfHandlesToInherit * sizeof(HANDLE), nullptr, nullptr);
	}
	if (fSuccess) {
		STARTUPINFOEX info;
		ZeroMemory(&info, sizeof info);
		info.StartupInfo = *lpStartupInfo;
		info.StartupInfo.cb = sizeof info;
		info.lpAttributeList = lpAttributeList;
		fSuccess = CreateProcessAsUser(hToken, lpApplicationName,
			lpCommandLine,
			lpProcessAttributes,
			lpThreadAttributes,
			bInheritHandles,
			dwCreationFlags | EXTENDED_STARTUPINFO_PRESENT,
			lpEnvironment,
			lpCurrentDirectory,
			&info.StartupInfo,
			lpProcessInformation);
	}

	if (fInitialized) DeleteProcThreadAttributeList(lpAttributeList);
	if (lpAttributeList) HeapFree(GetProcessHeap(), 0, lpAttributeList);
	return fSuccess;
}
