// mysandbox.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "mysandbox.h"


int main(int argc, char** argv)
{	
	DWORD result = 0, size = 0;
	WCHAR command_line[MAX_PATH + 1] = { 0 };
	HWINSTA target_station;
	HDESK target_desktop;
	HANDLE job_handle = NULL;
	HANDLE effective_token = NULL;
	HANDLE lockdown_token = NULL;
	HANDLE initial_token = NULL;
	IPC* ipc;
	PROCESS_INFORMATION process_info = { 0 };

	// parse command line.
	if (argc < 3 || strcmp("-torun", argv[1])) {
		fprintf(stderr, "Usage: -torun <TargetPath>\n");
		return -1;
	}

	MultiByteToWideChar(0, 0, argv[2], strlen(argv[2]), command_line, strlen(argv[2]));


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

	if ((result = SpawnTarget(&lockdown_token, &initial_token, &job_handle, &target_desktop, ipc, command_line, &process_info)) != 0)
		goto BAD;

	//ipc->loop();

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
	__in LPWSTR command_line,
	__out PPROCESS_INFORMATION process_info) {

	DWORD result = 0, old_protection = 0, target_desktop_name_length = 0;
	HANDLE target_token = NULL;
	STARTUPINFO startup_info;
	WCHAR* target_desktop_name;
	CONTEXT context = { 0 };
	LPVOID entry_point = 0;
	BYTE first_two_bytes[2] = { 0 };
	SIZE_T size = 0;
	
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

	// set targets desktop
	startup_info.lpDesktop = target_desktop_name;
	// set targets standard in, out and error
	/*startup_info.hStdError = ipc->target_write;
	startup_info.hStdOutput = ipc->target_write;
	startup_info.hStdInput = ipc->target_read;
	startup_info.dwFlags |= STARTF_USESTDHANDLES;*/

	// create the target process suspended whithin the new station and desktop
	// and whith the lockdown token as a primary token
	if (!CreateProcessAsUser(*lockdown_token,
		NULL,	// No name
		command_line,
		NULL,   // No security attribute.
		NULL,   // No thread attribute.
		FALSE,  // Do not inherit handles.
		CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB,
		NULL,   // Use the environment of the caller.
		NULL,   // Use current directory of the caller.
		&startup_info,
		process_info)) {
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
	Sleep(1000);

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


