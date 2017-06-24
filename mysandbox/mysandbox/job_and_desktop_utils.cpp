#include "stdafx.h"
#include "job_and_desktop_utils.h"

DWORD createStationAndDesktop(HWINSTA* new_station, HDESK* new_desktop) {
	
	DWORD result = 0;
	HWINSTA current_station;
	HDESK current_desktop;
	//HWINSTA new_station;
	//HDESK new_desktop;

	if ((current_station = GetProcessWindowStation()) == 0) {
		fprintf(stderr, "GetProcessWindowStation Error %u\n", result = GetLastError());
		goto BAD;
	}

	if ((current_desktop = GetThreadDesktop(GetCurrentThreadId())) == 0) {
		fprintf(stderr, "GetThreadDesktop Error %u\n", result = GetLastError());
		goto BAD;
	}
	
	if ((*new_station = CreateWindowStation(NULL, NULL, WINSTA_ALL_ACCESS, NULL)) == 0 ){
		//(new_station = OpenWindowStation(NULL, NULL, GENERIC_ALL)) == 0) {
		fprintf(stderr, "CreateWindowStation Error %u\n", result = GetLastError());
		goto BAD;
	}

	
	if (!SetProcessWindowStation(*new_station)) {
		fprintf(stderr, "SetProcessWindowStation Error %u\n", result = GetLastError());
		goto BAD;
	}

			
	if ((*new_desktop = CreateDesktop(TEXT("standbox_target_desktop"), NULL, NULL, 0, GENERIC_ALL, NULL)) == 0 ){
		//(new_desktop = OpenDesktop(new_desktop_name, NULL, TRUE, GENERIC_ALL)) == 0){
		fprintf(stderr, "CreateDesktop Error %u\n", result = GetLastError());
		goto BAD;
	}

	
	// Revert to original station and desktop
	if (!SetProcessWindowStation(current_station)) {
		fprintf(stderr, "SetProcessWindowStation (revert back to origin) Error %u\n", result = GetLastError());
		goto BAD;
	}
	
	if(current_station)
		CloseHandle(current_station);
	if (current_desktop)
		CloseHandle(current_desktop);



	return 0;

	BAD:
		fprintf(stderr, "setNewWindowStationAndDesktop Error %u\n", result);
		if(new_station)
			SetProcessWindowStation(current_station);
		if (current_station)
			CloseHandle(current_station);
		if (current_desktop)
			CloseHandle(current_desktop);
		if (new_station)
			CloseHandle(new_station);
		if (new_desktop)
			CloseHandle(new_desktop);
		return result;
}


// Create enclosing job object
DWORD CreateJob(PHANDLE job_handle) {
	
	DWORD result = 0;
	SECURITY_ATTRIBUTES security_attributes;
	JOBOBJECT_BASIC_UI_RESTRICTIONS ui_restriction;
	JOBOBJECT_BASIC_LIMIT_INFORMATION basic_limits;
	JOBOBJECT_EXTENDED_LIMIT_INFORMATION extLimit;

	if (!(*job_handle = CreateJobObject(NULL, NULL))) {
		fprintf(stderr, "CreateJobObject Error %u\n", result = GetLastError());
		goto BAD;
	}

	
	ZeroMemory(&ui_restriction, sizeof(JOBOBJECT_BASIC_UI_RESTRICTIONS));
	ui_restriction.UIRestrictionsClass = 
		JOB_OBJECT_UILIMIT_WRITECLIPBOARD |
		JOB_OBJECT_UILIMIT_READCLIPBOARD |
		JOB_OBJECT_UILIMIT_HANDLES |
		JOB_OBJECT_UILIMIT_GLOBALATOMS |
		JOB_OBJECT_UILIMIT_DISPLAYSETTINGS |
		JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS |
		JOB_OBJECT_UILIMIT_DESKTOP |
		JOB_OBJECT_UILIMIT_EXITWINDOWS;
		
		
	if (!SetInformationJobObject(*job_handle, JobObjectBasicUIRestrictions, &ui_restriction, sizeof(JOBOBJECT_BASIC_UI_RESTRICTIONS))) {
		fprintf(stderr, "CreateRestrictedJobObject Error %u\n", result = GetLastError());
		goto BAD;
	}

	
	ZeroMemory(&basic_limits, sizeof(JOBOBJECT_BASIC_LIMIT_INFORMATION));
	basic_limits.LimitFlags = 
		JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION | 
		JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
		JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
	
	basic_limits.ActiveProcessLimit = 1;

	ZeroMemory(&extLimit, sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
	extLimit.BasicLimitInformation = basic_limits;
	if (!SetInformationJobObject(*job_handle, JobObjectExtendedLimitInformation, &extLimit, sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION))) {
		fprintf(stderr, "SetInformationJobObject Error %u\n", result = GetLastError());
		goto BAD;
	}

	return 0;

	BAD:
		fprintf(stderr, "CreateJob Error %u\n", result);
		if(*job_handle)
			TerminateJobObject(*job_handle, EXIT_FAILURE);
		return result;
}


