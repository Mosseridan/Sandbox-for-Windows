#include "stdafx.h"
#include "ipc_utils.h"

IPC::IPC(){
	target_read = NULL;
	target_write = NULL;
	broker_read = NULL;
	broker_write = NULL;
}

IPC::~IPC() {
	if (target_read)
		CloseHandle(target_read);
	if (target_write)
		CloseHandle(target_write);
	if (broker_read)
		CloseHandle(broker_read);
	if (broker_write)
		CloseHandle(broker_write);
}

DWORD IPC::init() {
	DWORD result = 0;
	SECURITY_ATTRIBUTES security_attributes;

	ZeroMemory(&security_attributes, sizeof(SECURITY_ATTRIBUTES));
	security_attributes.nLength = sizeof(security_attributes);
	security_attributes.bInheritHandle = TRUE;

	// Create a pipe for the targets stdout. 
	if (!CreatePipe(&broker_read, &target_write, &security_attributes, BUFFER_SIZE)) {
		fprintf(stderr, "CreatePipe (target to broker) Error %u\n", result = GetLastError());
		goto BAD;
	}

	// Ensure the read handle to the pipe for stdout is not inherited.
	if (!SetHandleInformation(broker_read, HANDLE_FLAG_INHERIT, 0)) {
		fprintf(stderr, "SetHandleInformation (broker_read) Error %u\n", result = GetLastError());
		goto BAD;
	}

	// Create a pipe for the targets stdin. 
	if (!CreatePipe(&target_read, &broker_write, &security_attributes, BUFFER_SIZE)) {
		fprintf(stderr, "CreatePipe (broker to target) Error %u\n", result = GetLastError());
		goto BAD;
	}

	// Ensure the write handle to the pipe for stdin is not inherited. 
	if (!SetHandleInformation(broker_write, HANDLE_FLAG_INHERIT, 0)){
		fprintf(stderr, "SetHandleInformation (broker_write) Error %u\n", result = GetLastError());
		goto BAD;
	}

	return 0;
	
	BAD:
		if (target_read)
			CloseHandle(target_read);
		if (target_write)
			CloseHandle(target_write);
		if (broker_read)
			CloseHandle(broker_read);
		if (broker_write)
			CloseHandle(broker_write);
		fprintf(stderr, "IPC::init Error %u\n", result);
}


DWORD IPC::writeToTarget(CHAR* msg, size_t len){	
	DWORD bytes_writen;
	WriteFile(broker_write, msg, len, &bytes_writen, NULL);
	return bytes_writen;
}

VOID IPC::writeToTarget() {
	DWORD bytes_read, bytes_writen;
	CHAR buffer[BUFFER_SIZE];
	HANDLE broker_stdin = GetStdHandle(STD_OUTPUT_HANDLE);
	while (TRUE)
	{
		if (!ReadFile(broker_stdin, buffer, BUFFER_SIZE, &bytes_read, NULL) || bytes_read == 0)
			break;

		if (!WriteFile(broker_write, buffer, bytes_read, &bytes_writen, NULL))
			break;
	}
}

VOID IPC::readFromTarget(){
	DWORD bytes_read, bytes_writen;
	CHAR buffer[BUFFER_SIZE];
	HANDLE broker_stdout = GetStdHandle(STD_OUTPUT_HANDLE);

	while(TRUE)
	{
		if(!ReadFile(broker_read, buffer, 1, &bytes_read, NULL) || bytes_read == 0)
			break;

		if (!WriteFile(broker_stdout, buffer, bytes_read, &bytes_writen, NULL))
			break;
	}
}

VOID IPC::loop(){
	while (target_write){
		readFromTarget();
		writeToTarget();
	}
}

