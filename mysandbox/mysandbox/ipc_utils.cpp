#include "stdafx.h"
#include "ipc_utils.h"

IPC::IPC(){
	target_read = NULL;
	target_write = NULL;
	broker_read = NULL;
	broker_write = NULL;
	broker_stdin = NULL;
	broker_stdout = NULL;
	read_thread = NULL;
	write_thread = NULL;
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
	if (broker_stdin)
		CloseHandle(broker_stdin);
	if (broker_stdout)
		CloseHandle(broker_stdout);
	if (read_thread) {
		TerminateThread(read_thread, 0);
		CloseHandle(read_thread);
	}
	if (write_thread) {
		TerminateThread(write_thread, 0);
		CloseHandle(write_thread);
	}
}

DWORD WINAPI threadReadFromTarget(LPVOID ipc) {
	((IPC*)ipc)->readFromTarget();
	return 0;
}

DWORD WINAPI  threadWriteToTarget(LPVOID ipc) {
	((IPC*)ipc)->writeToTarget();
	return 0;
}

DWORD IPC::init() {
	DWORD result = 0;
	SECURITY_ATTRIBUTES security_attributes;

	broker_stdin = GetStdHandle(STD_INPUT_HANDLE);
	broker_stdout = GetStdHandle(STD_OUTPUT_HANDLE);

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

	read_thread = CreateThread(NULL, 0, threadReadFromTarget, this, 0, &read_tid);
	write_thread =  CreateThread(NULL, 0, threadWriteToTarget, this, 0, &write_tid);

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
		if (broker_stdin)
			CloseHandle(broker_stdin);
		if (broker_stdout)
			CloseHandle(broker_stdout);
		if (read_thread) {
			TerminateThread(read_thread, 0);
			CloseHandle(read_thread);
		}
		if (write_thread) {
			TerminateThread(write_thread, 0);
			CloseHandle(write_thread);
		}
		fprintf(stderr, "IPC::init Error %u\n", result);
		return result;
}


DWORD IPC::writeToTarget(CHAR* msg, size_t len){	
	DWORD bytes_writen;
	WriteFile(broker_write, msg, len, &bytes_writen, NULL);
	return bytes_writen;
}



VOID IPC::writeToTarget() {
	DWORD bytes_read, bytes_writen;
	CHAR buffer[BUFFER_SIZE + 1] = { 0 };
	
	while (TRUE)
	{	
		if (!ReadFile(broker_stdin, buffer, BUFFER_SIZE, &bytes_read, NULL) || bytes_read == 0)
			break;

		buffer[bytes_read] = 0; // null terminate string also remove \r\n added from console

		if (!WriteFile(broker_write, buffer, bytes_read, &bytes_writen, NULL))
			break;
	}
}

VOID IPC::readFromTarget(){
	DWORD bytes_read, bytes_writen;
	CHAR buffer[BUFFER_SIZE + 1] = { 0 };

	while(TRUE)
	{
		if (!ReadFile(broker_read, buffer, BUFFER_SIZE, &bytes_read, NULL) || bytes_read == 0)
			break;
		
		buffer[bytes_read] = 0; // null terminate string

		if (!WriteFile(broker_stdout, buffer, bytes_read, &bytes_writen, NULL))
			break;
	}
}
