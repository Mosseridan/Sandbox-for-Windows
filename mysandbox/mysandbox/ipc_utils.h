#pragma once

#define BUFFER_SIZE	4096

class IPC {

public:
	HANDLE target_read;
	HANDLE target_write;
	HANDLE broker_read;
	HANDLE broker_write;
	HANDLE broker_stdin;
	HANDLE broker_stdout;
	
	HANDLE read_thread;
	HANDLE write_thread;
	DWORD read_tid;
	DWORD write_tid;

	IPC();
	~IPC();
	DWORD init();
	VOID readFromTarget();
	VOID writeToTarget();
	DWORD writeToTarget(CHAR* msg, size_t len);
};

