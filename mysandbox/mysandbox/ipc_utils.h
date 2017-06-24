#pragma once

#define BUFFER_SIZE	4096

class IPC {

public:
	HANDLE target_read;
	HANDLE target_write;
	HANDLE broker_read;
	HANDLE broker_write;


	IPC();
	~IPC();
	DWORD init();
	VOID readFromTarget();
	VOID writeToTarget();
	DWORD writeToTarget(CHAR* msg, size_t len);
	VOID loop();
};

