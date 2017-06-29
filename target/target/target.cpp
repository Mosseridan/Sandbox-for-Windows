// target.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#define BUFSIZE 4096 

int main(void)
{
	CHAR chBuf[BUFSIZE];
	DWORD dwRead, dwWritten;
	HANDLE hStdin, hStdout;
	HANDLE log = NULL;

	hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
	hStdin = GetStdHandle(STD_INPUT_HANDLE);
	if ((hStdout == INVALID_HANDLE_VALUE) || (hStdin == INVALID_HANDLE_VALUE))
		ExitProcess(1);

	// Send something to this process's stdout using printf.
	printf("\n ** This is a message from the child process. ** \n\r\n");
	fflush(stdout);

	
	log = CreateFile(TEXT("log.txt"), // file name 
		GENERIC_ALL,        // open for all actions 
		0,                    // do not share 
		NULL,                 // defined
		CREATE_ALWAYS,        // overwrite existing
		FILE_ATTRIBUTE_NORMAL,// normal file 
		NULL);                // no template 
	if (log == INVALID_HANDLE_VALUE) {
		printf("failed to create file in temp.txt\n");
		fflush(stdout);
	}


	// This simple algorithm uses the existence of the pipes to control execution.
	// It relies on the pipe buffers to ensure that no data is lost.
	// Larger applications would use more advanced process control.
	for (;;)
	{
		ZeroMemory(chBuf, BUFSIZE);
		printf("\nSay somthing:\n");
		fflush(stdout);
		// Read from standard input and stop on error or no data.
		if (!ReadFile(hStdin, chBuf, BUFSIZE, &dwRead, NULL) || dwRead == 0)
			break;

		if (!strcmp(chBuf, "exit\r\n"))
			break;


		printf("You said:\n");
		fflush(stdout);
		// Write to standard output and stop on error.
		if(!WriteFile(hStdout, chBuf, dwRead, &dwWritten, NULL))
			break;

		if (log && !WriteFile(log, chBuf, dwRead, &dwWritten, NULL))
			break;
			
	}

	if (log) {
		CloseHandle(log);
		DeleteFile(TEXT("log.txt"));
	}
		
	printf("\nTarget exiting...\n");
	fflush(stdout);

	return 0;
}