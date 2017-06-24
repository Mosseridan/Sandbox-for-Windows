// target.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <iostream>
#include <string>
using namespace std;



#define BUFSIZE 4096 


int main()
{
	string str;

	cout << "Hello World!\n";

	while (TRUE) {
		getline(cin, str);
		if (!str.compare("exit"))
			return 0;

		else if (!str.compare("create files")) {
			HANDLE hTempFile = INVALID_HANDLE_VALUE;
			hTempFile = CreateFile(TEXT("C:\\Users\\mosse\\Desktop\\temp.txt"), // file name 
				GENERIC_ALL,        // open for all actions 
				0,                    // do not share 
				NULL,                 // defined
				CREATE_ALWAYS,        // overwrite existing
				FILE_ATTRIBUTE_NORMAL,// normal file 
				NULL);                // no template 
			if (hTempFile == INVALID_HANDLE_VALUE)
				cout << "failed to create a file on your desktop\n";
			else{
				cout << "Created a file on your desktop\n";
				CloseHandle(hTempFile);
			}

			hTempFile = CreateFile(TEXT("C:\\temp.txt"), // file name 
				GENERIC_ALL,        // open for all actions 
				0,                    // do not share 
				NULL,                 // defined
				CREATE_ALWAYS,        // overwrite existing
				FILE_ATTRIBUTE_NORMAL,// normal file 
				NULL);                // no template 
			if (hTempFile == INVALID_HANDLE_VALUE)
				cout << "failed to create file in C\n";
			else{
				cout << "Created a file in C\n";
				CloseHandle(hTempFile);
			}

			hTempFile = CreateFile(TEXT("C:\\Windows\\temp.txt"), // file name 
				GENERIC_ALL,        // open for all actions 
				0,                    // do not share 
				NULL,                 // defined
				CREATE_ALWAYS,        // overwrite existing
				FILE_ATTRIBUTE_NORMAL,// normal file 
				NULL);                // no template 
			if (hTempFile == INVALID_HANDLE_VALUE)
				printf("failed to create file in C:\\Windows\n\n");
			else {
				cout << "Created a file in C:\\Windows \n\n";
				CloseHandle(hTempFile);
			}

		}

		else if (!str.compare("delete files")) {
			cout << "Deleting created files\n";
			if (DeleteFile(TEXT("C:\\Users\\mosse\\Desktop\\temp.txt")))
				cout << "C:\\Users\\mosse\\Desktop\\temp.txt deleted!";
			else
				cout << "Failed to delete C:\\Users\\mosse\\Desktop\\temp.txt!";
			
			if (DeleteFile(TEXT("C:\\temp.txt")))
				cout << "C:\\temp.txt deleted!";
			else
				cout << "Failed to delete C:\\temp.txt!";
			
			if(DeleteFile(TEXT("C:\\Windows\\temp.txt")))
				cout << "C:\\Windows\\temp.txt deleted!";
			else
				cout << "Failed to delete C:\\Windows\\temp.txt!";
		}

		else
			cout << "You said: " << str << ".\nGreat for you!\n\n";
	}
	return 0;
}


