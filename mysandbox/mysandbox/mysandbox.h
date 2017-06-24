#include "token_utils.h"
#include "job_and_desktop_utils.h"
#include "ipc_utils.h"

int main(int argc, char ** argv);

DWORD SpawnTarget(
	__in PHANDLE lockdown_token,
	__in PHANDLE initial_token,
	__in PHANDLE job_handle,
	__in HDESK* target_desktop,
	__in IPC* ipc,
	__in LPWSTR command_line,
	__out PPROCESS_INFORMATION process_info);