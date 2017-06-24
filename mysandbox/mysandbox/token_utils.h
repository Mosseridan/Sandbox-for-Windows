#pragma once

enum INTEGRITY_LEVEL { UNTUSTED = 0, LOW };

// Create the lockdown token with all privilages removed,
// mandatory low integrity level,
// all groups in deny only except logon
// and the restricted and logon sids as a restricted sids
DWORD CreateLockdownToken(PHANDLE effective_token, PHANDLE lockdown_token);

// Create the initial token with all privilages removed, 
// mandatory low integrity level,
// all groups in deny only except logon , everyone, and users and domain related sids
// and the restricted, everyone, users and logon sids as a restricted sids
DWORD CreateInitialToken(PHANDLE effective_token, PHANDLE initial_token);

// Set tokens integrity level to the given level
DWORD SetIntegrityLevel(PHANDLE token, INTEGRITY_LEVEL integrity_level);

// Set tokens integrity level to untrusted
DWORD SetUntrustedIntegrityLevel(PHANDLE token);

// Set tokens integrity level to mandatory low integrity level
DWORD SetLowIntegrityLevel(PHANDLE token);