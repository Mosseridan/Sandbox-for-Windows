
#include "stdafx.h"
#include "token_utils.h"

// Create the lockdown token with all privilages removed,
// mandatory low integrity level,
// all groups in deny only except logon
// and the restricted and logon sids as a restricted sids
DWORD CreateLockdownToken(PHANDLE effective_token, PHANDLE lockdown_token) {

	DWORD result = 0, token_groups_size = 0, disabled_count = 0, restricted_count = 0;
	PTOKEN_GROUPS token_groups = NULL;
	PSID_AND_ATTRIBUTES sids_to_disable = NULL;
	PSID_AND_ATTRIBUTES sids_to_restrict = NULL;

	// Call GetTokenInformation to get the token_groups size.
	GetTokenInformation(*effective_token, TokenGroups, NULL, token_groups_size, &token_groups_size);
	if (!token_groups_size) {
		result = GetLastError();
		fprintf(stderr, "GetTokenInformation (size check) Error %u\n", result);
		goto BAD;
	}

	// Allocate the space for token_groups
	token_groups = reinterpret_cast<PTOKEN_GROUPS>(new BYTE[token_groups_size]);

	// Obtain token_groups.
	if (!GetTokenInformation(*effective_token, TokenGroups, token_groups, token_groups_size, &token_groups_size)) {
		result = GetLastError();
		fprintf(stderr, "GetTokenInformation Error %u\n", result);
		goto BAD;
	}

	// Allocate space for sids_to_disable
	sids_to_disable = new SID_AND_ATTRIBUTES[token_groups->GroupCount];

	// Allocate space for sids_to_restrict
	restricted_count = 2;
	sids_to_restrict = new SID_AND_ATTRIBUTES[restricted_count];
	for (int i = 0; i < restricted_count; ++i)
		sids_to_restrict[i].Attributes = 0;

	// Obtain the restricted sid add it to sids_to_restrict[0]
	if (!ConvertStringSidToSid(L"S-1-5-12", &(sids_to_restrict[0].Sid))) {
		result = GetLastError();
		fprintf(stderr, "ConvertStringSidToSid (restricted sid) Error %u\n", result);
		goto BAD;
	}

	//// Obtain the null sid add it to sids_to_restrict[1]
	//if (!ConvertStringSidToSid(L"S-1-0-0", &(sids_to_restrict[1].Sid))) {
	//	result = GetLastError();
	//	fprintf(stderr, "ConvertStringSidToSid (null sid) Error %u\n", result);
	//	goto BAD;
	//}

	// Build sids_to_disable and fild logon sid and add it to sids_to_restrict[2]
	for (unsigned int i = 0; i < token_groups->GroupCount; ++i) {

		if ((token_groups->Groups[i].Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID)
			sids_to_restrict[1].Sid = token_groups->Groups[i].Sid;

		if ((token_groups->Groups[i].Attributes & SE_GROUP_INTEGRITY) == 0 &&
			(token_groups->Groups[i].Attributes & SE_GROUP_LOGON_ID) == 0) {
			sids_to_disable[disabled_count].Sid = token_groups->Groups[i].Sid;
			sids_to_disable[disabled_count].Attributes = SE_GROUP_USE_FOR_DENY_ONLY;
			disabled_count++;
		}
	}

	// Create the lockdown token with all privilages removed,
	// mandatory low integrity level,
	// all groups in deny only except logon
	// and the restricted and logon sids as a restricted sids
	if (!CreateRestrictedToken(*effective_token,
		DISABLE_MAX_PRIVILEGE | SANDBOX_INERT,
		disabled_count, sids_to_disable,
		0, NULL,
		restricted_count, sids_to_restrict,
		lockdown_token)) {
		result = GetLastError();
		fprintf(stderr, "CreateRestrictedToken Error %u\n", result);
		goto BAD;
	}

	// set Low Integrity level
	if ((result = SetLowIntegrityLevel(lockdown_token) != 0))
		goto BAD;


	if (token_groups)
		delete[] reinterpret_cast<BYTE*>(token_groups);
	if (sids_to_disable)
		delete[] sids_to_disable;
	if (sids_to_restrict)
		delete[] sids_to_restrict;
	return 0;

BAD:
	fprintf(stderr, "CreateLockdownToken Error %u\n", result);
	if (token_groups)
		delete[] reinterpret_cast<BYTE*>(token_groups);
	if (sids_to_disable)
		delete[] sids_to_disable;
	if (sids_to_restrict)
		delete[] sids_to_restrict;
	return result;
}

// Create the initial token with all privilages removed, 
// mandatory low integrity level,
// all groups in deny only except logon , everyone, and users and domain related sids
// and the restricted, everyone, users and logon sids as a restricted sids
DWORD CreateInitialToken(PHANDLE effective_token, PHANDLE initial_token) {

	DWORD result = 0, token_groups_size = 0, disabled_count = 0, restricted_count = 0;
	PTOKEN_GROUPS token_groups = NULL;
	PSID_AND_ATTRIBUTES sids_to_disable = NULL;
	PSID_AND_ATTRIBUTES sids_to_restrict = NULL;
	HANDLE new_token = NULL;

	// Call GetTokenInformation to get the token_groups size.
	GetTokenInformation(*effective_token, TokenGroups, NULL, token_groups_size, &token_groups_size);
	if (!token_groups_size) {
		result = GetLastError();
		fprintf(stderr, "GetTokenInformation (size check) Error %u\n", result);
		goto BAD;
	}

	// Allocate the space for token_groups
	token_groups = reinterpret_cast<PTOKEN_GROUPS>(new BYTE[token_groups_size]);

	// Obtain token_groups.
	if (!GetTokenInformation(*effective_token, TokenGroups, token_groups, token_groups_size, &token_groups_size)) {
		result = GetLastError();
		fprintf(stderr, "GetTokenInformation Error %u\n", result);
		goto BAD;
	}

	// Allocate space for sids_to_disable
	sids_to_disable = new SID_AND_ATTRIBUTES[token_groups->GroupCount];

	// Allocate space for sids_to_restrict
	restricted_count = 4;
	sids_to_restrict = new SID_AND_ATTRIBUTES[restricted_count];
	for (int i = 0; i < restricted_count; ++i)
		sids_to_restrict[i].Attributes = 0;

	// Obtain the restricted sid add it to sids_to_restrict[0]
	if (!ConvertStringSidToSid(L"S-1-5-12", &(sids_to_restrict[0].Sid))) {
		result = GetLastError();
		fprintf(stderr, "ConvertStringSidToSid (restricted sid) Error %u\n", result);
		goto BAD;
	}

	//// Obtain the null sid add it to sids_to_restrict[1]
	//if (!ConvertStringSidToSid(L"S-1-0-0", &(sids_to_restrict[1].Sid))) {
	//	result = GetLastError();
	//	fprintf(stderr, "ConvertStringSidToSid (null sid) Error %u\n", result);
	//	goto BAD;
	//}

	// Obtain the everyone sid add it to sids_to_restrict[2]
	if (!ConvertStringSidToSid(L"S-1-1-0", &(sids_to_restrict[1].Sid))) {
		result = GetLastError();
		fprintf(stderr, "ConvertStringSidToSid (everyone sid) Error %u\n", result);
		goto BAD;
	}

	// Obtain the users sid add it to sids_to_restrict[3]
	if (!ConvertStringSidToSid(L"S-1-5-32-545", &(sids_to_restrict[2].Sid))) {
		result = GetLastError();
		fprintf(stderr, "ConvertStringSidToSid (users sid) Error %u\n", result);
		goto BAD;
	}

	// Build sids_to_disable and fild logon sid and add it to sids_to_restrict[4]
	for (unsigned int i = 0; i < token_groups->GroupCount; ++i) {
		if ((token_groups->Groups[i].Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID) {
			sids_to_restrict[3].Sid = token_groups->Groups[i].Sid;
		}

		if ((token_groups->Groups[i].Attributes & SE_GROUP_INTEGRITY) == 0 &&
			(token_groups->Groups[i].Attributes & SE_GROUP_LOGON_ID) == 0 &&
			((SID*)token_groups->Groups[i].Sid)->SubAuthority[0] != SECURITY_BUILTIN_DOMAIN_RID &&
			!EqualSid(token_groups->Groups[i].Sid, sids_to_restrict[1].Sid)) { // not everyone sid
			sids_to_disable[disabled_count].Sid = token_groups->Groups[i].Sid;
			sids_to_disable[disabled_count].Attributes = SE_GROUP_USE_FOR_DENY_ONLY;
			disabled_count++;
		}
	}

	// Create the initial token with all privilages removed, 
	// mandatory low integrity level,
	// all groups in deny only except logon , everyone, and users and domain related sids
	// and the restricted, everyone, users and logon sids as a restricted sids
	if (!CreateRestrictedToken(*effective_token,
		DISABLE_MAX_PRIVILEGE | SANDBOX_INERT,
		disabled_count, sids_to_disable,
		0, NULL,
		restricted_count, sids_to_restrict,
		&new_token)) {
		result = GetLastError();
		fprintf(stderr, "CreateRestrictedToken Error %u\n", result);
		goto BAD;
	}

	// set Low Integrity level
	if ((result = SetLowIntegrityLevel(&new_token) != 0))
		goto BAD;

	// duplicate the new token for impersonation
	if (!DuplicateToken(new_token, SecurityImpersonation, initial_token)) {
		result = GetLastError();
		fprintf(stderr, "DuplicateToken Error %u\n", result);
		goto BAD;
	}

	if (token_groups)
		delete[] reinterpret_cast<BYTE*>(token_groups);
	if (sids_to_disable)
		delete[] sids_to_disable;
	if (sids_to_restrict)
		delete[] sids_to_restrict;
	if (new_token)
		CloseHandle(new_token);

	return 0;

BAD:
	fprintf(stderr, "CreateInitialToken Error %u\n", result);
	if (token_groups)
		delete[] reinterpret_cast<BYTE*>(token_groups);
	if (sids_to_disable)
		delete[] sids_to_disable;
	if (sids_to_restrict)
		delete[] sids_to_restrict;
	if (new_token)
		CloseHandle(new_token);
	return result;
}

// Set tokens integrity level to the given level
DWORD SetIntegrityLevel(PHANDLE token, INTEGRITY_LEVEL integrity_level) {
	DWORD result = 0;
	PSID integrity_sid = NULL;
	//WCHAR string_integrity_sid[20];
	TOKEN_MANDATORY_LABEL token_information = { 0 };

	switch (integrity_level) {
	case UNTUSTED:
		if (!ConvertStringSidToSid(L"S-1-16-0", &integrity_sid)) {
			fprintf(stderr, "ConvertStringSidToSid Error %u\n", result = GetLastError());
			goto BAD;
		}
		break;
	case LOW:
		if (!ConvertStringSidToSid(L"S-1-16-4096", &integrity_sid)) {
			fprintf(stderr, "ConvertStringSidToSid Error %u\n", result = GetLastError());
			goto BAD;
		}
		break;
	defult:
		fprintf(stderr, "Invalid Integrity level Error %u\n", result = -1);
		goto BAD;
	}

	token_information.Label.Attributes = SE_GROUP_INTEGRITY;
	token_information.Label.Sid = integrity_sid;

	if (!SetTokenInformation(*token,
		TokenIntegrityLevel,
		&token_information,
		sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(integrity_sid))) {
		result = GetLastError();
		fprintf(stderr, "SetTokenInformation Error %u\n", result);
		goto BAD;
	}

	if (integrity_sid)
		LocalFree(integrity_sid);
	return 0;

BAD:
	fprintf(stderr, "SetLowIntegrityLevel Error %u\n", result);
	if (integrity_sid)
		LocalFree(integrity_sid);
	return result;
}

// Set tokens integrity level to untrusted
DWORD SetUntrustedIntegrityLevel(PHANDLE token) {
	return SetIntegrityLevel(token, INTEGRITY_LEVEL::UNTUSTED);
}

// Set tokens integrity level to mandatory low integrity level
DWORD SetLowIntegrityLevel(PHANDLE token) {
	return SetIntegrityLevel(token, INTEGRITY_LEVEL::LOW);
}
