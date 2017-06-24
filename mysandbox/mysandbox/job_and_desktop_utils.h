#pragma once

DWORD CreateJob(PHANDLE job_handle);
DWORD createStationAndDesktop(HWINSTA* new_station, HDESK* new_desktop);