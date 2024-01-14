#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <tchar.h>
#include <strsafe.h>
#include <winevt.h>
#include <conio.h>
#include <iostream>
#include <fstream>

#pragma comment(lib, "wevtapi.lib")

#ifdef UNICODE
#define t_cout wcout
#define t_ofstream wofstream
#else
#define t_cout cout
#define t_ofstream ofstream
#endif
#define XML_QUERY_STRING TEXT("<QueryList><Query Id=\"0\" Path=\"Security\"><Select Path=\"Security\">*[System[(EventID = 4657)]]</Select></Query></QueryList>")
#define REGISTRY_MONITOR_PATH_A "\\REGISTRY\\USER\\S-1-5-21-2719797338-3036012922-1766862519-1001\\Control Panel\\International\\User Profile"
#define REGISTRY_MONITOR_PATH_W L"\\REGISTRY\\USER\\S-1-5-21-2719797338-3036012922-1766862519-1001\\Control Panel\\International\\User Profile"

BOOL ForceStop = FALSE;

BOOL DirectoryExists(LPCTSTR);
unsigned long long GetTimestampSeconds(FILETIME);
int GetParentPID(int);
int GetProcessParentTree(int, LPCTSTR);
DWORD ParentTreeFromEvent(EVT_HANDLE);

DWORD WINAPI SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION, PVOID, EVT_HANDLE);

int _tmain(int argc, TCHAR* argv[])
{
    EVT_HANDLE eventSubscriptionHandle = EvtSubscribe(NULL, NULL, NULL, XML_QUERY_STRING, NULL, NULL, (EVT_SUBSCRIBE_CALLBACK)SubscriptionCallback, EvtSubscribeToFutureEvents);
    if (eventSubscriptionHandle == NULL)
    {
        std::t_cout << TEXT("EvtSubscribe failed. (") << GetLastError() << TEXT(")") << std::endl;
        return -1;
    }

    std::t_cout << TEXT("Hit any key to quit...") << std::endl;
    while (!_kbhit() && !ForceStop) {
        Sleep(10);
    }
    int _ = _getch();

    if (eventSubscriptionHandle) {
        EvtClose(eventSubscriptionHandle);
    }
    return 0;
}

BOOL DirectoryExists(LPCTSTR szPath)
{
    DWORD dwAttrib = GetFileAttributes(szPath);

    return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
        (dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

unsigned long long GetTimestampSeconds(FILETIME time) {
    ULARGE_INTEGER ulTime;
    ulTime.LowPart = time.dwLowDateTime;
    ulTime.HighPart = time.dwHighDateTime;

    SYSTEMTIME stRefTime;
    stRefTime.wYear = 1970;
    stRefTime.wMonth = 1;
    stRefTime.wDay = 1;
    stRefTime.wDayOfWeek = 4;
    stRefTime.wHour = 0;
    stRefTime.wMinute = 0;
    stRefTime.wSecond = 0;
    stRefTime.wMilliseconds = 0;

    FILETIME ftRefTime;
    SystemTimeToFileTime(&stRefTime, &ftRefTime);
    ULARGE_INTEGER ulRefTime;
    ulRefTime.LowPart = ftRefTime.dwLowDateTime;
    ulRefTime.HighPart = ftRefTime.dwHighDateTime;

    return (ulTime.QuadPart - ulRefTime.QuadPart) / 10000000;
}

int GetParentPID(int pid) {
    HANDLE pidProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    FILETIME pidCreationTime, _0, _1, _2;
    GetProcessTimes(pidProcess, &pidCreationTime, &_0, &_1, &_2);
    unsigned long long pidTimestamp = GetTimestampSeconds(pidCreationTime);
    CloseHandle(pidProcess);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 processEntry = { 0 };
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &processEntry)) {
        do {
            if (processEntry.th32ProcessID == pid) {
                DWORD ppid = processEntry.th32ParentProcessID;
                HANDLE ppidProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ppid);
                FILETIME ppidCreationTime, _0, _1, _2;
                GetProcessTimes(ppidProcess, &ppidCreationTime, &_0, &_1, &_2);
                unsigned long long ppidTimestamp = GetTimestampSeconds(ppidCreationTime);
                CloseHandle(ppidProcess);
                CloseHandle(snapshot);

                if (ppidTimestamp > pidTimestamp) {
                    return -1;
                }

                return ppid;
            }
        } while (Process32Next(snapshot, &processEntry));
    }

    CloseHandle(snapshot);
    return -1;
}

int GetProcessParentTree(int pid, LPCTSTR outFileName) {
    std::t_ofstream outFileStream;
    outFileStream.open(outFileName);

    HANDLE checkProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (checkProcess == NULL) {
        return -1;
    }

    do {
        TCHAR processExePath[MAX_PATH];
        GetModuleFileNameEx(checkProcess, NULL, processExePath, MAX_PATH);
        CloseHandle(checkProcess);
        std::t_cout << pid << ' ' << processExePath << std::endl;
        outFileStream << pid << ' ' << processExePath << std::endl;
        pid = GetParentPID(pid);
        checkProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    } while (pid != -1 && checkProcess != NULL);

    CloseHandle(checkProcess);
    return 0;
}

DWORD WINAPI SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID pContext, EVT_HANDLE hEvent) {
    UNREFERENCED_PARAMETER(pContext);

    DWORD status = ERROR_SUCCESS;

    switch (action)
    {
        // You should only get the EvtSubscribeActionError action if your subscription flags 
        // includes EvtSubscribeStrict and the channel contains missing event records.
    case EvtSubscribeActionError:
        if (ERROR_EVT_QUERY_RESULT_STALE == (DWORD)hEvent)
        {
            std::t_cout << TEXT("The subscription callback was notified that event records are missing.") << std::endl;
            // Handle if this is an issue for your application.
        }
        else
        {
            std::t_cout << TEXT("The subscription callback received the following Win32 error: ") << (DWORD)hEvent << std::endl;
        }
        break;

    case EvtSubscribeActionDeliver:
        if (ERROR_SUCCESS != (status = ParentTreeFromEvent(hEvent))) {
            ForceStop = TRUE;
        }
        break;
    default:
        std::t_cout << TEXT("SubscriptionCallback: Unknown action.") << std::endl;
    }

    return status;
}

DWORD ParentTreeFromEvent(EVT_HANDLE hEvent) {
    LPCTSTR valuePaths[3] = { TEXT("Event/System/EventRecordID"), TEXT("Event/EventData/Data[@Name=\"ObjectName\"]"), TEXT("Event/EventData/Data[@Name=\"ProcessId\"]") };
    EVT_HANDLE renderContext = EvtCreateRenderContext(3, valuePaths, EvtRenderContextValues);
    if (renderContext == NULL) {
        return GetLastError();
    }
    EVT_VARIANT eventValues[3] = { NULL };
    DWORD bufferUsed = 0;
    DWORD propertyCount = 0;
    BOOL result = EvtRender(renderContext, hEvent, EvtRenderEventValues, sizeof(eventValues), &eventValues, &bufferUsed, &propertyCount);
    if (!result) {
        return GetLastError();
    }
    CloseHandle(renderContext);
    EVT_VARIANT eventRecordId = eventValues[0];
    EVT_VARIANT eventObjectName = eventValues[1];
    EVT_VARIANT eventPid = eventValues[2];
    if (eventObjectName.Type == EvtVarTypeString) {
        LPCWSTR objectNameW = eventObjectName.StringVal;
        if (wcsncmp(objectNameW, REGISTRY_MONITOR_PATH_W, 103) != 0) {
            return 0;
        }
    }
    else if (eventObjectName.Type == EvtVarTypeAnsiString) {
        LPCSTR objectNameA = eventObjectName.AnsiStringVal;
        if (strncmp(objectNameA, REGISTRY_MONITOR_PATH_A, 103) != 0) {
            return 0;
        }
    }

    UINT64 recordId = eventRecordId.UInt64Val;
    INT64 pid = eventPid.Int64Val;
    TCHAR outFileName[MAX_PATH];
    StringCchPrintf(outFileName, MAX_PATH, TEXT("out\\%llu.txt"), recordId);
    if (!DirectoryExists(TEXT("out"))) {
        CreateDirectory(TEXT("out"), NULL);
    }
    return GetProcessParentTree(pid, outFileName);
}