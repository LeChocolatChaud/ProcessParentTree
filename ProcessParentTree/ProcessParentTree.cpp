#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <strsafe.h>
#include <tchar.h>
#include <iostream>
#include <fstream>

#ifdef UNICODE
#define t_cout std::wcout
#define t_ofstream std::wofstream
#else
#define t_cout std::cout
#define t_ofstream std:ofstream
#endif

BOOL DirectoryExists(LPCTSTR);
unsigned long long GetTimestampSeconds(FILETIME);
int GetParentPID(int);

int _tmain(int argc, TCHAR* argv[])
{
    if (!DirectoryExists(TEXT("out"))) {
        CreateDirectory(TEXT("out"), NULL);
    }

    int pid = GetCurrentProcessId();
    TCHAR* outFileName;
    SYSTEMTIME currentTime;
    GetLocalTime(&currentTime);
    outFileName = new TCHAR[24];
    StringCchPrintf(outFileName, 24, TEXT("out\\%hu%02hu%02hu-%02hu%02hu%02hu.txt"), currentTime.wYear, currentTime.wMonth, currentTime.wDay, currentTime.wHour, currentTime.wMinute, currentTime.wSecond);
    switch (argc) {
    case 3:
        outFileName = argv[2];
    case 2:
        pid = _tstoi(argv[1]);
    case 1:
        break;
    default:
        return -1;
    }


    t_ofstream outFileStream;
    outFileStream.open(outFileName);

    HANDLE checkProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (checkProcess == NULL) {
        return -1;
    }

    do {
        TCHAR processExePath[MAX_PATH];
        GetModuleFileNameEx(checkProcess, NULL, processExePath, MAX_PATH);
        CloseHandle(checkProcess);
        t_cout << pid << ' ' << processExePath << std::endl;
        outFileStream << pid << ' ' << processExePath << std::endl;
        pid = GetParentPID(pid);
        checkProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    } while (pid != -1 && checkProcess != NULL);

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

    return ( ulTime.QuadPart - ulRefTime.QuadPart ) / 10000000;
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