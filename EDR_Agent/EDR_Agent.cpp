#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iostream>
#include <thread>
#include "krabs/krabs.hpp"
#include "RegistryDetector.h"
#include "ProcessAccessDetector.h" 
#include "ProcessFinder.h"         
#include "FileDetector.h"

RegistryDetector g_registryDetector;
ProcessAccessDetector g_accessDetector;
FileDetector g_fileDetector;
DWORD g_currentVictimPid = 0;

static const GUID AuditApiCallsGuid = { 0xe02a841c, 0x75a3, 0x4fa7, { 0xaf, 0xc8, 0xae, 0x09, 0xcf, 0x9b, 0x7f, 0x23 } };

void OnRegistryEvent(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    krabs::schema schema(record, trace_context.schema_locator);
    int opcode = schema.event_opcode();
    if (opcode == 10 || opcode == 11 || opcode == 16 || opcode == 22) {
        krabs::parser parser(schema);
        std::wstring keyName;
        try { keyName = parser.parse<std::wstring>(L"KeyName"); }
        catch (...) { try { keyName = parser.parse<std::wstring>(L"BaseName"); } catch (...) { return; } }

        if (g_registryDetector.Analyze(keyName)) {
            std::wcout << L"[ALERT] Suspicious Registry Access Detected: " << keyName << std::endl;
        }
    }
}

void OnApiCallEvent(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    krabs::schema schema(record, trace_context.schema_locator);
    if (schema.event_id() == 1 || schema.event_id() == 5) { 
        krabs::parser parser(schema);
        try {
            DWORD targetPid = parser.parse<DWORD>(L"TargetProcessId");
            DWORD attackerPid = schema.process_id();
            if (g_currentVictimPid != 0 && targetPid == g_currentVictimPid) {

                std::wstring attackerName = L"Unknown(PID:" + std::to_wstring(attackerPid) + L")";
                if (g_accessDetector.IsAccessingVictim(targetPid, attackerName)) {
                    std::wcout << L"[ALERT] Suspicious Process Access from " << attackerName << std::endl;
                }
            }
        }
        catch (...) {}
    }
}

void OnFileIoEvent(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    krabs::schema schema(record, trace_context.schema_locator);
    if (schema.event_opcode() == 0 || schema.event_opcode() == 64) {
        krabs::parser parser(schema);
        std::wstring fileName;
        try { fileName = parser.parse<std::wstring>(L"FileName"); }
        catch (...) { try { fileName = parser.parse<std::wstring>(L"OpenPath"); } catch (...) { return; } }

        if (g_fileDetector.Analyze(fileName)) {
            std::wcout << L"[ALERT] Sensitive File Accessed: " << fileName << std::endl;
        }
    }
}

int main() {

    std::wstring victimName = L"bsass.exe";
    g_currentVictimPid = ProcessFinder::FindPidByName(victimName);
    if (g_currentVictimPid != 0) g_accessDetector.SetVictimPid(g_currentVictimPid);

    std::cout << "[*] Starting EDR Agent (Reg + Process)..." << std::endl;

    krabs::kernel_trace kTrace(L"MyEDR_Kernel_Trace");


    krabs::user_trace uTrace(L"MyEDR_Api_Trace");
    krabs::provider<> pApi(AuditApiCallsGuid);
    pApi.add_on_event_callback(OnApiCallEvent);
    uTrace.enable(pApi);

    krabs::kernel_provider pFile(EVENT_TRACE_FLAG_FILE_IO_INIT, krabs::guids::file_io);
    pFile.add_on_event_callback(OnFileIoEvent);
    kTrace.enable(pFile);

    std::thread kThread([&]() { kTrace.start(); });
    std::thread uThread([&]() { uTrace.start(); });

    kThread.join();
    uThread.join();
    return 0;
}