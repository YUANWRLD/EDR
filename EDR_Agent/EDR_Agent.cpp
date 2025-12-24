#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iostream>
#include <string>
#include <vector>

#include "krabs/krabs.hpp"

#include "RegistryDetector.h"

RegistryDetector g_registryDetector;

void OnRegistryEvent(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    krabs::schema schema(record, trace_context.schema_locator);

    int opcode = schema.event_opcode();
    if (opcode == 10 || opcode == 11 || opcode == 16 || opcode == 22) {
        krabs::parser parser(schema);
        std::wstring keyName;

        try {
            keyName = parser.parse<std::wstring>(L"KeyName");
        }
        catch (...) {
            try { keyName = parser.parse<std::wstring>(L"BaseName"); }
            catch (...) { return; }
        }

        if (keyName.empty()) return;

        if (g_registryDetector.Analyze(keyName)) {
            DWORD pid = schema.process_id();
            std::wcout << L"[ALERT] Suspicious Registry Access Detected!" << std::endl;
            std::wcout << L"    [-] PID: " << pid << std::endl;
            std::wcout << L"    [-] Key: " << keyName << std::endl;
        }
    }
}

int main() {
    std::cout << "[*] BOMBE EDR Agent v0.1 (Registry Monitor)" << std::endl;

    krabs::kernel_trace kTrace(L"MyEDR_Kernel_Trace");

    krabs::kernel_provider pRegistry(EVENT_TRACE_FLAG_REGISTRY, krabs::guids::registry);
    pRegistry.add_on_event_callback(OnRegistryEvent);
    kTrace.enable(pRegistry);

    std::cout << "[*] Listening for registry events..." << std::endl;
    try {
        kTrace.start();
    }
    catch (const std::exception& e) {
        std::cerr << "[!] Error: " << e.what() << std::endl;
        std::cerr << "[!] Note: Please run as Administrator." << std::endl;
    }

    return 0;
}