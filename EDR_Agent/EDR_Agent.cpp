#include <iostream>
#include <windows.h>

int main() {
    std::cout << "[*] BOMBE EDR Agent Starting..." << std::endl;
    std::cout << "[*] Initializing Kernel Trace..." << std::endl;

    std::cout << "[*] Agent running. Press Ctrl+C to stop." << std::endl;
    while (true) {
        Sleep(1000);
    }
    return 0;
}