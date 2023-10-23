#include <phnt.h>
#include <tlhelp32.h>

#include <print>
#include <string>

#define TO_LOWER_WCHAR(c) ((c >= L'A' && c <= L'Z') ? (c + 32) : c)

__declspec(noinline, safebuffers) uint32_t Shellcode(void* p_thread_parameter) {
    PEB* p_peb = NtCurrentTeb()->ProcessEnvironmentBlock;

    // Loop through loaded modules.
    for (LIST_ENTRY* p_list_entry = p_peb->Ldr->InLoadOrderModuleList.Flink;
         reinterpret_cast<uint64_t>(p_list_entry) != reinterpret_cast<uint64_t>(p_peb->Ldr) + 0x10;
         p_list_entry = p_list_entry->Flink) {
        auto* p_entry = reinterpret_cast<LDR_DATA_TABLE_ENTRY*>(p_list_entry);

        // Compare the module names, case-insensitive.
        const wchar_t* w_module_name = p_entry->BaseDllName.Buffer;
        if (TO_LOWER_WCHAR(w_module_name[0]) == L'k' && TO_LOWER_WCHAR(w_module_name[1]) == L'e' &&
            TO_LOWER_WCHAR(w_module_name[2]) == L'r' && TO_LOWER_WCHAR(w_module_name[3]) == L'n' &&
            TO_LOWER_WCHAR(w_module_name[4]) == L'e' && TO_LOWER_WCHAR(w_module_name[5]) == L'l' &&
            TO_LOWER_WCHAR(w_module_name[6]) == L'3' && TO_LOWER_WCHAR(w_module_name[7]) == L'2' &&
            TO_LOWER_WCHAR(w_module_name[8]) == L'.' && TO_LOWER_WCHAR(w_module_name[9]) == L'd' &&
            TO_LOWER_WCHAR(w_module_name[10]) == L'l' && TO_LOWER_WCHAR(w_module_name[11]) == L'l' &&
            TO_LOWER_WCHAR(w_module_name[12]) == L'\0') {
            auto module_address = reinterpret_cast<uint64_t>(p_entry->DllBase);

            decltype(LoadLibraryA)* p_LoadLibraryA = nullptr;
            decltype(FreeLibrary)* p_FreeLibrary = nullptr;
            decltype(GetModuleHandleA)* p_GetModuleHandleA = nullptr;

            // Now that we have the module address, find the exports we need.
            auto* p_dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(module_address);
            auto* p_nt_header = reinterpret_cast<IMAGE_NT_HEADERS*>(module_address + p_dos_header->e_lfanew);

            auto* p_export_directory = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
                module_address +
                p_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

            // Function and name array both store offsets from the module base.
            auto* function_array = reinterpret_cast<uint32_t*>(module_address + p_export_directory->AddressOfFunctions);
            auto* name_array = reinterpret_cast<uint32_t*>(module_address + p_export_directory->AddressOfNames);
            // Holds both values that are used to index into the function array, and calculate the ordinal.
            auto* entry_index_array =
                reinterpret_cast<uint16_t*>(module_address + p_export_directory->AddressOfNameOrdinals);

            for (uint32_t i = 0; i < p_export_directory->NumberOfFunctions; ++i) {
                if (i >= p_export_directory->NumberOfNames) {
                    break;
                }
                // Get Function rva by indexing with the entry array index.
                uint32_t function_rva = function_array[entry_index_array[i]];

                // Get starting address of name.
                const char* export_name = reinterpret_cast<const char*>(module_address + name_array[i]);

                if (export_name[0] == 'L' && export_name[1] == 'o' && export_name[2] == 'a' && export_name[3] == 'd' &&
                    export_name[4] == 'L' && export_name[5] == 'i' && export_name[6] == 'b' && export_name[7] == 'r' &&
                    export_name[8] == 'a' && export_name[9] == 'r' && export_name[10] == 'y' &&
                    export_name[11] == 'A' && export_name[12] == '\0') {
                    p_LoadLibraryA = reinterpret_cast<decltype(LoadLibraryA)*>(module_address + function_rva);
                }
                if (export_name[0] == 'F' && export_name[1] == 'r' && export_name[2] == 'e' && export_name[3] == 'e' &&
                    export_name[4] == 'L' && export_name[5] == 'i' && export_name[6] == 'b' && export_name[7] == 'r' &&
                    export_name[8] == 'a' && export_name[9] == 'r' && export_name[10] == 'y' &&
                    export_name[11] == '\0') {
                    p_FreeLibrary = reinterpret_cast<decltype(FreeLibrary)*>(module_address + function_rva);
                }
                if (export_name[0] == 'G' && export_name[1] == 'e' && export_name[2] == 't' && export_name[3] == 'M' &&
                    export_name[4] == 'o' && export_name[5] == 'd' && export_name[6] == 'u' && export_name[7] == 'l' &&
                    export_name[8] == 'e' && export_name[9] == 'H' && export_name[10] == 'a' &&
                    export_name[11] == 'n' && export_name[12] == 'd' && export_name[13] == 'l' &&
                    export_name[14] == 'e' && export_name[15] == 'A' && export_name[16] == '\0') {
                    p_GetModuleHandleA = reinterpret_cast<decltype(GetModuleHandleA)*>(module_address + function_rva);
                }

                // If all the exports are found then we can do what we need to do.
                if (p_LoadLibraryA != nullptr && p_FreeLibrary != nullptr && p_GetModuleHandleA != nullptr) {
                    // If the library is already loaded, free it.
                    HMODULE h_module = p_GetModuleHandleA(reinterpret_cast<const char*>(p_thread_parameter) + 1);
                    if (h_module != nullptr) {
                        p_FreeLibrary(h_module);
                    }
                    if (reinterpret_cast<const char*>(p_thread_parameter)[0] == 'l') {
                        // Load the library.
                        p_LoadLibraryA(reinterpret_cast<const char*>(p_thread_parameter) + 1);
                    }
                    break;
                }
            }
            break;
        }
    }
    return 0;
}

int WinMain(HINSTANCE /* h_instance */, HINSTANCE /* h_prev_instance */, LPSTR cmd_line, int /* show_cmd */) {
    if (!AttachConsole(ATTACH_PARENT_PROCESS)) {
        AllocConsole();
    }
    FILE* p_stream;
    freopen_s(&p_stream, "conin$", "r", stdin);
    freopen_s(&p_stream, "conout$", "w", stdout);
    freopen_s(&p_stream, "conout$", "w", stderr);
    std::print("\n -= loadlibrary-ex.exe =- \n");

    // Parse command line args.
    char* command_line_a = GetCommandLineA();
    std::string_view command_line(command_line_a);

    bool free_only = false;
    if (command_line.find(" -free") != std::string::npos) {
        free_only = true;
    }
    size_t file_off = command_line.rfind(" -");
    if (file_off == std::string::npos) {
        std::print("Use format in order, \"[-free] -process.exe -dll.dll\".\n");
        return -1;
    }
    size_t process_off = command_line.rfind(" -", file_off - 2);
    if (process_off == std::string::npos) {
        std::print("Use format in order, \"[-free] -process.exe -dll.dll\".\n");
        return -1;
    }

    std::string process(command_line.substr(process_off + 2, file_off - process_off - 2));
    std::string file(command_line.substr(file_off + 2));
    if (!process.ends_with(".exe") || !file.ends_with(".dll")) {
        std::print("Include file extension, \"[-free] -process.exe -dll.dll\".\n");
        return -1;
    }

    // Verify the dll exists and get the full file path.
    HANDLE h_file = CreateFileA(file.c_str(), GENERIC_READ | GENERIC_EXECUTE, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h_file == INVALID_HANDLE_VALUE) {
        std::print("Error getting handle to file, {} with code {}.\n", file, GetLastError());
        return -1;
    }
    CloseHandle(h_file);
    char arg_and_full_path[MAX_PATH];
    if (free_only) {
        arg_and_full_path[0] = 'f';
    } else {
        arg_and_full_path[0] = 'l';
    }
    if (GetFullPathNameA(file.c_str(), MAX_PATH, arg_and_full_path + 1, nullptr) == 0) {
        std::print("Error getting full path of, {} with code {}.\n", file, GetLastError());
        return -1;
    }

    // Get HANDLE to the remote process.
    uint32_t pid = 0;
    HANDLE h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (h_snapshot == INVALID_HANDLE_VALUE) {
        std::print("Error getting snapshot with code {}.\n", GetLastError());
        return -1;
    }
    PROCESSENTRY32 process_entry;
    process_entry.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(h_snapshot, &process_entry)) {
        do {
            if (process == process_entry.szExeFile) {
                pid = process_entry.th32ProcessID;
                break;
            }
        } while (Process32Next(h_snapshot, &process_entry));
    }
    CloseHandle(h_snapshot);
    if (pid == 0) {
        std::print("Unable to find process, {}.\n", process);
        return -1;
    }

    // Inject LoadLibrary call shellcode into the process.
    HANDLE h_process = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
    if (h_process == INVALID_HANDLE_VALUE) {
        std::print("Unable to get handle to process, {} with pid, {}, and code {}.\n", process, pid, GetLastError());
        return -1;
    }
    void* shellcode_ex = VirtualAllocEx(h_process, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    void* buffer_ex = VirtualAllocEx(h_process, nullptr, 512, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (shellcode_ex == nullptr || buffer_ex == nullptr) {
        std::print("Allocation failed with code {}.\n", GetLastError());
        VirtualFreeEx(h_process, shellcode_ex, 0, MEM_RELEASE);
        VirtualFreeEx(h_process, buffer_ex, 0, MEM_RELEASE);
        CloseHandle(h_process);
        return -1;
    }
    if (!WriteProcessMemory(h_process, shellcode_ex, reinterpret_cast<void*>(Shellcode), 0x1000, nullptr) ||
        !WriteProcessMemory(h_process, buffer_ex, arg_and_full_path, MAX_PATH, nullptr)) {
        std::print("Failed to write shellcode buffers with code {}.\n", GetLastError());
        VirtualFreeEx(h_process, shellcode_ex, 0, MEM_RELEASE);
        VirtualFreeEx(h_process, buffer_ex, 0, MEM_RELEASE);
        CloseHandle(h_process);
        return -1;
    }

    // Create the remote thread.
    HANDLE h_thread = CreateRemoteThread(h_process, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(shellcode_ex),
                                         buffer_ex, 0, nullptr);
    if (h_thread == INVALID_HANDLE_VALUE) {
        std::print("Failed to create thread with code {}.\n", GetLastError());
        VirtualFreeEx(h_process, shellcode_ex, 0, MEM_RELEASE);
        VirtualFreeEx(h_process, buffer_ex, 0, MEM_RELEASE);
        CloseHandle(h_process);
    }

    CloseHandle(h_thread);
    CloseHandle(h_process);

    std::print("Success! Allocated and executed the shellcode!\n");

    return 0;
}