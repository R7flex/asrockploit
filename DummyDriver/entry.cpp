#include <Ntddk.h>
#include <intrin.h>
#include <ntimage.h>

typedef unsigned short     uint16_t;

#define printf(text, ...) (DbgPrintEx(0, 0, (text), ##__VA_ARGS__))

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

__int64 __declspec(dllexport) __fastcall MyIRPControl(struct _DEVICE_OBJECT* a1, IRP* a2) {
    my_irp_struct* buf = (my_irp_struct*)a2->AssociatedIrp.SystemBuffer;

    void* some_memory = buf->nt_ExAllocatePoolWithTag(NonPagedPoolExecute, buf->payload_size, (ULONG)"r7f3");
    buf->my_driver = some_memory;
    buf->nt_memcpy(some_memory, buf->payload, buf->payload_size);

    PIMAGE_DOS_HEADER image = (PIMAGE_DOS_HEADER)some_memory;
    PIMAGE_NT_HEADERS fileHeader = (PIMAGE_NT_HEADERS)((uintptr_t)some_memory + image->e_lfanew);

    IMAGE_DATA_DIRECTORY* reloc_directory_info = (IMAGE_DATA_DIRECTORY*)&fileHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    IMAGE_BASE_RELOCATION* cur_reloc = (IMAGE_BASE_RELOCATION*)((uintptr_t)some_memory + reloc_directory_info->VirtualAddress);
    void* reloc_table_end = (void*)((uintptr_t)cur_reloc + reloc_directory_info->Size);

    uintptr_t imageBaseDifference = (uintptr_t)some_memory - fileHeader->OptionalHeader.ImageBase;

    while (cur_reloc != reloc_table_end) {
        ULONG size_of_block = cur_reloc->SizeOfBlock;
        ULONG rva = cur_reloc->VirtualAddress;

        int num_entries = (size_of_block - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(__int16);

        uint16_t* reloc_entry = (uint16_t*)((uintptr_t)cur_reloc + sizeof(IMAGE_BASE_RELOCATION));
        for (int i = 0; i < num_entries; i++) {
            uint16_t offset = *reloc_entry & 0xFFF;
            USHORT reloc_type = *reloc_entry >> 12;

            if (reloc_type == IMAGE_REL_BASED_DIR64) {
                ULONG64* reloc_spot = (ULONG64*)((uintptr_t)some_memory + rva + offset);
                *reloc_spot += imageBaseDifference;
            }
            else if (reloc_type == IMAGE_REL_BASED_ABSOLUTE) {
            }
            else {
            }
            reloc_entry++;
        }
        cur_reloc = (IMAGE_BASE_RELOCATION*)((uintptr_t)cur_reloc + cur_reloc->SizeOfBlock);
    }

    HANDLE hThread;

    void* start_addr = (void*)((uintptr_t)some_memory + 0x1000);
    buf->nt_PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, (PKSTART_ROUTINE)start_addr, buf);

    ((void (*)(PIRP, CCHAR))buf->nt_IofCompleteRequest)(a2, 0);
    return 0;
}

_Use_decl_annotations_ NTSTATUS DriverEntry(my_irp_struct* info) {
    printf("r7flex has been spawned!\n");

    return STATUS_SUCCESS;
}