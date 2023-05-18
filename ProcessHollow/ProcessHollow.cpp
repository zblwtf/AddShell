// process-hollowing.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#pragma comment(lib,"C:\\Users\\23035\\Desktop\\Home\\C++\\AddShell\\Debug\\ProcessHollowing.lib")
extern "C" __declspec(dllimport) unsigned int process_hollowing(void* pe_base, unsigned long pe_size);
extern "C" __declspec(dllimport) unsigned int load_pe(unsigned long pe_base, unsigned long pe_size, unsigned long new_image_base);

int main()
{
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
	HANDLE sourceFile = CreateFileA("C:\\Users\\23035\\Downloads\\ProcessExplorer\\procexp.exe", GENERIC_READ, NULL, NULL, OPEN_ALWAYS, NULL, NULL);
	DWORD sourceFileSize = GetFileSize(sourceFile, NULL);
	LPDWORD fileBytesRead = 0;
	uint32_ptr pe_base = (uint32_ptr)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sourceFileSize);
	ReadFile(sourceFile, (void*)pe_base, sourceFileSize, NULL, NULL);
	p_dos_header ptr_DosHdr = reinterpret_cast<p_dos_header>(pe_base);
	p_nt_header  ptr_NtHdr = reinterpret_cast<p_nt_header>((uint32_ptr)pe_base + ptr_DosHdr->e_lfanew);
	uint32_t size_image = ptr_NtHdr->OptionalHeader.SizeOfImage;
	uint32_ptr image_base = (uint32_ptr)VirtualAlloc(NULL, size_image, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	load_pe(pe_base, 0, image_base);


}


