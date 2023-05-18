// AddShell.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <memory>
#include <fstream>
#include "pe_module.h"
#include <compressapi.h>
#include <stdio.h>
#pragma comment(lib,"Cabinet.lib")
using namespace std;
typedef typename PIMAGE_SECTION_HEADER psection;
typedef typename PIMAGE_NT_HEADERS pNt;
typedef typename PIMAGE_DOS_HEADER pDos;
typedef typename unsigned long uint32_ptr;
typedef typename unsigned int uint32_t;
int main(int argc,char** args)
{
	enum 
	{ shellcodesize = 3468,
		tempheadersize=0x400,
		ImpSize = 0x10000,
		EntryOffset = 0x76A,
		numbersection=0x4,
		FileAlignment=0x200,
		SectionAlignment=0x1000
	};
	extern unsigned char shellcode_data[shellcodesize];
	extern unsigned char temp_headers[tempheadersize];

	
	std::string path_module;
	std::string path_out;
	std::ifstream is;
	std::ofstream os;
	while (true)
	{
		cout << "[+] path_module:";
		cin >> path_module;
		is.open(path_module, ios_base::binary);
		if (!is.is_open())
		{
			cout << "[-] open module failed!" << std::endl;
			continue;
		}
		is.close();
		cout << "[-] path_out:";
		cin >> path_out;
		os.open(path_out, ios_base::binary);
		if (os.is_open())
			break;
	}
	pe_module module(path_module);
	uint32_t dwError = 0;
	BOOL bres;
	SIZE_T compressdatasize;
	SIZE_T decompressdatasize;
	COMPRESSOR_HANDLE hCompressor = NULL;
	DECOMPRESSOR_HANDLE hDecompressor = NULL;
	uint32_ptr startime;

	uint32_t dwValueA;
	uint32_t dwValueB;
	uint32_ptr uiValueB;

	std::unique_ptr<char> uq_ptr_compressed;
	std::unique_ptr<char> uq_ptr_tempheaders;
	
	//undefined x64 archive
	if (module.b64)
		return 0;
	//copy header
	
	dwValueA = module.lpNtHdr32->OptionalHeader.SizeOfHeaders;
	uq_ptr_tempheaders.reset(new char[dwValueA]);
	memcpy(uq_ptr_tempheaders.get(), temp_headers,dwValueA);
	//uiValueA = &SectionHeader uiValueB = &NumberOfSections
	pDos lpDosHdr = (pDos)uq_ptr_tempheaders.get();
	pNt lpNtHdr = (pNt)((uint32_ptr)lpDosHdr + lpDosHdr->e_lfanew);
	psection lpSecHdr = reinterpret_cast<psection>((uint32_ptr)&lpNtHdr->OptionalHeader + (uint32_ptr)lpNtHdr->FileHeader.SizeOfOptionalHeader);
	lpNtHdr->FileHeader.NumberOfSections = 4;

	lpSecHdr[numbersection-numbersection].Misc.VirtualSize = module.size_image;
	strcpy((char*)lpSecHdr[numbersection - numbersection].Name, ".text");
	lpSecHdr[numbersection - numbersection].Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
	lpSecHdr[numbersection - numbersection].VirtualAddress = module.lpSecHdr[0].VirtualAddress;
	lpSecHdr[numbersection - numbersection].SizeOfRawData = 0;
	lpSecHdr[numbersection - numbersection].PointerToRawData = 0;

#pragma region Compress
	bres = CreateCompressor(COMPRESS_ALGORITHM_MSZIP, NULL, &hCompressor);
	dwError = GetLastError();
	//Query compressed buffer size;

	bres = Compress(hCompressor, module.get_data().data(), module.get_size(), NULL, NULL, &compressdatasize);

	dwError = GetLastError();
	startime = GetTickCount64();

	uq_ptr_compressed.reset(new char[compressdatasize]);

	bres = Compress(hCompressor, module.get_data().data(), module.get_size(), uq_ptr_compressed.get(), compressdatasize, &compressdatasize);
	dwError = GetLastError();

#pragma endregion

	strcpy((char*)lpSecHdr[numbersection - 3].Name, ".comp");
	lpSecHdr[numbersection-3].Misc.VirtualSize =  compressdatasize + SectionAlignment -(compressdatasize % SectionAlignment);
	lpSecHdr[numbersection -3].VirtualAddress = lpSecHdr[numbersection - 4].VirtualAddress + lpSecHdr[numbersection - 4].Misc.VirtualSize;
	lpSecHdr[numbersection -3].SizeOfRawData = compressdatasize + FileAlignment - (compressdatasize % FileAlignment);
	lpSecHdr[numbersection -3].PointerToRawData = lpNtHdr->OptionalHeader.SizeOfHeaders;
	lpSecHdr[numbersection -3].PointerToRelocations = compressdatasize;
	lpSecHdr[numbersection -3].Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

	strcpy((char*)lpSecHdr[numbersection - 2].Name, ".code");
	lpSecHdr[numbersection - 2].Misc.VirtualSize = shellcodesize + SectionAlignment -(shellcodesize% SectionAlignment);
	lpSecHdr[numbersection - 2].VirtualAddress = lpSecHdr[numbersection - 3].VirtualAddress + lpSecHdr[numbersection - 3].Misc.VirtualSize;
	lpSecHdr[numbersection - 2].PointerToRawData = lpSecHdr[numbersection - 3].PointerToRawData + lpSecHdr[numbersection - 3].SizeOfRawData;
	lpSecHdr[numbersection - 2].SizeOfRawData = shellcodesize + FileAlignment - (shellcodesize%FileAlignment);
	lpSecHdr[numbersection - 2].Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ;

	strcpy((char*)lpSecHdr[numbersection - 1].Name, ".imp");
    lpSecHdr[numbersection - 1].Misc.VirtualSize = ImpSize + SectionAlignment - (ImpSize % SectionAlignment);
	lpSecHdr[numbersection - 1].VirtualAddress = lpSecHdr[numbersection - 2].VirtualAddress + lpSecHdr[numbersection - 2].Misc.VirtualSize;
	lpSecHdr[numbersection - 1].PointerToRawData = lpSecHdr[numbersection - 2].PointerToRawData + lpSecHdr[numbersection - 2].SizeOfRawData;
	lpSecHdr[numbersection - 1].SizeOfRawData = 0;
	lpSecHdr[numbersection - 1].Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ;

	

	pDos lpDosHdr_temp =  reinterpret_cast<pDos>(uq_ptr_tempheaders.get());
	pNt lpNtHdr_temp = reinterpret_cast<pNt>(reinterpret_cast<uint32_ptr>(lpDosHdr_temp) + lpDosHdr_temp->e_lfanew);
	PIMAGE_DATA_DIRECTORY ptr_dir = lpNtHdr_temp->OptionalHeader.DataDirectory;
	for (int i = 0; i < 14; i++)
	{
		memset(&ptr_dir[i], 0, 8);
	}
	lpNtHdr_temp->OptionalHeader.SizeOfImage = lpSecHdr[numbersection - 1].VirtualAddress + lpSecHdr[numbersection - 1].Misc.VirtualSize;
	lpNtHdr_temp->OptionalHeader.AddressOfEntryPoint = lpSecHdr[numbersection - 2].VirtualAddress + EntryOffset;
	os.write(uq_ptr_tempheaders.get(), module.lpNtHdr32->OptionalHeader.SizeOfHeaders);
	os.write(uq_ptr_compressed.get(), compressdatasize);
	uint32_t counter = 0x200 - (compressdatasize % 0x200);
	while(counter--)
		os.put(0);
	os.write((char*)shellcode_data, shellcodesize);
	os.close();

	return 0;

}
