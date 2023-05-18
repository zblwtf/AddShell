#include <Windows.h>
#include "pe_module.h"
#include <iostream>
#include <fstream>
using namespace std;

pe_module::pe_module(const std::string& path)noexcept :size(0), data(), lpNtHdr32(nullptr),lpNtHdr64(nullptr), lpDosHdr(nullptr), imagebase(0), b64(false), bExe(false), import_dir(), export_dir(), section_number(0), lpSecHdr(nullptr), size_image(0)
{
	uint64_t size = 0;
	ifstream is(path, ios_base::binary);
	is.seekg(0, is.end);
	size = is.tellg();
	this->size = size;
	is.seekg(is.beg);
	this->data.resize(size);
	is.read((char*)this->data.data(), size);

	this->lpDosHdr = static_cast<PIMAGE_DOS_HEADER>((void*)this->data.data());
	this->lpNtHdr32 = reinterpret_cast<PIMAGE_NT_HEADERS32>((ULONG_PTR)lpDosHdr + lpDosHdr->e_lfanew);
	this->b64 = lpNtHdr32->FileHeader.SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER64);

	if (b64)
	{
		this->lpNtHdr64 = reinterpret_cast<PIMAGE_NT_HEADERS64>((ULONG_PTR)lpDosHdr + lpDosHdr->e_lfanew);
		this->imagebase = lpNtHdr64->OptionalHeader.ImageBase;
		this->size_image = lpNtHdr64->OptionalHeader.SizeOfImage;
		this->bExe = lpNtHdr64->FileHeader.Characteristics < 0x2000;
		this->import_dir = lpNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		this->export_dir = lpNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		this->section_number = lpNtHdr64->FileHeader.NumberOfSections;
		this->lpSecHdr = reinterpret_cast<PIMAGE_SECTION_HEADER>((ULONG_PTR)&lpNtHdr64->FileHeader + lpNtHdr64->FileHeader.SizeOfOptionalHeader);
	}
	else 
	{
		this->imagebase = lpNtHdr32->OptionalHeader.ImageBase;
		this->size_image = lpNtHdr32->OptionalHeader.SizeOfImage;
		this->bExe = lpNtHdr32->FileHeader.Characteristics < 0x2000;
		this->import_dir = lpNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		this->export_dir = lpNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		this->section_number = lpNtHdr32->FileHeader.NumberOfSections;
		this->lpSecHdr = reinterpret_cast<PIMAGE_SECTION_HEADER>((ULONG_PTR)&lpNtHdr32->OptionalHeader + lpNtHdr32->FileHeader.SizeOfOptionalHeader);
	}
	
}
pe_module::pe_module(std::string&& path) noexcept :pe_module(path)
{
	
}
pe_module::pe_module(pe_module& module) noexcept :size(module.get_size()), data(module.get_data()),lpNtHdr32(module.lpNtHdr32), lpNtHdr64(module.lpNtHdr64), lpDosHdr(module.lpDosHdr), imagebase(module.imagebase), b64(module.b64), bExe(module.b64), import_dir(module.import_dir), export_dir(module.export_dir), section_number(module.section_number), lpSecHdr(module.lpSecHdr), size_image(module.size_image)
{
}
pe_module::pe_module(pe_module&& module) noexcept :size(module.get_size()), data(), lpNtHdr32(module.lpNtHdr32),lpNtHdr64(module.lpNtHdr64), lpDosHdr(module.lpDosHdr), imagebase(module.imagebase), b64(module.b64), bExe(module.b64), import_dir(module.import_dir), export_dir(module.export_dir), section_number(module.section_number), lpSecHdr(module.lpSecHdr), size_image(module.size_image)
{
	module.lpDosHdr = nullptr;
	module.lpNtHdr32 = nullptr;
	module.lpNtHdr64 = nullptr;
	module.lpSecHdr = nullptr;

	module.imagebase = 0;
	module.size_image = 0;
	module.size = 0;

	vector<uint8_t>& old_data = module.get_data();
	this->data = std::move(old_data);
}

vector<uint8_t>& pe_module::get_data() noexcept
{
	return this->data;
}
std::size_t pe_module::get_size() const noexcept
{
	return this->size;
}
