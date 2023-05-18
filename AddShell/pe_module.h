#pragma once
#include <string>
#include <vector>
#include <Windows.h>
class pe_module
{
public:
	explicit pe_module(const std::string& path) noexcept;
	explicit pe_module(std::string&& path) noexcept;
	explicit pe_module(pe_module& module) noexcept;
	explicit pe_module(pe_module&& module) noexcept;
	~pe_module() {}
	std::vector<uint8_t>& get_data() noexcept;
	std::size_t get_size() const noexcept;
	
	std::size_t size_image;
	uint16_t section_number;
	IMAGE_DATA_DIRECTORY export_dir;
	IMAGE_DATA_DIRECTORY import_dir;


	bool bExe;
	bool b64;
	ULONG_PTR imagebase;
	PIMAGE_DOS_HEADER lpDosHdr;
	PIMAGE_NT_HEADERS64 lpNtHdr64;
	PIMAGE_NT_HEADERS32 lpNtHdr32;
	PIMAGE_SECTION_HEADER lpSecHdr;
private:
	std::vector<uint8_t> data;
	std::size_t size;
	

};