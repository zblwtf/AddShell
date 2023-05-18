#pragma once
extern "C" __declspec(dllexport) unsigned int process_hollowing(void* pe_base, PPROCESS_INFORMATION pi);
extern "C" __declspec(dllexport) unsigned int load_pe(unsigned long pe_base, unsigned long pe_size, unsigned long new_image_base);