// Remote process IAT parser
// Date: 2021-11-20

#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <winternl.h>
#include <psapi.h>
#include <string>
#include <format>

// =========================================================

DWORD Get_Process_ID(const wchar_t* Process_Name);
INT64 get_remote_process_base_address(int pid);
BOOL IAT_Parser(HANDLE hproc, INT64 remote_base_address);

// =========================================================

BOOL IAT_Parser(HANDLE hproc, INT64 remote_base_address) {

	// Read the PE
	auto file_runtime_base_address = (LPCVOID)remote_base_address;
	auto pe_file_bytes = new BYTE[1024];

	if (!ReadProcessMemory(hproc, file_runtime_base_address, pe_file_bytes, 1024, 0)) {
		std::cout << "[-] ReadProcessMemory(): " << GetLastError() << "\n";
		return 0;
	}

	// std::cout << std::format("Remote PE base address: {:#x} \n", file_runtime_base_address);


	// Start Parsing
	PIMAGE_DOS_HEADER file_dos_header = (PIMAGE_DOS_HEADER)pe_file_bytes;
	PIMAGE_NT_HEADERS file_nt_header = (PIMAGE_NT_HEADERS)((DWORD_PTR)pe_file_bytes + file_dos_header->e_lfanew);

	// Get the first import directory/table address
	IMAGE_DATA_DIRECTORY imports_directory = file_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	auto imports_directory_address = (INT64)file_runtime_base_address + imports_directory.VirtualAddress;


	PIMAGE_IMPORT_DESCRIPTOR imports_directory_entires = new IMAGE_IMPORT_DESCRIPTOR[imports_directory.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR)];
	ReadProcessMemory(hproc, (LPCVOID)imports_directory_address, imports_directory_entires, imports_directory.Size, 0);

	// Read the first IAT entery
	IMAGE_IMPORT_DESCRIPTOR imports_directory_entery = imports_directory_entires[0];

	auto library_name = new char[MAX_PATH];
	auto library_name_address = (DWORD_PTR)file_runtime_base_address + (DWORD_PTR)imports_directory_entery.Name;
	if (!ReadProcessMemory(hproc, (LPCVOID)(library_name_address), library_name, MAX_PATH, 0)) {
		std::cout << "[-] ReadProcessMemory(): " << GetLastError() << "\n";
		return 0;

	}


	// Loop over the import directories (DLLs)
	int i = 0;
	int n = (imports_directory.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR)) - 1;
	while (i < n) {

		std::cout << std::format("============= DLL: {} =============\n\n", library_name);

		// Loop of the imports enteries (functions) thunks

		// original_first_thunk --> Pointer to the first element in Import Name Table (Strucutres of `original_first_thunk->u1.AddressOfData`)
		auto original_first_thunk_address = (DWORD_PTR)file_runtime_base_address + imports_directory_entery.OriginalFirstThunk;
		PIMAGE_THUNK_DATA original_first_thunk = new IMAGE_THUNK_DATA[sizeof(IMAGE_THUNK_DATA)];

		// first_thunk --> Pointer to the first element in Import Address Table (Strcutures of first_thunk->u1.Function)
		auto first_thunk_address = (DWORD_PTR)file_runtime_base_address + imports_directory_entery.FirstThunk;
		PIMAGE_THUNK_DATA first_thunk = new IMAGE_THUNK_DATA[sizeof(IMAGE_THUNK_DATA)];

		ReadProcessMemory(hproc, (LPCVOID)original_first_thunk_address, original_first_thunk, sizeof(IMAGE_THUNK_DATA), 0);
		ReadProcessMemory(hproc, (LPCVOID)first_thunk_address, first_thunk, sizeof(IMAGE_THUNK_DATA), 0);

		while (original_first_thunk->u1.AddressOfData != NULL) {

			// For function name	
			PIMAGE_IMPORT_BY_NAME functionName = new IMAGE_IMPORT_BY_NAME[1024];
			ReadProcessMemory(hproc, (LPCVOID)((INT64)file_runtime_base_address + original_first_thunk->u1.AddressOfData), functionName, 1024, 0);

			std::cout << std::format("{}:  {:#x}\n", functionName->Name, first_thunk->u1.Function);

			//original_first_thunk++;
			original_first_thunk_address = original_first_thunk_address + sizeof(IMAGE_THUNK_DATA);
			ReadProcessMemory(hproc, (LPCVOID)original_first_thunk_address, original_first_thunk, sizeof(IMAGE_THUNK_DATA), 0);

			//first_thunk++;
			first_thunk_address = (DWORD_PTR)first_thunk_address + sizeof(IMAGE_THUNK_DATA);
			ReadProcessMemory(hproc, (LPCVOID)first_thunk_address, first_thunk, sizeof(IMAGE_THUNK_DATA), 0);

		}

		std::cout << "\n==========================================================================\n\n";

		// Go to the next libaray in the import directory
		i++;
		imports_directory_entery = imports_directory_entires[i];

		// Read the next DLL
		auto library_name_address = (DWORD_PTR)file_runtime_base_address + (DWORD_PTR)imports_directory_entery.Name;
		ReadProcessMemory(hproc, (LPCVOID)(library_name_address), library_name, MAX_PATH, 0);

	}

	std::cout << "[+] Done" << "\n";
	return 1;
}



INT64 get_remote_process_base_address(int pid) {

	auto hproc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

	if (hproc == NULL) {
		std::cout << "[-] OpenProcss(): " << GetLastError() << "\n";
		return 0;
	}

	HMODULE lphModule[1024]{ 0 };
	DWORD lpcbNeeded{ 0 };

	if (!EnumProcessModules(hproc, lphModule, sizeof(lphModule), &lpcbNeeded)) {

		std::cout << "[-] EnumProcessModules(): " << GetLastError() << "\n";
		return 0;

	}
	CloseHandle(hproc);

	// lphModule[0] --> The Executable module 
	return (INT64)lphModule[0];

}


DWORD Get_Process_ID(const wchar_t* Process_Name) {

	// Take snapshot of all active proceses
	DWORD process_id = 0;
	auto hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnapshot != INVALID_HANDLE_VALUE) {

		PROCESSENTRY32 pe;
		pe.dwSize = sizeof(pe);

		// Returns the procceses info for the first proccess in `hSnapshot` in `pe` struct
		if (Process32First(hSnapshot, &pe)) {

			// Process32Next(): Retrieves information about the next process recorded in a system snapshot
			// Print the proccess info while (::Process32Next(hSnapshot, &pe)) retturn TRUE;
			// Each return contians info about a proccess stored in `pe` struct
			do {

				// if the process name == `Process_Name` argument, then get the id and break
				if (!std::wcscmp(pe.szExeFile, Process_Name)) {

					process_id = pe.th32ProcessID;
					break;
				}

			} while (Process32Next(hSnapshot, &pe));
		}

		// After it finish, close the hSnapshot handel and reuturn
		::CloseHandle(hSnapshot);
		return process_id;
	}
}


int wmain(int argc, wchar_t* argv[])
{

	if (argc < 2) {
		std::wcerr << "Usage: " << argv[0] << " <process name> \n";
		return 0;
	}

	auto pname = argv[1];

	auto pid = Get_Process_ID(pname);
	auto hproc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

	if (hproc == NULL) {
		std::cout << "[-] OpenProcss(): " << GetLastError() << "\n";
		return 0;
	}

	auto remote_base_Address = get_remote_process_base_address(pid);

	IAT_Parser(hproc, remote_base_Address);


	return 0;
}