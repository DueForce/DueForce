
#include "MyPinTool.h"

FILE* dep;
fstream trace_file("./trace.txt", ios::out);
WINDOWS::DWORD startTime;

INT32 Usage()
{
	cerr << "Ex 3" << endl;
	return -1;
}

VOID Fini(INT32 code, VOID* v) {
	fclose(dep);
	stap_file.close();
	trace_file.close();

	startTime = 0;
	WINDOWS::WaitForSingleObject(hThread, INFINITE);
	// WINDOWS::CloseHandle(hThread);
	cout << ">>>>>>>>>>>>>>END PINTOOL<<<<<<<<<<<" << endl;
	//stdout_file.close();

	//fprintf(mem_file, "#eof\n");
	//fclose(mem_file);
}

static REG GetScratchReg(UINT32 index)
{
	static vector<REG> regs;

	while (index >= regs.size())
	{
		REG reg = PIN_ClaimToolRegister();
		if (reg == REG_INVALID())
		{
			cerr << "*** Ran out of tool registers" << endl;
			PIN_ExitProcess(1);
			/* does not return */
		}
		regs.push_back(reg);
	}

	return regs[index];
}

static ADDRINT GetMemAddress(ADDRINT ea)
{
	if (ea < PREMEM_SIZE) {
		ea += mmap_base;
	}
	return ea;
}

static ADDRINT GetRealAddress(ADDRINT addr, ADDRINT base, 
	ADDRINT false_branch, ADDRINT true_branch, BOOL target) 
{
	ADDRINT target_branch;
	ADDRINT off = addr - base;

	if (scheme_map.count(off) > 0)
		target = scheme_map[off];

	//fstream trace_file("./trace.txt", ios::out | ios::app);
	//if (!trace_file.is_open())cout << "file!" << endl;
	trace_file << hex << (UINT32)addr << ":";
	//cout << hex << (UINT32)addr << ":(F/T)" << endl;
	if (target) {
		trace_file << "T" << endl;
	}
	else {
		trace_file << "F" << endl;
	}
	//trace_file.close();
	//cout << hex << (UINT32)addr << ":(F/T) DONE" << endl;

	target_branch = target ? true_branch : false_branch;
	return target_branch;
}

map<UINT32, UINT32> img_low;
map<UINT32, UINT32> img_high;
//map<UINT32, string> img_name;
typedef pair<UINT32, UINT32> addr2inst;
set<addr2inst> deps;
map<UINT32, UINT32>memory;

#define BUFF_DEP_PATH "./buff_dep.txt"

// Print a memory read record
VOID RecordMemRead(UINT32 ip, UINT32 mem_addr, UINT32 img_id, UINT32 mem_size)
{
	//UINT32 offset = ip - img_low[img_id];

	//if(IMG_IsMainExecutable(IMG_FindImgById(img_id)))
	//	fprintf(mem_file, "r %x %x %u\n", ip, mem_addr, mem_size);

	for (UINT32 addr = mem_addr; addr < mem_addr + mem_size; addr++) {
		UINT32 use = ip;
		UINT32 define = memory[addr];
		if (!define) continue;

		addr2inst item;
		item.first = use;
		item.second = define;

		if (deps.count(item))continue;
		deps.insert(item);

		fprintf(dep, "%x->%x\n", use, define);
		fflush(dep);
	}
}

// Print a memory write record
VOID RecordMemWrite(UINT32 ip, UINT32 mem_addr, UINT32 img_id, UINT32 mem_size)
{
	//UINT32 offset = ip - img_low[img_id];

	//if (IMG_IsMainExecutable(IMG_FindImgById(img_id)))
	//	fprintf(mem_file, "w %x %x %u\n", ip, mem_addr, mem_size);
	//string iname = img_name[img_id];
	//if (iname.find("test.exe") != string::npos) fprintf(mem_file, "%s_%d: W %p\n", iname.c_str(), offset, addr);
	for (UINT32 addr = mem_addr; addr < mem_addr + mem_size; addr++) {
		memory[addr] = ip;
	}
}

set<ADDRINT> has_insert;

VOID Instruction(INS ins, VOID* v)
{
	// if (WINDOWS::GetTickCount() - startTime > 5000) {
	// 	cout << "[!] FATAL: timeout" << endl;
	// 	PIN_ExitApplication(-1);
	// }
	
	UINT32 addr, next_addr, jump_addr, off;
	REG scratchReg;

	addr = INS_Address(ins);
	if (addr < global_start || addr >= global_end) {
		return;
	}
	off = addr - global_start;
	//cout << hex << "[&] " << addr << endl;
	//if (off == 0x1698) {
	//	PIN_Sleep(1000 * 10);
	//	PIN_ExitApplication(-1);
	//}

	for (UINT32 memIndex = 0; memIndex < INS_MemoryOperandCount(ins); memIndex++) {
		scratchReg = GetScratchReg(memIndex);
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)GetMemAddress,
			IARG_MEMORYOP_EA, memIndex,
			IARG_RETURN_REGS, scratchReg,
			IARG_END);
		INS_RewriteMemoryOperand(ins, memIndex, scratchReg);
	}

	if (INS_IsBranch(ins) && INS_IsDirectControlFlow(ins)) {
		next_addr = INS_NextAddress(ins);
		jump_addr = INS_DirectControlFlowTargetAddress(ins);

		if (has_insert.count(addr) == 0) {
			scratchReg = GetScratchReg(0);
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)GetRealAddress,
				IARG_ADDRINT, addr,
				IARG_ADDRINT, global_start,
				IARG_ADDRINT, next_addr,
				IARG_ADDRINT, jump_addr,
				IARG_BRANCH_TAKEN,
				IARG_RETURN_REGS, scratchReg,
				IARG_END);
		}

		bool is_force = false;

		if (has_forced.count(off) > 0 &&
			has_forced[off] == false) {
			if (scheme_map.count(off) > 0) {
				cout << hex << "[@] MATCH branch addr: 0x" << addr << endl;
				is_force = true;
				has_forced[off] = true;
			}
		}

		if (is_force && has_insert.count(addr) == 0) {
			INS_InsertIndirectJump(ins, IPOINT_BEFORE, scratchReg);
			INS_Delete(ins);
		}
		has_insert.insert(addr);
	}

	IMG img = IMG_FindByAddress(addr);
	UINT32 img_id = IMG_Id(img);
	// Instruments memory accesses using a predicated call, i.e.
	// the instrumentation is called iff the instruction will actually be executed.
	//
	// On the IA-32 and Intel(R) 64 architectures conditional moves and REP 
	// prefixed instructions appear as predicated instructions in Pin.
	UINT32 memOperands = INS_MemoryOperandCount(ins);

	// Iterate over each memory operand of the instruction.
	for (UINT32 memOp = 0; memOp < memOperands; memOp++)
	{
		if (INS_MemoryOperandIsRead(ins, memOp))
		{
			INS_InsertPredicatedCall(
				ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead,
				IARG_INST_PTR,
				IARG_MEMORYOP_EA, memOp,
				IARG_UINT32, img_id,
				IARG_MEMORYREAD_SIZE,
				IARG_END);
		}
		// Note that in some architectures a single memory operand can be 
		// both read and written (for instance incl (%eax) on IA-32)
		// In that case we instrument it once for read and once for write.
		if (INS_MemoryOperandIsWritten(ins, memOp))
		{
			INS_InsertPredicatedCall(
				ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite,
				IARG_INST_PTR,
				IARG_MEMORYOP_EA, memOp,
				IARG_UINT32, img_id,
				IARG_MEMORYWRITE_SIZE,
				IARG_END);
		}
	}
}

void PrepareScheme() {
	fstream scheme_file;
	string line, str_addr;

	scheme_file.open("./force.txt", ios_base::in);

	stap_file << hex << "\nforce(";
	while (!scheme_file.eof()) {
		ssize_t pos, addr;

		getline(scheme_file, line);
		if (line.empty())break;
		pos = line.find(":");
		str_addr = line.substr(0, pos);
		addr = stoul(str_addr, nullptr, 16);

		scheme_map[addr & 0xffff] = line[pos+1] == 'T'?1:0;
		has_forced[addr & 0xffff] = false;
		cout << hex << "[*] " << addr << "->" << scheme_map[addr & 0xffff] << endl;
		stap_file << hex << addr << "->" << scheme_map[addr & 0xffff] << "|";
	}
	stap_file << ")" << endl;
	scheme_file.close();
}

VOID DoMmap() {
	UINT32* iter;

	mmap_base = (UINT32)WINDOWS::VirtualAlloc(0,
		PREMEM_SIZE, 
		MEM_COMMIT, 
		PAGE_EXECUTE_READWRITE);
	if (mmap_base == NULL) {
		cerr << hex << "[!] mmap failed: 0x" << mmap_base << endl;
		PIN_ExitProcess(-1);
	}

	cout << hex << "[+] mmap at 0x" << mmap_base << endl;
	for (iter = (UINT32*)mmap_base;
		(UINT32)iter < (mmap_base + PREMEM_SIZE);
		iter++) {
		*iter = mmap_base + rand() % PREMEM_SIZE;
	}

}

VOID AfterAllocate(ADDRINT ret, WINDOWS::DWORD dwBytes)
{
	if (ret_addr == ret || ret >= 0x1000000 ||
		dwBytes > 0x10000 || dwBytes == 0)return;
	ret_addr = ret;

	cout << hex << "[+] Allocate: 0x" << dwBytes
		<< " returns 0x" << ret << endl;
	for (int i = 0; i + 4 < dwBytes; i += 4) {
		*(UINT32*)(ret+i) = mmap_base;
	}
	memset((VOID*)ret, 0, dwBytes);
}

typedef WINDOWS::PVOID(__stdcall* RtlAllocateHeapType) (WINDOWS::PVOID,
	WINDOWS::ULONG,
	WINDOWS::SIZE_T);

void* replacement_RtlAllocateHeap(
	AFUNPTR pfnRtlAllocateHeap,
	WINDOWS::PVOID HeapHandle,
	WINDOWS::ULONG Flags,
	WINDOWS::SIZE_T Size,
	CONTEXT* ctxt) {
	void* result;

	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_STDCALL, pfnRtlAllocateHeap, NULL,
		PIN_PARG(void*), &result,
		PIN_PARG(WINDOWS::PVOID), HeapHandle,
		PIN_PARG(WINDOWS::ULONG), Flags,
		PIN_PARG(WINDOWS::SIZE_T), Size,
		PIN_PARG_END());

	if ((Flags & HEAP_ZERO_MEMORY) == HEAP_ZERO_MEMORY) return result;

	for (WINDOWS::SIZE_T i = 0; i + 4 < Size; i += 4) {
		*(UINT32*)((UINT32)result+i) = mmap_base + rand() % PREMEM_SIZE;
	}
	return result;
}

VOID ImageLoad(IMG img, VOID* v) {
	string fullname = IMG_Name(img);
	string iname = fullname.substr(fullname.rfind('\\') + 1);
	string fmt = iname.substr(iname.rfind('.') + 1);

	//img_name[IMG_Id(img)] = iname;
	img_low[IMG_Id(img)] = IMG_LowAddress(img);
	img_high[IMG_Id(img)] = IMG_HighAddress(img);

	if (IMG_IsMainExecutable(img)) {
		global_start = IMG_StartAddress(img);
		global_end = global_start + IMG_SizeMapped(img);
		cout << hex << "[*] MAIN image load at [" << global_start
			<< ", " << global_end << ")" << endl;

		bool has_mmaped = false;
		for (SEC sec = IMG_SecHead(img); SEC_Valid(sec) && !has_mmaped; sec = SEC_Next(sec)) {
			//cout << hex << "[*] MAIN image SEC: " << SEC_Name(sec) << endl;
			for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn) && !has_mmaped; rtn = RTN_Next(rtn)) {
				//cout << hex << "[*] MAIN image RTN: " << RTN_Name(rtn) << endl;
				if (RTN_Valid(rtn)) {
					cout << "[+] MMAP on rtn: " << RTN_Name(rtn) << endl;
					RTN_Open(rtn);
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)DoMmap, IARG_END);
					RTN_Close(rtn);

					has_mmaped = true;
				}
			}
		}
	}

	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
		for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) {
			if (RTN_Valid(rtn)) {
				auto it = api_map.find(RTN_Name(rtn));
				if (it != api_map.end()) {
					RTN_Open(rtn);
					it->second(rtn);
					RTN_Close(rtn);
				}
			}
		}
	}

	RTN rtn = RTN_FindByName(img, "RtlAllocateHeap");

	if (RTN_Invalid() == rtn) return;

	//cout << "[+] Replacing " << IMG_Name(img) << endl;
	PROTO protoRtlAllocateHeap =
		PROTO_Allocate(PIN_PARG(void*),
			CALLINGSTD_STDCALL,
			"RtlAllocateHeap",
			PIN_PARG(WINDOWS::PVOID), // HeapHandle
			PIN_PARG(WINDOWS::ULONG), // Flags
			PIN_PARG(WINDOWS::SIZE_T), // Size
			PIN_PARG_END());


	RTN_ReplaceSignature(rtn, (AFUNPTR)replacement_RtlAllocateHeap,
		IARG_PROTOTYPE, protoRtlAllocateHeap,
		IARG_ORIG_FUNCPTR,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_CONTEXT,
		IARG_END);

	PROTO_Free(protoRtlAllocateHeap);
}

VOID UndoMmap() {
	WINDOWS::VirtualFree((VOID*)mmap_base, PREMEM_SIZE, MEM_DECOMMIT);
}

VOID ImageUnload(IMG img, VOID* v) {
	//if (IMG_IsMainExecutable(img)) {
	//	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
	//		for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) {
	//			if (RTN_Valid(rtn)) {
	//				cout << hex << "[-] UNMMAP on rtn: " << RTN_Name(rtn) << endl;
	//				RTN_Open(rtn);
	//				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)UndoMmap, IARG_END);
	//				RTN_Close(rtn);

	//				break;
	//			}
	//		}
	//	}
	//}
	return;
}

WINDOWS::DWORD WINAPI ThreadFunction(WINDOWS::LPVOID lpParam)
{
	while (WINDOWS::GetTickCount() - startTime <= 10000) continue;

	cout << "[!] FATAL: timeout" << endl;
	PIN_ExitApplication(-1);
	return 0;
}


VOID init() {
	cout << endl << ">>>>>>>>>>>>>START PINTOOL<<<<<<<<<<" << endl;

	srand(0);

	//mem_file = fopen("mem_file.txt", "w");
	dep = fopen(BUFF_DEP_PATH, "w");

	startTime = WINDOWS::GetTickCount();
	cout << "[*] START time at " << startTime << endl;

	// hThread = WINDOWS::CreateThread(NULL, 0, ThreadFunction, NULL, 0, NULL);

	init_map();
}

int main(int argc, char* argv[]) {
	// cout << "PINTOOL" << endl;
	// return 0;
	init();

	PIN_InitSymbols();
	if (PIN_Init(argc, argv))
	{
		return Usage();
	}
	PrepareScheme();

	IMG_AddInstrumentFunction(ImageLoad, 0);
	IMG_AddUnloadFunction(ImageUnload, 0);

	INS_AddInstrumentFunction(Instruction, 0);

	PIN_AddFiniFunction(Fini, 0);
	PIN_StartProgram();
	return 0;
}
