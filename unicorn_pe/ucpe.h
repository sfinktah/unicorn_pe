#pragma once

using api_emu_callback = std::function<bool(uc_engine *uc)>;

using disasm_callback = std::function<bool(cs_insn *inst, uint64_t pAddress, size_t instLen, int instCount)>;

IMAGE_OPTIONAL_HEADER* __fastcall Get_IMAGE_OPTIONAL_HEADER(IMAGE_FILE_HEADER* fheader);
IMAGE_FILE_HEADER* __fastcall Get_IMAGE_FILE_HEADER(IMAGE_DOS_HEADER* ImageBase);

struct s_segment {
    uintptr_t ptr;
    size_t size;
};

typedef struct UCPE_CacheFile_s
{
	ULONG ImageSize;
	ULONG HeapSize;
	ULONG StackSize;
	ULONG RealEntryPoint;
	CONTEXT ContextAtRealEntryPoint;
}UCPE_CacheFile_t;

typedef struct FakeAPI_s
{
	FakeAPI_s(const char *n, uint64_t va) : ProcedureName(n), VirtualAddress(va) {
		EmuCallback = NULL;
	}
	std::string ProcedureName;
	void *EmuCallback;
	uint64_t VirtualAddress;
}FakeAPI_t;

typedef struct FakeSection_s
{
	FakeSection_s(ULONG a, ULONG b, char *c, bool u) : SectionBase(a), SectionSize(b), IsUnknownSection(u){
		memcpy(SectionName, c, 8);
		SectionName[8] = 0;
	}
	ULONG SectionBase;
	ULONG SectionSize;
	CHAR SectionName[9];
	bool IsUnknownSection;
}FakeSection_t;

typedef struct FakeModule_s
{
	FakeModule_s(ULONG64 b, ULONG s, ULONG64 e, const std::wstring &n) : ImageBase(b), ImageSize(s), ImageEntry(e), DllName(n) {
		Priority = 0;
	}
	ULONG64 ImageBase;
	ULONG ImageSize;
	ULONG64 ImageEntry;
	std::wstring DllName;
	std::vector<FakeAPI_t> FakeAPIs;
	std::vector<FakeSection_t> FakeSections;
	int Priority;
	ULONG64 ExceptionTable;
	ULONG ExceptionTableSize;
}FakeModule_t;

typedef struct AllocBlock_s
{
	AllocBlock_s(ULONG64 b, ULONG s) : base(b), size(s) {
		free = false;
	}
	ULONG64 base;
	ULONG size;
	bool free;
}AllocBlock_t;

typedef struct MemMappingBlock_s
{
	MemMappingBlock_s(ULONG64 v, ULONG64 val, ULONG s) : va(v), value(val), size(s) {

	}
	ULONG64 va;
	ULONG64 value;
	ULONG size;
}MemMappingBlock_t;

typedef struct MemMapping_s
{
	MemMapping_s(ULONG64 b, ULONG64 v, ULONG s) : baseva(b), mappedva(v), size(s) {
		
	}
	ULONG64 baseva;
	ULONG64 mappedva;
	ULONG size;
	std::vector<MemMappingBlock_t> blocks;
}MemMapping_t;

class PeEmulation
{
public:
	PeEmulation()
	{
		m_BoundCheck = false;
		m_Disassemble = false;
		m_IsKernel = false;
		m_IsWin64 = true;
		m_IsPacked = false;
		m_Dump = false;
		m_HasCache = false;
		m_Cache = false;
		m_PebBase = 0;
		m_PebEnd = 0;
		m_TebBase = 0;
		m_TebEnd = 0;
		m_Win32LastError = 0;
		m_DriverObjectBase = 0;
		m_RegistryPathBase = 0;
		m_PsLoadedModuleListBase = 0;
		m_DriverLdrEntry = 0;
		m_ExecCodeCount = 0;
		m_LastRip = 0;
		m_LastRipModule = 0;
		m_ExecuteFromRip = 0;
		m_ImageRealEntry = 0;
		m_MainModuleIndex = -1;
		m_LastHeapAllocBytes = 0;
		m_LastException = STATUS_SUCCESS;
		memset(&m_InitReg, 0, sizeof(m_InitReg));
		m_PsInvertedFunctionTable = { 0, MAXIMUM_INVERTED_FUNCTION_TABLE_SIZE, FALSE };

		UCHAR slottable[] = {
			1,          // UWOP_PUSH_NONVOL
			2,          // UWOP_ALLOC_LARGE (or 3, special cased in lookup code)
			1,          // UWOP_ALLOC_SMALL
			1,          // UWOP_SET_FPREG
			2,          // UWOP_SAVE_NONVOL
			3,          // UWOP_SAVE_NONVOL_FAR
			0,          // UWOP_SPARE_CODE1
			0,          // UWOP_SPARE_CODE2
			2,          // UWOP_SAVE_XMM128
			3,          // UWOP_SAVE_XMM128_FAR
			1           // UWOP_PUSH_MACHFRAME
		};
		memcpy(m_RtlpUnwindOpSlotTable, slottable, sizeof(slottable));

		m_ExecuteExceptionHandler = 0;
		m_FakeAPICallEnabled = false;
		m_LastFakeAPICall = NULL;
		m_LastFakeAPICallReturnAddress = 0;
	}

	void InitProcessorState();
	void InitTebPeb();
	void InitCommandLine();
	void InitKTHREAD();
	void InitPsLoadedModuleList();
	void InitDriverObject();
	void InitKSharedUserData();
	void InsertTailList(IN ULONG64 ListHeadAddress, IN ULONG64 EntryAddress);
	void SortModuleList();

	void MapImageToEngine(const std::wstring &ImageName, PVOID ImageBase, ULONG ImageSize, ULONG64 MappedBase, ULONG64 EntryPoint);
	uintptr_t NormaliseBase(ULONG64 address, ULONG64 base = 0x140000000) const;

	bool FindAddressInRegion(ULONG64 address, std::stringstream &RegionName);
	bool OldFindAPIByAddress(ULONG64 address, std::wstring &DllName, FakeAPI_t **api);
	bool FindAPIByAddress(ULONG64 address, std::wstring &DllName, FakeAPI_t **api);
	bool FindSectionByAddress(ULONG64 address, FakeSection_t **section);
	bool FindModuleByAddress(ULONG64 address, ULONG64 &DllBase);
	bool RegisterAPIEmulation(const std::wstring &DllName, const char *ProcedureName, void *callback, int argsCount);
	void AddAPIEmulation(FakeAPI_t *r, void *callback, int argsCount);

	VOID LdrResolveExportTable(FakeModule_t *module, PVOID ImageBase, ULONG64 MappedBase);
	ULONG64 LdrGetProcAddress(ULONG64 ImageBase, const char *ProcedureName);
	NTSTATUS LdrFindDllByName(const std::wstring &DllName, ULONG64 *ImageBase, ULONG *ImageSize, bool LoadIfNotExist);
	NTSTATUS LdrLoadDllByName(const std::wstring &DllName, ULONG64 *ImageBase, ULONG *ImageSize);

	bool RebuildSection(PVOID ImageBase, ULONG ImageSize, virtual_buffer_t &RebuildSectionBuffer);
    bool AlignSectionHeaders(PVOID ImageBase, ULONG ImageSize);

	void DisasmFunction(ULONG64 FunctionBegin, ULONG64 FunctionEnd, const disasm_callback& callback);

    static DWORD RebuildSectionSizes(PVOID ImageBase, ULONG ImageSize);


	ULONG64 HeapAlloc(ULONG Bytes, bool IsPageAlign = false);
	bool HeapFree(ULONG64 FreeAddress);
	bool CreateMemMapping(ULONG64 BaseAddress, ULONG64 MapAddress, ULONG Bytes);
	void DeleteMemMapping(ULONG64 MapAddress);
	bool WriteMemMapping(ULONG64 baseaddress, ULONG64 value, ULONG size);
	void FlushMemMapping(void);

	ULONG64 StackAlloc(ULONG AllocBytes);
	VOID StackFree(ULONG AllocBytes);

	VOID RtlpGetStackLimits(OUT PULONG64 LowLimit, OUT PULONG64 HighLimit);
	VOID RtlpCaptureContext(IN PCONTEXT ContextRecord);
	VOID RtlpRestoreContext(IN PCONTEXT ContextRecord,	IN PEXCEPTION_RECORD ExceptionRecord OPTIONAL);
	BOOLEAN RtlpDispatchException(IN PEXCEPTION_RECORD ExceptionRecord, IN PCONTEXT ContextRecord);
	VOID RtlRaiseStatus(IN NTSTATUS Status);
	NTSTATUS RaiseException(IN PEXCEPTION_RECORD ExceptionRecord, IN PCONTEXT ContextRecord, IN BOOLEAN FirstChance);
	VOID RtlInsertInvertedFunctionTable(
		PINVERTED_FUNCTION_TABLE InvertedTable,
		ULONG64 MappedBase,
		PVOID ImageBase,
		ULONG SizeOfImage
	);
	EXCEPTION_DISPOSITION RtlpExecuteHandlerForException(
		_Inout_ struct _EXCEPTION_RECORD *ExceptionRecord,
		_In_ PVOID EstablisherFrame,
		_Inout_ struct _CONTEXT *ContextRecord,
		_In_ PDISPATCHER_CONTEXT DispatcherContext
	);
	PRUNTIME_FUNCTION RtlpLookupFunctionTable(
		IN PVOID ControlPc,
		OUT PVOID *ImageBase,
		OUT PULONG SizeOfTable
	);
	PRUNTIME_FUNCTION RtlpLookupFunctionEntry(
			IN ULONG64 ControlPc,
			OUT PULONG64 ImageBase,
			IN OUT PUNWIND_HISTORY_TABLE HistoryTable OPTIONAL
		);
	PRUNTIME_FUNCTION RtlpConvertFunctionEntry(
			IN PRUNTIME_FUNCTION FunctionEntry,
			IN ULONG64 ImageBase
		);
	PEXCEPTION_ROUTINE RtlpVirtualUnwind(
		IN ULONG HandlerType,
		IN ULONG64 ImageBase,
		IN ULONG64 ControlPc,
		IN PRUNTIME_FUNCTION FunctionEntry,
		IN OUT PCONTEXT ContextRecord,
		OUT PVOID *HandlerData,
		OUT PULONG64 EstablisherFrame,
		IN OUT PKNONVOLATILE_CONTEXT_POINTERS ContextPointers OPTIONAL
	);
	PRUNTIME_FUNCTION RtlpSameFunction(
		IN PRUNTIME_FUNCTION FunctionEntry,
		IN ULONG64 ImageBase,
		IN ULONG64 ControlPc
	);
	PUNWIND_INFO RtlpLookupPrimaryUnwindInfo(
		IN PRUNTIME_FUNCTION FunctionEntry,
		IN ULONG64 ImageBase,
		OUT PRUNTIME_FUNCTION *PrimaryEntry
	);
	PRUNTIME_FUNCTION RtlpUnwindPrologue(
		IN ULONG64 ImageBase,
		IN ULONG64 ControlPc,
		IN ULONG64 FrameBase,
		IN PRUNTIME_FUNCTION FunctionEntry,
		IN OUT PCONTEXT ContextRecord,
		IN OUT PKNONVOLATILE_CONTEXT_POINTERS ContextPointers OPTIONAL
	);
	EXCEPTION_DISPOSITION C_specific_handler(VOID);
	VOID RtlpUnwindEx(
		IN PVOID TargetFrame OPTIONAL,
		IN PVOID TargetIp OPTIONAL,
		IN PEXCEPTION_RECORD ExceptionRecord OPTIONAL,
		IN PVOID ReturnValue,
		IN PCONTEXT OriginalContext,
		IN PUNWIND_HISTORY_TABLE HistoryTable OPTIONAL
	);
public:
	blackbone::Process thisProc;
	csh m_cs;
	uc_engine *m_uc;
	bool m_IsWin64;
	bool m_IsKernel;
	bool m_Disassemble;
	bool m_DisassembleForce = false;
	bool m_IsPacked;
	bool m_BoundCheck;
	bool m_Dump;
	bool m_Cache;
	bool m_HasCache;
	bool m_FindChecks;
	bool m_Bitmap;
	bool m_Obfu;
	bool m_SkipSecondCall;
	bool m_SkipFourthCall;;
	bool m_PatchRuntime;
	bool m_RebuildImageSize = false;
	bool m_RebuildSectionSizes = false;
	bool m_DisableRebase = false;
	bool m_Sandbox = false;

	uint64_t m_KSharedUserDataBase;
	uint64_t m_KSharedUserDataEnd;
	uint64_t m_StackBase;
	uint64_t m_StackEnd;
	uint64_t m_ImageBase;
	uint64_t m_ImageEnd;
	uint64_t m_ImageEntry;
	uint64_t m_ImageRealEntry;
	uint64_t m_HeapBase;
	uint64_t m_HeapEnd;
	uint64_t m_LoadModuleBase;

	//usermode only
	uint64_t m_PebBase;
	uint64_t m_PebEnd;
	uint64_t m_TebBase;
	uint64_t m_TebEnd;
	uint32_t m_Win32LastError;
	uint64_t m_CommandLineABase;
	uint64_t m_CommandLineWBase;

	//kernelmode only
	uint64_t m_DriverObjectBase;
	uint64_t m_RegistryPathBase;
	uint64_t m_KThreadBase;
	uint64_t m_PsLoadedModuleListBase;
	uint64_t m_DriverLdrEntry;
	std::vector<FakeModule_t *> m_FakeModules;
	std::vector<AllocBlock_t> m_HeapAllocs;
	std::vector<MemMapping_t> m_MemMappings;
	int m_MainModuleIndex;
	int m_LastHeapAllocBytes;
	std::vector<uint64_t> m_TlsValue;
	uint64_t m_LastRip;
	uint64_t m_LastRipModule;
	uint64_t m_ExecCodeCount;
	uint64_t m_ExecuteFromRip;
	NTSTATUS m_LastException;
	bool m_FakeAPICallEnabled;
	FakeAPI_t *m_LastFakeAPICall;
	uint64_t m_LastFakeAPICallReturnAddress;
	_CONTEXT m_InitReg;
	INVERTED_FUNCTION_TABLE m_PsInvertedFunctionTable;
	UCHAR m_RtlpUnwindOpSlotTable[11];
	int m_ExecuteExceptionHandler;
	std::string filename;

	std::string m_SaveWritten;
	std::string m_SaveRead;

	std::vector<std::tuple<uintptr_t, uint8_t>> m_Undo;
	std::vector<std::tuple<uintptr_t, uint8_t>> m_Written;
	std::vector<std::tuple<uintptr_t, uint8_t>> m_Read;
	std::vector<bool> m_WrittenBitmap;
	std::vector<uintptr_t> m_StartAddresses;
	std::vector<std::tuple<uintptr_t, uintptr_t>> m_Calls;
};

extern PeEmulation g_ctx;

void* uc_memcpy( uc_engine* uc, uintptr_t _Dst, void const* _Src, size_t _Size);

int uc_memcmp( uc_engine* uc, uintptr_t _Dst, void const* _Src, size_t _Size);

void* uc_memset(uc_engine* uc, uintptr_t _Dst, int _Val, size_t _Size);

void ResetRegisters(uc_engine* uc, PeEmulation& ctx);

void SaveResult(uc_engine* uc, const uintptr_t& fn_address, PeEmulation& ctx);

int ImageDump(PeEmulation& ctx, uc_engine* uc, const std::string& filename);

int WritePrologue(uc_engine* uc, uintptr_t prologue_address, uintptr_t start_address);

void RegisterAPIs(PeEmulation& ctx);


#define API_FUNCTION_SIZE 8
#define PAGE_SIZE 0x1000
#define PAGE_ALIGN(Va) ((ULONG_PTR)(Va) & ~(PAGE_SIZE - 1))
#define PAGE_ALIGN_UP(Va) (((ULONG_PTR)(Va) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))
#define PAGE_ALIGN_UP_MIN1(Va) ((((ULONG_PTR)(Va) ? (ULONG_PTR)(Va) : 1) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))
#define PAGE_ALIGN_64(Va) ((Va) & ~(0x1000ull - 1))
#define PAGE_ALIGN_64k(Va) (((Va)) & ~(0x10000ull - 1))
#define ALIGN_UP_MIN1(Va, Align) ((((Va) ? (Va) : 1) + Align - 1) & ~(Align - 1))

#define AlignSize(Size, Align) (Size+Align-1)/Align*Align

#define EXCP00_DIVZ	0
#define EXCP01_DB	1
#define EXCP02_NMI	2
#define EXCP03_INT3	3
#define EXCP04_INTO	4
#define EXCP05_BOUND	5
#define EXCP06_ILLOP	6
#define EXCP07_PREX	7
#define EXCP08_DBLE	8
#define EXCP09_XERR	9
#define EXCP0A_TSS	10
#define EXCP0B_NOSEG	11
#define EXCP0C_STACK	12
#define EXCP0D_GPF	13
#define EXCP0E_PAGE	14
#define EXCP10_COPR	16
#define EXCP11_ALGN	17
#define EXCP12_MCHK	18

#define EXCP_SYSCALL    0x100 /* only happens in user only emulation
								 for syscall instruction */