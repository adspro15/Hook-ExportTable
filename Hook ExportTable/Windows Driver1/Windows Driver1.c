#include <ntddk.h>
#include <WINDEF.H>

ULONG_PTR old_NtOpenProcess;

ULONG_PTR RecoverAddress;									//用来恢复的地址

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
	HANDLE Section;
	PVOID MappedBase;
	PVOID Base;
	ULONG Size;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT PathLength;
	CHAR ImageName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef NTSTATUS(*NTOPENPROCESS)(__out PHANDLE ProcessHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in_opt PCLIENT_ID ClientId
	);

typedef NTSTATUS(*NTQUERYSYSTEMINFORMATION)(
	IN ULONG_PTR SystemInformationClass,
	OUT PVOID   SystemInformation,
	IN ULONG_PTR    SystemInformationLength,
	OUT PULONG_PTR  ReturnLength OPTIONAL);

NTSTATUS MyNtOpenProcess(
	__out PHANDLE ProcessHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in_opt PCLIENT_ID ClientId
	)
{
	KdPrint(("My NtOpenProcess!\n"));
	return ((NTOPENPROCESS)(old_NtOpenProcess))(
		ProcessHandle,
		DesiredAccess,
		ObjectAttributes,
		ClientId);
}

void PageProtectOff()
{
	_asm
	{
		cli;
		mov eax, cr0;
		and eax, not 10000h;
		mov cr0, eax;
	}
}

void PageProtectOn()
{
	_asm
	{
		mov eax, cr0;
		or eax, 10000h;
		mov cr0, eax;
		sti;
	}
}

ULONG_PTR GetNtBase()
{
	UNICODE_STRING Name;
	ULONG_PTR Address;
	ULONG_PTR size;
	UCHAR *moduleaddress;
	PSYSTEM_MODULE_INFORMATION_ENTRY entry;
	ULONG_PTR StartAddress;

	RtlInitUnicodeString(&Name, L"NtQuerySystemInformation");
	Address = (ULONG_PTR)MmGetSystemRoutineAddress(&Name);
	((NTQUERYSYSTEMINFORMATION)(Address))(11, NULL, 0, &size);
	moduleaddress = (UCHAR*)ExAllocatePoolWithTag(NonPagedPool, size, 'ytz');
	((NTQUERYSYSTEMINFORMATION)(Address))(11, moduleaddress, size, &size);
	entry = (PSYSTEM_MODULE_INFORMATION_ENTRY)(moduleaddress + sizeof(ULONG_PTR));
	StartAddress = (ULONG_PTR)entry->Base;
	ExFreePoolWithTag(moduleaddress, 'ytz');
	return StartAddress;
}

VOID Unload(PDRIVER_OBJECT DriverObject)
{
	KdPrint(("Unload Success!\n"));
	PageProtectOff();
	*(ULONG_PTR*)RecoverAddress = old_NtOpenProcess;
	PageProtectOn();
}

VOID HookExport(ULONG_PTR FuncAddress,ULONG_PTR KernelBase)
{
	ULONG_PTR TempBase;						//作为临时地址的变量
	ULONG_PTR *AddressArry;					//导出表的地址表
	ULONG_PTR NumberOfFunctions;			//导出函数的总数
	ULONG_PTR i;							//用来做下标
	UNICODE_STRING FuncName;

	TempBase = KernelBase;

	TempBase = TempBase + *(ULONG_PTR*)(KernelBase + 0x3c);
	TempBase = TempBase + 0x18;
	TempBase = TempBase + 0x60;
	TempBase = KernelBase + *(ULONG_PTR*)TempBase;

	NumberOfFunctions = *(ULONG_PTR*)(TempBase + 0x14);
	AddressArry = (ULONG_PTR*)(KernelBase + *(ULONG_PTR*)(TempBase + 0x1c));
	
	KdPrint(("导出函数的总数是：%x\n", NumberOfFunctions));
	KdPrint(("函数地址表的基址是：%x\n", (ULONG_PTR)AddressArry));

	for (i = 0; i < NumberOfFunctions; ++i)
	{
		if (AddressArry[i] + KernelBase == FuncAddress)
		{
			KdPrint(("找到函数位置！\n"));
			PageProtectOff();
			AddressArry[i] = (ULONG_PTR)MyNtOpenProcess - KernelBase;
			PageProtectOn();
			RecoverAddress = (ULONG_PTR)&AddressArry[i];
			break;
		}
	}

	RtlInitUnicodeString(&FuncName, L"NtOpenProcess");
	KdPrint(("MyNtOpenProcess is %x\n", (ULONG_PTR)MyNtOpenProcess));
	KdPrint(("SysNtOpenProcess is %x\n", (ULONG_PTR)MmGetSystemRoutineAddress(&FuncName)));
}

VOID Init(PWSTR Name)
{
	UNICODE_STRING FuncName;
	ULONG_PTR KernelBase;

	RtlInitUnicodeString(&FuncName, Name);
	old_NtOpenProcess = (ULONG_PTR)MmGetSystemRoutineAddress(&FuncName);
	KdPrint(("NtOpenProcess Address is %x\n", old_NtOpenProcess));

	KernelBase = GetNtBase();
	KdPrint(("Kernel BaseAddress is %x\n", KernelBase));

	HookExport(old_NtOpenProcess, KernelBase);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegString)
{
	KdPrint(("Entry Driver!\n"));
	Init(L"NtOpenProcess");
	DriverObject->DriverUnload = Unload;
	return STATUS_SUCCESS;
}