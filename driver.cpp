#include <ntddk.h>

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);
extern "C" VOID UnloadDriver(_In_ PDRIVER_OBJECT DriverObject);
extern "C" NTSTATUS CreateCloseHandler(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
extern "C" NTSTATUS DeviceIoControlHandler(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
extern "C" NTSTATUS InjectDllIntoProcess(_In_ HANDLE ProcessId, _In_ PCWSTR DllPath);

PVOID remoteModule;
KEVENT remoteEvent;

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = UnloadDriver;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateCloseHandler;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateCloseHandler;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceIoControlHandler;

    // Create a device object
    UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\TestDriver");
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\TestDriver");

    PDEVICE_OBJECT devObj;
    NTSTATUS status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &devObj);

    if (!NT_SUCCESS(status))
    {
        KdPrint(("Failed to create device object (0x%X)\n", status));
        return status;
    }

    devObj->Flags |= DO_BUFFERED_IO;

    // Create a symbolic link
    IoCreateSymbolicLink(&symLink, &devName);

    // Initialize the global event for signaling
    KeInitializeEvent(&remoteEvent, NotificationEvent, FALSE);

    return STATUS_SUCCESS;
}

extern "C" VOID UnloadDriver(_In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\TestDriver");

    // Delete the symbolic link
    IoDeleteSymbolicLink(&symLink);

    // Delete the device object
    IoDeleteDevice(DriverObject->DeviceObject);

    KdPrint(("Driver Unloaded\n"));
}

extern "C" NTSTATUS CreateCloseHandler(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

extern "C" NTSTATUS DeviceIoControlHandler(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);

    if (irpStack->Parameters.DeviceIoControl.IoControlCode == CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS))
    {
        // Retrieve the process ID from user-mode (replace with your mechanism)
        HANDLE targetProcessId = ...; // Implement a mechanism to get the process ID

        NTSTATUS status = InjectDllIntoProcess(targetProcessId, L"C:\\test.dll");

        if (NT_SUCCESS(status))
        {
            Irp->IoStatus.Status = STATUS_SUCCESS;
        }
        else
        {
            Irp->IoStatus.Status = status;
        }
    }
    else
    {
        Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
    }

    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

extern "C" NTSTATUS InjectDllIntoProcess(_In_ HANDLE ProcessId, _In_ PCWSTR DllPath)
{
    PEPROCESS targetProcess;
    NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &targetProcess);

    if (NT_SUCCESS(status))
    {
        KAPC_STATE apcState;
        KeStackAttachProcess(targetProcess, &apcState);

        // Allocate memory in the target process for the DLL path
        SIZE_T pathSize = (wcslen(DllPath) + 1) * sizeof(WCHAR);
        PVOID remotePath;
        status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &remotePath, 0, &pathSize, MEM_COMMIT, PAGE_READWRITE);

        if (NT_SUCCESS(status))
        {
            // Copy the DLL path to the target process
            status = ZwWriteVirtualMemory(ZwCurrentProcess(), remotePath, DllPath, pathSize, NULL);

            if (NT_SUCCESS(status))
            {
                // Load the DLL in the target process
                PETHREAD currentThread = PsGetCurrentThread();
                status = PsImpersonateClient(currentThread, targetProcess);

                if (NT_SUCCESS(status))
                {
                    status = PsCreateSystemThread(
                        NULL, 0, NULL, NULL, NULL,
                        (PKSTART_ROUTINE)LoadLibraryThread,
                        remotePath
                    );

                    PsRevertToSelf();
                }
            }

            // Free the allocated memory in the target process
            ZwFreeVirtualMemory(ZwCurrentProcess(), &remotePath, &pathSize, MEM_RELEASE);
        }

        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(targetProcess);
    }

    return status;
}

extern "C" VOID LoadLibraryThread(_In_ PVOID Parameter)
{
    PAGED_CODE();

    UNICODE_STRING dllPath;
    RtlInitUnicodeString(&dllPath, (PWSTR)Parameter);

    // Load the DLL
    NTSTATUS status = PsLoadImage(&dllPath, NULL, NULL, 0, NULL, &remoteModule);

    // Signal completion
    KeSetEvent(&remoteEvent, IO_NO_INCREMENT, FALSE);

    PsTerminateSystemThread(status);
}
