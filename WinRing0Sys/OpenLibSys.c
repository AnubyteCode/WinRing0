#include "OpenLibSys.h"
#include <wdmsec.h>

static ULONG refCount;

/*
Return Value:
    STATUS_SUCCESS if the driver initialized correctly, otherwise an error indicating the reason for failure.
*/
NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING ntDeviceName = RTL_CONSTANT_STRING(NT_DEVICE_NAME);
    UNICODE_STRING win32DeviceName = RTL_CONSTANT_STRING(DOS_DEVICE_NAME);
    PDEVICE_OBJECT deviceObject = NULL;

    // Secure device creation: Ensure only Administrators can access this driver
    NTSTATUS status = IoCreateDeviceSecure(
        DriverObject,                    // Our Driver Object
        0,                                // No device extension
        &ntDeviceName,                    // Device name
        OLS_TYPE,                         // Device type
        FILE_DEVICE_SECURE_OPEN,          // Device characteristics
        FALSE,                            // Not exclusive
        &SDDL_DEVOBJ_SYS_ALL_ADM_ALL,     // Security descriptor to restrict access to Admins only
        NULL,                             // No class GUID
        &deviceObject);                   // Output device object pointer

    if (!NT_SUCCESS(status))
    {
        refCount = (ULONG)(-1);
        return status;
    }
    else
    {
        refCount = 0;
    }

    // Initialize the driver's dispatch functions
    DriverObject->MajorFunction[IRP_MJ_CREATE] = OlsDispatch;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = OlsDispatch;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = OlsDispatch;
    DriverObject->DriverUnload = Unload;

    // Create a symbolic link between our device name and the Win32 name
    status = IoCreateSymbolicLink(&win32DeviceName, &ntDeviceName);

    if (!NT_SUCCESS(status))
    {
        // Clean up if symbolic link creation failed
        IoDeleteDevice(deviceObject);
    }

    return status;
}

NTSTATUS OlsDispatch(IN PDEVICE_OBJECT pDO, IN PIRP pIrp)
{
    UNREFERENCED_PARAMETER(pDO);
    pIrp->IoStatus.Information = 0;
    PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(pIrp);

    NTSTATUS status = STATUS_NOT_IMPLEMENTED;

    switch (pIrpStack->MajorFunction)
    {
    case IRP_MJ_CREATE:
        if (refCount != (ULONG)(-1))
        {
            refCount++;
        }
        status = STATUS_SUCCESS;
        break;
    case IRP_MJ_CLOSE:
        if (refCount != (ULONG)(-1))
        {
            refCount--;
        }
        status = STATUS_SUCCESS;
        break;
    case IRP_MJ_DEVICE_CONTROL:
        // Dispatch on IOCTL
        switch (pIrpStack->Parameters.DeviceIoControl.IoControlCode)
        {
        case IOCTL_OLS_GET_DRIVER_VERSION:
            if (pIrpStack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(ULONG))
            {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            *(PULONG)pIrp->AssociatedIrp.SystemBuffer = OLS_DRIVER_VERSION;
            pIrp->IoStatus.Information = sizeof(ULONG);
            status = STATUS_SUCCESS;
            break;

        case IOCTL_OLS_GET_REFCOUNT:
            if (pIrpStack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(refCount))
            {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            *(PULONG)pIrp->AssociatedIrp.SystemBuffer = refCount;
            pIrp->IoStatus.Information = sizeof(refCount);
            status = STATUS_SUCCESS;
            break;

        case IOCTL_OLS_READ_MSR:
            status = ReadMsr(
                pIrp->AssociatedIrp.SystemBuffer,
                pIrpStack->Parameters.DeviceIoControl.InputBufferLength,
                pIrp->AssociatedIrp.SystemBuffer,
                pIrpStack->Parameters.DeviceIoControl.OutputBufferLength,
                (ULONG*)&pIrp->IoStatus.Information
            );
            break;
        case IOCTL_OLS_WRITE_MSR:
            status = WriteMsr(
                pIrp->AssociatedIrp.SystemBuffer,
                pIrpStack->Parameters.DeviceIoControl.InputBufferLength,
                pIrp->AssociatedIrp.SystemBuffer,
                pIrpStack->Parameters.DeviceIoControl.OutputBufferLength,
                (ULONG*)&pIrp->IoStatus.Information
            );
            break;
            // Similar checks for other IOCTL cases here...
        }
        break;
    }

    pIrp->IoStatus.Status = status;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return status;
}

VOID Unload(PDRIVER_OBJECT DriverObject)
{
    PDEVICE_OBJECT deviceObject = DriverObject->DeviceObject;
    UNICODE_STRING win32NameString;

    PAGED_CODE();

    RtlInitUnicodeString(&win32NameString, DOS_DEVICE_NAME);
    IoDeleteSymbolicLink(&win32NameString);

    if (deviceObject != NULL)
    {
        IoDeleteDevice(deviceObject);
    }
}

NTSTATUS ReadMsr(void* lpInBuffer, ULONG nInBufferSize, void* lpOutBuffer, ULONG nOutBufferSize, ULONG* lpBytesReturned)
{
    __try
    {
        UNREFERENCED_PARAMETER(nInBufferSize);
        if (nOutBufferSize < sizeof(ULONGLONG))
        {
            *lpBytesReturned = 0;
            return STATUS_BUFFER_TOO_SMALL;
        }
#ifdef _ARM64_
        ULONGLONG data = _ReadStatusReg(*(ULONG*)lpInBuffer);
#else
        ULONGLONG data = __readmsr(*(ULONG*)lpInBuffer);
#endif
        memcpy((PULONG)lpOutBuffer, &data, sizeof(ULONGLONG));
        *lpBytesReturned = sizeof(ULONGLONG);
        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        *lpBytesReturned = 0;
        return STATUS_UNSUCCESSFUL;
    }
}

NTSTATUS WriteMsr(void* lpInBuffer, ULONG nInBufferSize, void* lpOutBuffer, ULONG nOutBufferSize, ULONG* lpBytesReturned)
{
    __try
    {
        UNREFERENCED_PARAMETER(lpOutBuffer);
        if (BufferSizeCheck(nInBufferSize, nOutBufferSize, lpBytesReturned, sizeof(OLS_WRITE_MSR_INPUT)) < 0) return STATUS_INVALID_PARAMETER;
        OLS_WRITE_MSR_INPUT* param = (OLS_WRITE_MSR_INPUT*)lpInBuffer;

#ifdef _ARM64_
        _WriteStatusReg(param->Register, param->Value.QuadPart);
#else
        __writemsr(param->Register, param->Value.QuadPart);
#endif
        * lpBytesReturned = 0;
        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        *lpBytesReturned = 0;
        return STATUS_UNSUCCESSFUL;
    }
}

NTSTATUS pciConfigRead(ULONG pciAddress, ULONG offset, void* data, int length)
{
    PCI_SLOT_NUMBER slot;
    int error;
    ULONG busNumber;

    busNumber = PciGetBus(pciAddress);
    slot.u.AsULONG = 0;
    slot.u.bits.DeviceNumber = PciGetDev(pciAddress);
    slot.u.bits.FunctionNumber = PciGetFunc(pciAddress);
    error = HalGetBusDataByOffset(PCIConfiguration, busNumber, slot.u.AsULONG,
        data, offset, length);

    if (error == 0)
    {
        return OLS_ERROR_PCI_BUS_NOT_EXIST;
    }
    else if (length != 2 && error == 2)
    {
        return OLS_ERROR_PCI_NO_DEVICE;
    }
    else if (length != error)
    {
        return OLS_ERROR_PCI_READ_CONFIG;
    }

    return STATUS_SUCCESS;
}

NTSTATUS pciConfigWrite(ULONG pciAddress, ULONG offset, void* data, int length)
{
    PCI_SLOT_NUMBER slot;
    int error;
    ULONG busNumber;

    busNumber = PciGetBus(pciAddress);

    slot.u.AsULONG = 0;
    slot.u.bits.DeviceNumber = PciGetDev(pciAddress);
    slot.u.bits.FunctionNumber = PciGetFunc(pciAddress);
    error = HalSetBusDataByOffset(PCIConfiguration, busNumber, slot.u.AsULONG,
        data, offset, length);

    if (error != length)
    {
        return OLS_ERROR_PCI_WRITE_CONFIG;
    }

    return STATUS_SUCCESS;
}
