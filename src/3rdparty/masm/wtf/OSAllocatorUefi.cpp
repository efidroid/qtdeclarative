#include "config.h"
#include "OSAllocator.h"

#if OS(UEFI)

#include <cstdlib>

#include "PageAllocation.h"
#include <errno.h>
#include <wtf/Assertions.h>
#include <wtf/UnusedParam.h>

#include <Base.h>
#include <PiDxe.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/Cpu.h>
#include <assert.h>
#include <stdio.h>

namespace WTF {

static EFI_GUID mEfiCpuArchProtocolGuid = EFI_CPU_ARCH_PROTOCOL_GUID;
static EFI_CPU_ARCH_PROTOCOL *mCpu = NULL;

static void __attribute__((constructor)) init_allocator(void) {
    EFI_STATUS status;

    status = gST->BootServices->LocateProtocol (&mEfiCpuArchProtocolGuid, NULL, (void **)&mCpu);
    if (EFI_ERROR(status)) {
        CRASH();
    }
}

void OSAllocator::setMemoryProtection(void *base, size_t size, bool writable, bool executable)
{
    EFI_STATUS status;
    UINT64 attributes = 0;

    if (!writable)
        attributes |= EFI_MEMORY_RO;
    if (!executable)
        attributes |= EFI_MEMORY_XP;

    size = EFI_PAGES_TO_SIZE(EFI_SIZE_TO_PAGES(size));

    status = mCpu->SetMemoryAttributes(mCpu, (UINT64)(UINTN)base, size, attributes);
    if (EFI_ERROR(status)) {
        CRASH();
    }
}

void* OSAllocator::reserveUncommitted(size_t bytes, Usage usage, bool writable, bool executable)
{
    return reserveAndCommit(bytes, usage, writable, executable, false);
}

void* OSAllocator::reserveAndCommit(size_t bytes, Usage usage, bool writable, bool executable, bool includesGuardPages)
{
    EFI_STATUS status;
    EFI_PHYSICAL_ADDRESS  Memory;

    UNUSED_PARAM(includesGuardPages);
    UNUSED_PARAM(usage);

    status = gST->BootServices->AllocatePages (AllocateAnyPages, EfiLoaderCode, EFI_SIZE_TO_PAGES(bytes), &Memory);
    if (EFI_ERROR(status)) {
        return NULL;
    }

    memset((VOID*)(UINTN) Memory, 0, bytes);

    setMemoryProtection((VOID*)(UINTN) Memory, bytes, writable, executable);

    return (VOID*)(UINTN) Memory;
}

void OSAllocator::commit(void* address, size_t bytes, bool writable, bool executable)
{
    UNUSED_PARAM(address);
    UNUSED_PARAM(bytes);
    UNUSED_PARAM(writable);
    UNUSED_PARAM(executable);
}

void OSAllocator::decommit(void* address, size_t bytes)
{
    UNUSED_PARAM(address);
    UNUSED_PARAM(bytes);
}

void OSAllocator::releaseDecommitted(void* address, size_t bytes)
{
    if (!address)
        return;

    EFI_STATUS status = gST->BootServices->FreePages((EFI_PHYSICAL_ADDRESS) (UINTN) address, EFI_SIZE_TO_PAGES(bytes));
    if (EFI_ERROR(status))
        CRASH();
}

bool OSAllocator::canAllocateExecutableMemory()
{
    return true;
}

} // namespace WTF

#endif // OS(UEFI)
