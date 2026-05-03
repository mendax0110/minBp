#include "hv/MemoryRegion.h"
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/kvm.h>
#include <algorithm>
#include <cassert>
#include <cerrno>
#include <cstring>
#include <utility>

using namespace kvm;

std::expected<MemoryRegion, std::error_code> MemoryRegion::create(const int vm_fd, const uint32_t slot, const uint64_t guest_phys_addr, const size_t size_bytes, const uint32_t flags)
{
    void* const host_name = ::mmap(nullptr, size_bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);

    if (host_name == MAP_FAILED)
    {
        return std::unexpected(std::error_code(errno, std::generic_category()));
    }

    ::madvise(host_name, size_bytes, MADV_MERGEABLE);

    kvm_userspace_memory_region region{};
    region.slot = slot;
    region.flags = flags;
    region.guest_phys_addr = guest_phys_addr;
    region.memory_size = size_bytes;
    region.userspace_addr = reinterpret_cast<uint64_t>(host_name);

    if (::ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0)
    {
        const int err = errno;
        ::munmap(host_name, size_bytes);
        return std::unexpected(std::error_code(err, std::generic_category()));
    }

    return MemoryRegion(vm_fd, slot, guest_phys_addr, size_bytes, host_name);
}

MemoryRegion::MemoryRegion(const int vm_fd, const uint32_t slot, const uint64_t guest_phys_addr, const size_t size, void* host_addr) noexcept
    : m_vmFd(vm_fd)
    , m_slot(slot)
    , m_guestPhysAddr(guest_phys_addr)
    , m_size(size)
    , m_hostAddr(host_addr)
{
}

MemoryRegion::~MemoryRegion()
{
    if (m_hostAddr != nullptr && m_hostAddr != MAP_FAILED)
    {
        kvm_userspace_memory_region region{};
        region.slot = m_slot;
        region.memory_size = 0;
        ::ioctl(m_vmFd, KVM_SET_USER_MEMORY_REGION, &region);

        ::munmap(m_hostAddr, m_size);
    }
}

MemoryRegion::MemoryRegion(MemoryRegion&& other) noexcept
    : m_vmFd(other.m_vmFd)
    , m_slot(other.m_slot)
    , m_guestPhysAddr(other.m_guestPhysAddr)
    , m_size(other.m_size)
    , m_hostAddr(std::exchange(other.m_hostAddr, nullptr))
{
}

MemoryRegion& MemoryRegion::operator=(MemoryRegion&& other) noexcept
{
    if (this != &other)
    {
        if (m_hostAddr != nullptr && m_hostAddr != MAP_FAILED)
        {
            kvm_userspace_memory_region region{};
            region.slot = m_slot;
            region.memory_size = 0;
            ::ioctl(m_vmFd, KVM_SET_USER_MEMORY_REGION, &region);
            ::munmap(m_hostAddr, m_size);
        }
        m_vmFd = other.m_vmFd;
        m_slot = other.m_slot;
        m_guestPhysAddr = other.m_guestPhysAddr;
        m_size = other.m_size;
        m_hostAddr = std::exchange(other.m_hostAddr, nullptr);
    }
    return *this;
}

void MemoryRegion::write(const size_t guest_offset, std::span<const std::byte> data) const
{
    assert(guest_offset + data.size() <= m_size);
    auto* dest = static_cast<std::byte*>(m_hostAddr) + guest_offset;
    std::ranges::copy(data, dest);
}

void MemoryRegion::read(const size_t guest_offset, std::span<std::byte> out) const
{
    assert(guest_offset + out.size() <= m_size);
    const auto* src = static_cast<const std::byte*>(m_hostAddr) + guest_offset;
    std::copy_n(src, out.size(), out.begin());
}

void *MemoryRegion::hostAddr() const noexcept
{
    return m_hostAddr;
}

uint64_t MemoryRegion::guestPhysAddr() const noexcept
{
    return m_guestPhysAddr;
}

size_t MemoryRegion::size() const noexcept
{
    return m_size;
}
