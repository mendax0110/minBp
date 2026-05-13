#include "hv/VCpu.h"
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <linux/kvm.h>
#include <cerrno>
#include <cstring>
#include <utility>

using namespace kvm;

std::expected<VCpu, std::error_code> VCpu::create(const int vm_fd, const uint32_t vcpu_id, const int mmap_size)
{
    const int fd = ::ioctl(vm_fd, KVM_CREATE_VCPU, static_cast<unsigned long>(vcpu_id));
    if (fd < 0)
    {
        return std::unexpected(std::error_code(errno, std::generic_category()));
    }

    auto* run_page = static_cast<kvm_run*>(::mmap(nullptr, static_cast<size_t>(mmap_size), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0));
    if (run_page == MAP_FAILED)
    {
        const int err = errno;
        ::close(fd);
        return std::unexpected(std::error_code(err, std::generic_category()));
    }

    return VCpu(fd, vcpu_id, run_page, static_cast<size_t>(mmap_size));
}

VCpu::VCpu(const int fd, const uint32_t id, kvm_run* run_page, const size_t mmap_size) noexcept
    : m_fd(fd)
    , m_id(id)
    , m_runPage(run_page)
    , m_mmapSize(mmap_size)
{
}

VCpu::~VCpu()
{
    if (m_runPage != nullptr && m_runPage != MAP_FAILED)
    {
        ::munmap(m_runPage, m_mmapSize);
    }

    if (m_fd >= 0)
    {
        ::close(m_fd);
    }
}

VCpu::VCpu(VCpu&& other) noexcept
    : m_fd(std::exchange(other.m_fd, -1))
    , m_id(other.m_id)
    , m_runPage(std::exchange(other.m_runPage, nullptr))
    , m_mmapSize(other.m_mmapSize)
{
}

VCpu& VCpu::operator=(VCpu&& other) noexcept
{
    if (this != &other)
    {
        if (m_runPage != nullptr && m_runPage != MAP_FAILED)
        {
            ::munmap(m_runPage, m_mmapSize);
        }
        if (m_fd >= 0)
        {
            ::close(m_fd);
        }

        m_fd = std::exchange(other.m_fd, -1);
        m_id = other.m_id;
        m_runPage = std::exchange(other.m_runPage, nullptr);
        m_mmapSize = other.m_mmapSize;
    }
    return *this;
}

std::expected<ExitReason, std::error_code> VCpu::run() const
{
    if (::ioctl(m_fd, KVM_RUN, 0) < 0)
    {
        if (errno == EINTR)
        {
            return ExitReason::Intr;
        }
        return std::unexpected(std::error_code(errno, std::generic_category()));
    }
    return static_cast<ExitReason>(m_runPage->exit_reason);
}

std::expected<kvm_regs, std::error_code> VCpu::getRegs() const
{
    kvm_regs regs{};
    if (::ioctl(m_fd, KVM_GET_REGS, &regs) < 0)
    {
        return std::unexpected(std::error_code(errno, std::generic_category()));
    }
    return regs;
}

std::error_code VCpu::setRegs(const kvm_regs& regs) const
{
    if (::ioctl(m_fd, KVM_SET_REGS, &regs) < 0)
    {
        return {errno, std::generic_category()};
    }
    return {};
}

std::expected<kvm_sregs, std::error_code> VCpu::getSregs() const
{
    kvm_sregs sregs{};
    if (::ioctl(m_fd, KVM_GET_SREGS, &sregs) < 0)
    {
        return std::unexpected(std::error_code(errno, std::generic_category()));
    }
    return sregs;
}

std::error_code VCpu::setSregs(const kvm_sregs& sregs) const
{
    if (::ioctl(m_fd, KVM_SET_SREGS, &sregs) < 0)
    {
        return {errno, std::generic_category()};
    }
    return {};
}

std::error_code VCpu::setSingleStep(const bool enable) const
{
    kvm_guest_debug dbg{};
    if (enable)
    {
        dbg.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP;
    }

    if (::ioctl(m_fd, KVM_SET_GUEST_DEBUG, &dbg) < 0)
    {
        return {errno, std::generic_category()};
    }
    return {};
}

kvm_run* VCpu::kvmRun() const noexcept
{
    return m_runPage;
}

int VCpu::fd() const noexcept
{
    return m_fd;
}

uint32_t VCpu::id() const noexcept
{
    return m_id;
}

std::error_code VCpu::installCpuid(const std::vector<kvm_cpuid_entry2>& entries) const
{
    const size_t size = sizeof(kvm_cpuid2) + entries.size() * sizeof(kvm_cpuid_entry2);
    std::vector<uint8_t> buf(size, 0);

    auto* cpuid2 = reinterpret_cast<kvm_cpuid2*>(buf.data());
    cpuid2->nent = static_cast<uint32_t>(entries.size());
    std::memcpy(cpuid2->entries, entries.data(), entries.size() * sizeof(kvm_cpuid_entry2));

    if (::ioctl(m_fd, KVM_SET_CPUID2, buf.data()) < 0)
    {
        return {errno, std::generic_category()};
    }
    return {};
}


