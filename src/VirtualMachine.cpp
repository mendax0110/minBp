#include "hv/VirtualMachine.h"
#include <sys/ioctl.h>
#include <unistd.h>
#include <linux/kvm.h>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <utility>

using namespace kvm;

VirtualMachine::VirtualMachine(const int vm_fd, const int vcpu_mmap_size) noexcept
    : m_fd(vm_fd)
    , m_vcpuMmapSize(vcpu_mmap_size)
{

}

VirtualMachine::~VirtualMachine()
{
    if (m_fd >= 0)
    {
        ::close(m_fd);
    }
}

VirtualMachine::VirtualMachine(VirtualMachine&& other) noexcept
    : m_fd(std::exchange(other.m_fd, -1))
    , m_vcpuMmapSize(other.m_vcpuMmapSize)
    , m_nextSlot(other.m_nextSlot)
    , m_memoryRegions(std::move(other.m_memoryRegions))
    , m_vcpus(std::move(other.m_vcpus))
{

}

VirtualMachine& VirtualMachine::operator=(VirtualMachine&& other) noexcept
{
    if (this != &other)
    {
        if (m_fd >= 0)
        {
            ::close(m_fd);
        }

        m_fd             = std::exchange(other.m_fd, -1);
        m_vcpuMmapSize   = other.m_vcpuMmapSize;
        m_nextSlot       = other.m_nextSlot;
        m_memoryRegions  = std::move(other.m_memoryRegions);
        m_vcpus          = std::move(other.m_vcpus);
    }
    return *this;
}

std::expected<MemoryRegion*, std::error_code> VirtualMachine::addMemoryRegion(const uint64_t guest_phys_addr, const size_t size_bytes, const uint32_t flags)
{
    auto result = MemoryRegion::create(m_fd, m_nextSlot, guest_phys_addr, size_bytes, flags);

    if (!result)
    {
        return std::unexpected(result.error());
    }

    m_memoryRegions.push_back(std::move(*result));
    ++m_nextSlot;
    return &m_memoryRegions.back();
}

std::expected<VCpu*, std::error_code> VirtualMachine::addVCpu(const uint32_t vcpu_id)
{
    auto result = VCpu::create(m_fd, vcpu_id, m_vcpuMmapSize);
    if (!result)
    {
        return std::unexpected(result.error());
    }

    m_vcpus.push_back(std::move(*result));
    return &m_vcpus.back();
}

std::error_code VirtualMachine::setIrqLine(const uint32_t irq, const int level) const
{
    kvm_irq_level kill{};
    kill.irq = irq;
    kill.level = static_cast<uint32_t>(level);

    if (::ioctl(m_fd, KVM_IRQ_LINE, &kill) < 0)
    {
        return {errno, std::generic_category()};
    }
    return {};
}

std::error_code VirtualMachine::createIrqChip() const
{
    if (::ioctl(m_fd, KVM_CREATE_IRQCHIP, 0) < 0)
    {
        return {errno, std::generic_category()};
    }
    return {};
}

std::error_code VirtualMachine::createPit2() const
{
    kvm_pit_config pit_cfg{};
    pit_cfg.flags = 0;
    if (::ioctl(m_fd, KVM_CREATE_PIT2, &pit_cfg) < 0)
    {
        return {errno, std::generic_category()};
    }
    return {};
}

int VirtualMachine::fd() const noexcept
{
    return m_fd;
}

const std::vector<VCpu>& VirtualMachine::vcpus() const noexcept
{
    return m_vcpus;
}

std::vector<VCpu>& VirtualMachine::vcpus() noexcept
{
    return m_vcpus;
}

const std::vector<MemoryRegion> &VirtualMachine::memoryRegions() const noexcept
{
    return m_memoryRegions;
}

std::error_code VirtualMachine::enableEmulationExits() const
{
    kvm_enable_cap cap{};
    cap.cap = KVM_CAP_EXIT_ON_EMULATION_FAILURE;
    cap.args[0] = 1;
    if (::ioctl(m_fd, KVM_ENABLE_CAP, &cap) < 0)
    {
        return {errno, std::generic_category()};
    }
    return {};
}

VmSnapShot VirtualMachine::takeSnapShot(VirtualMachine& vm)
{
    VmSnapShot snap;
    const auto& vcpu = vm.vcpus()[0];
    snap.regs = vcpu.getRegs().value_or(kvm_regs{});
    snap.sregs = vcpu.getSregs().value_or(kvm_sregs{});

    for (const auto& region : vm.memoryRegions())
    {
        if (region.hostAddr() == nullptr)
        {
            snap.memoryRegions.emplace_back();
            continue;
        }
        auto* host = static_cast<std::byte*>(region.hostAddr());
        snap.memoryRegions.emplace_back(host, host + region.size());
    }
    return snap;
}

void VirtualMachine::restoreSnapshot(VirtualMachine& vm, const VmSnapShot& snapshot)
{
    const auto& vcpu = vm.vcpus()[0];

    const auto codeRegs = vcpu.setRegs(snapshot.regs);
    if (codeRegs)
    {
        std::println(std::cerr, "[!] Failed to restore vCPU registers: {}", codeRegs.message());
    }

    const auto codeSregs = vcpu.setSregs(snapshot.sregs);
    if (codeSregs)
    {
        std::println(std::cerr, "[!] Failed to restore vCPU special registers: {}", codeSregs.message());
    }

    for (size_t i = 0; i < vm.memoryRegions().size(); ++i)
    {
        auto& region = vm.memoryRegions()[i];
        if (region.hostAddr() == nullptr || i >= snapshot.memoryRegions.size() || snapshot.memoryRegions[i].empty())
        {
            continue;
        }
        std::memcpy(region.hostAddr(), snapshot.memoryRegions[i].data(), region.size());
    }
}
