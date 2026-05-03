#include "hv/MsrHandler.h"
#include "hv/VCpu.h"
#include <sys/ioctl.h>
#include <linux/kvm.h>
#include <cerrno>
#include <cstring>
#include <vector>
#include <algorithm>
#include <ranges>

using namespace kvm;

void MsrHandler::registerRead(const uint32_t msr_index, ReadCallback cb)
{
    m_readCallbacks[msr_index] = std::move(cb);
}

void MsrHandler::registerWrite(const uint32_t msr_index, WriteCallback cb)
{
    m_writeCallbacks[msr_index] = std::move(cb);
}

std::error_code MsrHandler::installFilter(int vm_fd) const
{
    std::vector<uint32_t> indices;
    indices.reserve(m_readCallbacks.size() + m_writeCallbacks.size());

    for (const auto &idx: m_readCallbacks | std::views::keys)
    {
        indices.push_back(idx);
    }

    for (const auto &idx: m_writeCallbacks | std::views::keys)
    {
        if (std::ranges::find(indices, idx) == indices.end())
        {
            indices.push_back(idx);
        }
    }

    if (indices.empty())
    {
        return {};
    }

    const size_t n = indices.size();
    std::vector<kvm_msr_filter_range> ranges(n);

    std::vector<std::vector<uint64_t>> bitmaps(n, std::vector<uint64_t>(1, 1ULL));

    for (size_t i = 0; i < n; ++i)
    {
        ranges[i].flags = KVM_MSR_FILTER_READ | KVM_MSR_FILTER_WRITE;
        ranges[i].nmsrs = 1;
        ranges[i].base = indices[i];
        ranges[i].bitmap = reinterpret_cast<uint8_t*>(bitmaps[i].data());
    }

    kvm_msr_filter filter{};
    filter.flags = KVM_MSR_FILTER_DEFAULT_ALLOW;
    const size_t range_count = std::min(n, static_cast<size_t>(KVM_MSR_FILTER_MAX_RANGES));
    for (size_t i = 0; i < range_count; ++i)
    {
        filter.ranges[i] = ranges[i];
    }

    if (::ioctl(vm_fd, KVM_X86_SET_MSR_FILTER, &filter) < 0)
    {
        return std::error_code(errno, std::generic_category());
    }

    return {};
}

bool MsrHandler::handle(const VCpu& vcpu, const kvm_run& run)
{
    const uint32_t idx = run.msr.index;
    const bool is_write = (run.msr.reason == KVM_MSR_EXIT_REASON_VALID_MASK);

    if (is_write)
    {
        const uint64_t value = run.msr.data;
        if (const auto it = m_writeCallbacks.find(idx); it != m_writeCallbacks.end())
        {
            it->second(idx, value);
        }
        ++m_writeCount;
    }
    else
    {
        uint64_t result = 0;
        if (const auto it = m_readCallbacks.find(idx); it != m_readCallbacks.end())
        {
            result = it->second(idx);
        }

        // Inject the value back via KVM_GET_REGS/KVM_SET_REGS.
        const auto regs_result = vcpu.getRegs();
        if (!regs_result)
        {
            return false;
        }

        auto regs = *regs_result;
        regs.rax = result & 0xFFFF'FFFF;
        regs.rdx = (result >> 32) & 0xFFFF'FFFF;

        if (const auto ec = vcpu.setRegs(regs); ec)
        {
            return false;
        }

        ++m_readCount;
    }

    return true;
}

uint64_t MsrHandler::readCount() const noexcept
{
    return m_readCount;
}

uint64_t MsrHandler::writeCount() const noexcept
{
    return m_writeCount;
}


