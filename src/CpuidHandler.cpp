#include "hv/CpuidHandler.h"
#include "hv/VCpu.h"
#include <cpuid.h>

using namespace kvm;

void CpuidHandler::registerLeaf(const uint32_t leaf, LeafCallback callback)
{
    m_leafCallbacks[leaf] = std::move(callback);
}

bool CpuidHandler::handle(const VCpu& vcpu)
{
    const auto regs_result = vcpu.getRegs();
    if (!regs_result)
    {
        return false;
    }

    auto regs = *regs_result;
    const auto leaf = static_cast<uint32_t>(regs.rax);
    const auto subleaf = static_cast<uint32_t>(regs.rcx);

    LeafResult result{};
    if (const auto it = m_leafCallbacks.find(leaf); it != m_leafCallbacks.end())
    {
        result = it->second(leaf, subleaf);
    }
    else
    {
        result = executeHostCpuid(leaf, subleaf);
    }

    regs.rax = result.eax;
    regs.rbx = result.ebx;
    regs.rcx = result.ecx;
    regs.rdx = result.edx;

    if (const auto ec = vcpu.setRegs(regs); ec)
    {
        return false;
    }

    ++m_handledCount;
    return true;
}

uint64_t CpuidHandler::handledCount() const noexcept
{
    return m_handledCount;
}

CpuidHandler::LeafResult CpuidHandler::executeHostCpuid(uint32_t leaf, uint32_t subleaf) noexcept
{
    LeafResult r{};
    __cpuid_count(leaf, subleaf, r.eax, r.ebx, r.ecx, r.edx);
    return r;
}
