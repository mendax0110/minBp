#include "hv/InstructionTrapper.h"
#include "hv/CpuidHandler.h"
#include "hv/IoPortHandler.h"
#include "hv/MsrHandler.h"
#include "hv/MmioHandler.h"
#include "hv/EventDispatcher.h"
#include "hv/VCpu.h"
#include <algorithm>
#include <cstring>
#include <iostream>

#include "hv/VirtualMachine.h"

using namespace kvm;

InstructionTrapper::InstructionTrapper(VCpu* vcpu,
                                       CpuidHandler* cpuid,
                                       IoPortHandler* io,
                                       MsrHandler* msr,
                                       MmioHandler* mmio,
                                       EventDispatcher* dispatch) noexcept
    : m_vcpu(vcpu)
    , m_cpuid(cpuid)
    , m_io(io)
    , m_msr(msr)
    , m_mmio(mmio)
    , m_dispatch(dispatch)
{

}

InstructionTrapper::RunResult InstructionTrapper::runLoop(const uint64_t max_iterations)
{
    uint64_t iterations = 0;
    while (max_iterations == 0 || iterations < max_iterations)
    {
        const RunResult result = step();

        if (result != RunResult::Continue)
        {
            return result;
        }
        ++iterations;
    }
    return RunResult::Continue;
}

InstructionTrapper::RunResult InstructionTrapper::step()
{
    const auto exitResult = m_vcpu->run();
    if (!exitResult)
    {
        return RunResult::Error;
    }

    ++m_exitCount;
    return dispatchExit(*exitResult);
}

InstructionTrapper::RunResult InstructionTrapper::dispatchExit(ExitReason reason) const
{
    kvm_run* const run = m_vcpu->kvmRun();

    /*std::println(std::cout, "[DBG] exit_reason={} hw_exit={} internal_suberror={}",
        run->exit_reason,
        run->hw.hardware_exit_reason,
        run->internal.suberror);*/

    switch (reason)
    {
        case ExitReason::Hlt:
        {
            if (m_dispatch)
            {
                HvEvent ev{};
                ev.type = EventType::GuestHalt;
                ev.vcpu_id = m_vcpu->id();
                ev.timestamp = std::chrono::steady_clock::now();
                ev.payload = std::monostate{};

                if (auto regs = m_vcpu->getRegs(); regs)
                {
                    ev.rip = regs->rip;
                }
                m_dispatch->publish(ev);
            }
            return RunResult::Halt;
        }
        case ExitReason::Shutdown:
        {
            if (m_dispatch)
            {
                HvEvent ev{};
                ev.type = EventType::GuestShutdown;
                ev.vcpu_id = m_vcpu->id();
                ev.timestamp = std::chrono::steady_clock::now();
                m_dispatch->publish(ev);
            }
            return RunResult::Shutdown;
        }
        case ExitReason::Io:
        {
            if (m_io && !m_io->handle(*m_vcpu, *run))
            {
                return RunResult::Error;
            }

            if (m_dispatch)
            {
                const auto& io = run->io;
                IoEvent payload{};
                payload.size = io.size;
                payload.port = io.port;
                payload.isWrite = (io.direction == KVM_EXIT_IO_OUT);

                const auto* data = reinterpret_cast<const uint8_t*>(run) + io.data_offset;
                std::memcpy(&payload.value, data, std::min<uint8_t>(io.size, 4));

                HvEvent ev{};
                ev.type = payload.isWrite ? EventType::IoWrite : EventType::IoRead;
                ev.vcpu_id = m_vcpu->id();
                ev.payload = payload;
                ev.timestamp = std::chrono::steady_clock::now();
                if (auto regs = m_vcpu->getRegs(); regs)
                {
                    ev.rip = regs->rip;
                }
                m_dispatch->publish(ev);
            }
            return RunResult::Continue;
        }
        case ExitReason::Unknown:
        {
            if (run->hw.hardware_exit_reason == 0)
            {
                if (m_cpuid)
                {
                    if (!m_cpuid->handle(*m_vcpu))
                    {
                        return RunResult::Error;
                    }
                }
            }

            return RunResult::Continue;
        }
        case ExitReason::Intr:
        {
            return RunResult::Continue;
        }
        case ExitReason::Mmio:
        {
            if (m_mmio && !m_mmio->handle(*run))
            {
                return RunResult::Error;
            }

            if (m_dispatch)
            {
                const auto& mmio = run->mmio;

                MmioEvent payload{};
                payload.guest_phys_addr = mmio.phys_addr;
                payload.size = mmio.len;
                payload.isWrite = (mmio.is_write != 0);
                std::memcpy(&payload.value, mmio.data, std::min<uint8_t>(mmio.len, 8));

                HvEvent ev{};
                ev.type = EventType::MemAccess;
                ev.vcpu_id = m_vcpu->id();
                ev.payload = payload;
                ev.timestamp = std::chrono::steady_clock::now();
                if (auto regs = m_vcpu->getRegs(); regs)
                {
                    ev.rip = regs->rip;
                }
                m_dispatch->publish(ev);
            }

            return RunResult::Continue;
        }
        case ExitReason::InternalError:
        {
            if (run->internal.suberror == KVM_INTERNAL_ERROR_EMULATION)
            {
                if (m_cpuid && !m_cpuid->handle(*m_vcpu))
                {
                    return RunResult::Error;
                }

                if (m_dispatch)
                {
                    CpuidEvent payload{};
                    if (auto regs = m_vcpu->getRegs(); regs)
                    {
                        payload.leaf = static_cast<uint32_t>(regs->rax);
                        payload.subleaf = static_cast<uint32_t>(regs->rcx);
                        // read back injected values after we call handle()
                        payload.eax = static_cast<uint32_t>(regs->rax);
                        payload.ebx = static_cast<uint32_t>(regs->rbx);
                        payload.ecx = static_cast<uint32_t>(regs->rcx);
                        payload.edx = static_cast<uint32_t>(regs->rdx);
                    }

                    HvEvent ev{};
                    ev.type = EventType::CpuidAccess;
                    ev.vcpu_id = m_vcpu->id();
                    ev.payload = payload;
                    ev.timestamp = std::chrono::steady_clock::now();
                    if (auto regs = m_vcpu->getRegs(); regs)
                    {
                        ev.rip = regs->rip;
                    }
                    m_dispatch->publish(ev);
                }
                return RunResult::Continue;
            }
            return RunResult::Error;
        }
        default:
            return RunResult::Continue;
    }
}

uint64_t InstructionTrapper::exitCount() const noexcept
{
    return m_exitCount;
}
