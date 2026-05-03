#include "hv/VmiAgent.h"
#include "hv/VirtualMachine.h"
#include "hv/MemoryRegion.h"
#include "hv/VCpu.h"
#include <fstream>
#include <sstream>
#include <format>
#include <variant>
#include <cstring>

using namespace kvm;

VmiAgent::VmiAgent(VirtualMachine* vm, EventDispatcher* dispatcher)
    : m_vm(vm)
    , m_dispatch(dispatcher)
{
    if (m_dispatch)
    {
        m_subId = m_dispatch->subscribeAll([this](const HvEvent& ev)
        {
           handleHvEvent(ev);
        });
    }
}

VmiAgent::~VmiAgent()
{
    if (m_dispatch && m_subId != 0)
    {
        m_dispatch->unsubscribe(m_subId);
    }
}

void VmiAgent::onEvent(IntrospectionCallback cb)
{
    m_callbacks.push_back(std::move(cb));
}

void VmiAgent::enableMemoryDump(const uint64_t guest_phys_addr, const size_t size)
{
    m_memDumpEnabled = true;
    m_memDumpAddr = guest_phys_addr;
    m_memDumpSize = size;
}

void VmiAgent::disableMemoryDump()
{
    m_memDumpEnabled = false;
}

std::vector<uint8_t> VmiAgent::readGuestPhysMemory(const uint64_t guest_phys_addr, const size_t size) const
{
    if (!m_vm)
    {
        return {};
    }

    for (const auto& region : m_vm->memoryRegions())
    {
        const uint64_t base = region.guestPhysAddr();
        const uint64_t end = base + region.size();

        if (guest_phys_addr >= base && (guest_phys_addr + size) <= end)
        {
            std::vector<uint8_t> buf(size);
            const auto* src = static_cast<const uint8_t*>(region.hostAddr()) + (guest_phys_addr - base);
            std::memcpy(buf.data(), src, size);
            return buf;
        }
    }

    return {};
}

std::optional<GuestSnapshot> VmiAgent::snapshotRegisters(const uint32_t vcpu_index) const
{
    if (!m_vm || vcpu_index >= m_vm->vcpus().size())
    {
        return std::nullopt;
    }

    const VCpu& vcpu = m_vm->vcpus()[vcpu_index];

    const auto regsResult = vcpu.getRegs();
    const auto sregsResult = vcpu.getSregs();

    if (!regsResult || !sregsResult)
    {
        return std::nullopt;
    }

    const auto& r = *regsResult;
    const auto& sr = *sregsResult;

    GuestSnapshot snap{};
    snap.rip = r.rip;
    snap.rsp = r.rsp;
    snap.rax = r.rax;
    snap.rbx = r.rbx;
    snap.rcx = r.rcx;
    snap.rdx = r.rdx;
    snap.rsi = r.rsi;
    snap.rdi = r.rdi;
    snap.r8  = r.r8;
    snap.r9  = r.r9;
    snap.r10 = r.r10;
    snap.r11 = r.r11;
    snap.r12 = r.r12;
    snap.r13 = r.r13;
    snap.r14 = r.r14;
    snap.r15 = r.r15;
    snap.rflags = r.rflags;
    snap.cr0 = sr.cr0;
    snap.cr3 = sr.cr3;
    snap.cr4 = sr.cr4;
    snap.timestamp = std::chrono::steady_clock::now();

    return snap;
}

void VmiAgent::handleHvEvent(const HvEvent& event)
{
    IntrospectionEvent ie{};
    ie.base = event;

    if (const auto snap = snapshotRegisters(event.vcpu_id))
    {
        ie.snapshot = *snap;
    }

    if (m_memDumpEnabled)
    {
        auto dump = readGuestPhysMemory(m_memDumpAddr, m_memDumpSize);
        if (!dump.empty())
        {
            ie.memDump = std::move(dump);
        }
    }

    ie.summary = buildSummary(event, ie.snapshot);

    m_eventLog.push_back(ie);

    for (const auto& cb : m_callbacks)
    {
        cb(ie);
    }
}

std::string VmiAgent::buildSummary(const HvEvent& event, const GuestSnapshot& snap) const
{
    std::ostringstream oss;
    oss << std::hex << std::uppercase;

    oss << "[VCPU" << event.vcpu_id << "] RIP=0x" << snap.rip << " | ";

    std::visit([&]<typename T0>(const T0& payload)
    {
        using T = std::decay_t<T0>;

        if constexpr (std::is_same_v<T, CpuidEvent>)
        {
            oss << "CPUID leaf=0x" << payload.leaf
                << " sub=0x" << payload.subleaf
                << " => EAX=0x" << payload.eax
                << " EBX=0x" << payload.ebx
                << " ECX=0x" << payload.ecx
                << " EDX=0x" << payload.edx;
        }
        else if constexpr (std::is_same_v<T, IoEvent>)
        {
            oss << (payload.isWrite ? "OUT" : "IN") << " port=0x" << payload.port
                << " size=" << std::dec << static_cast<uint32_t>(payload.size) << "B"
                << " value=0x" << std::hex << payload.value;
        }
        else if constexpr (std::is_same_v<T, MsrEvent>)
        {
            oss << (payload.isWrite ? "WRMSR" : "RDMSR")
                << " index=0x" << payload.index
                << " value=0x" << payload.value;
        }
        else
        {
            switch (event.type)
            {
                case EventType::GuestHalt: oss << "HLT"; break;
                case EventType::GuestShutdown: oss << "SHUTDOWN"; break;
                default: oss << "EVENT"; break;
            }
        }
    }, event.payload);

    return oss.str();
}

void VmiAgent::dumpEventLog(const std::filesystem::path& path) const
{
    std::ofstream out(path);
    if (!out)
    {
        return;
    }

    out << "[\n";
    for (std::size_t i = 0; i < m_eventLog.size(); ++i)
    {
        const auto&[base, snapshot, memDump, summary] = m_eventLog[i];
        const auto  ts = std::chrono::duration_cast<std::chrono::milliseconds>(snapshot.timestamp.time_since_epoch()).count();

        out << "  {\n"
            << "    \"timestamp\": " << std::dec  << ts                    << ",\n"
            << "    \"vcpu_id\": "   << std::dec  << base.vcpu_id       << ",\n"
            << "    \"rip\": \"0x"   << std::hex  << snapshot.rip       << "\",\n"
            << "    \"summary\": \"" << summary << "\"";

        if (memDump.has_value())
        {
            out << ",\n    \"mem_dump\": \"";
            for (const uint8_t byte : memDump.value())
            {
                out << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
            }
            out << "\"";
        }

        out << "\n  }" << (i + 1 < m_eventLog.size() ? "," : "") << "\n";
    }

    out << "]\n";
}

const std::vector<VmiAgent::IntrospectionEvent>& VmiAgent::eventLog() const noexcept
{
    return m_eventLog;
}