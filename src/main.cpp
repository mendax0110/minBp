#include "hv/KvmSystem.h"
#include "hv/VirtualMachine.h"
#include "hv/VCpu.h"
#include "hv/GuestLoader.h"
#include "hv/CpuidHandler.h"
#include "hv/IoPortHandler.h"
#include "hv/MsrHandler.h"
#include "hv/MmioHandler.h"
#include "hv/InstructionTrapper.h"
#include "hv/VmiAgent.h"
#include "hv/EventDispatcher.h"
#include <iostream>
#include <csignal>
#include <atomic>
#include <fstream>
#include <print>


static std::atomic<bool> g_running{true};

static void sigint_handler(int /*sig*/)
{
    g_running = false;
}

// Minimal 16-bit real-mode guest
// This blob:
//   IN   AL, 0x60   ; read from port 0x60 (keyboard)
//   CPUID            ; leaf 0  (get vendor string)
//   HLT              ; stop
//
// Assembled bytes:
static constexpr std::array<uint8_t, 8> k_guestCode =
{
    0xE4, 0x60,        // IN AL, 0x60
    0x31, 0xC0,        // XOR EAX, EAX  (CPUID leaf 0)
    0x0F, 0xA2,        // CPUID
    0xF4,              // HLT
    0x00               // padding
};

static constexpr uint64_t k_mmio_base = 0x80000;
static constexpr uint64_t k_reg_magic = k_mmio_base + 0x00;
static constexpr uint64_t k_reg_input = k_mmio_base + 0x08;
static constexpr uint64_t k_reg_status = k_mmio_base + 0x10;

struct MmioDeviceState
{
    uint64_t last_write_value{0};
    uint64_t write_count{0};
};

// Entry point
int main(int /*argc*/, char** /*argv*/)
{
    std::signal(SIGINT, sigint_handler);

    // Open KVM
    auto kvm_result = kvm::KvmSystem::open();
    if (!kvm_result)
    {
        std::println(std::cerr, "[!] Failed to open /dev/kvm: {}", kvm_result.error().message());
        return 1;
    }
    auto& kvm_sys = *kvm_result;
    std::println("[+] KVM API version: {}", kvm_sys.apiVersion());

    // Create VM
    auto vm_result = kvm_sys.createVm();
    if (!vm_result)
    {
        std::println(std::cerr, "[!] KVM_CREATE_VM failed: {}", vm_result.error().message());
        return 1;
    }
    auto& vm = **vm_result;
    std::println("[+] VM created (fd={})", vm.fd());

    if (kvm_sys.checkExtension(KVM_CAP_EXIT_ON_EMULATION_FAILURE))
    {
        if (auto ec = vm.enableEmulationExits(); ec)
        {
            std::println(std::cerr, "[!] Failed to enable emulation failure exits: {}", ec.message());
        }
        else
        {
            std::println("[+] Enabled KVM_CAP_EXIT_ON_EMULATION_FAILURE, CPUID will trap to userspace");
        }
    }
    else
    {
        std::println("[!] KVM_CAP_EXIT_ON_EMULATION_FAILURE not supported, CPUID exits may be handled in-kernel");
        std::println("    (This may cause CPUID exit counts to be inaccurate and some leaf handlers to not work.)");
    }

    std::ifstream f("simpleGuest.bin", std::ios::binary);
    std::vector<uint8_t> guestCodeBytes(std::istreambuf_iterator<char>(f), {});

    if (guestCodeBytes.empty())
    {
        std::println(std::cerr, "[!] Failed to read guest code from simpleGuest.bin");
        return 1;
    }

    // Load guest
    if (auto ec = kvm::GuestLoader::loadBytes(vm,
            std::span<const uint8_t>(/*k_guestCode*/guestCodeBytes),
            /*load_addr=*/0x1000,
            /*mem_size= */1 << 19);  // 512 KiB; keep MMIO at 0x80000 outside RAM
        ec)
    {
        std::println(std::cerr, "[!] GuestLoader::loadBytes failed: {}", ec.message());
        return 1;
    }
    std::println("[+] Guest code loaded at GPA 0x1000");

    kvm::VCpu *vcpu = &vm.vcpus()[0];

    // Set up handlers
    kvm::EventDispatcher dispatcher;
    kvm::CpuidHandler    cpuid_handler;
    kvm::IoPortHandler   io_handler;
    kvm::MsrHandler      msr_handler;
    kvm::MmioHandler     mmio_handler;
    MmioDeviceState mmio_state{};

    // Mask the hypervisor-present bit in CPUID leaf 1 ECX.
    cpuid_handler.registerLeaf(0x01, [](uint32_t leaf, uint32_t sub)
    {
        auto r = kvm::CpuidHandler::LeafResult{};
        uint32_t eax, ebx, ecx, edx;
        __asm__ volatile("cpuid"
            : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
            : "a"(leaf),  "c"(sub));
        r.ecx &= ~(1u << 31);
        return r;
    });

    // Simulate a simple PS/2 keyboard port.
    io_handler.registerInPort(0x60, [](const kvm::IoPortHandler::InContext&) -> uint32_t
    {
        std::println("  [IO] Guest read from port 0x60 (keyboard)");
        return 0x1A;//0x1C;  // 'A' scancode
    });

    mmio_handler.registerRead(k_reg_magic, [](const kvm::MmioHandler::ReadContext& ctx) -> uint64_t
    {
        static_cast<void>(ctx);
        return 0x4D4D494F;
    });

    mmio_handler.registerWrite(k_reg_input, [&mmio_state](const kvm::MmioHandler::WriteContext& ctx)
    {
        mmio_state.last_write_value = ctx.value;
        ++mmio_state.write_count;
        std::println("  [MMIO] write input=0x{:x} (size={})", ctx.value, ctx.size);
    });

    mmio_handler.registerRead(k_reg_status, [&mmio_state](const kvm::MmioHandler::ReadContext& ctx) -> uint64_t
    {
        static_cast<void>(ctx);
        const uint64_t count = (mmio_state.write_count & 0xFFFF'FFFFULL) << 32;
        const uint64_t last = (mmio_state.last_write_value & 0xFFFF'FFFFULL);
        return count | last;
    });

    // Wire up VMI agent
    kvm::VmiAgent vmi_agent(&vm, &dispatcher);
    vmi_agent.onEvent([](const kvm::VmiAgent::IntrospectionEvent& ev)
    {
        std::println("  [VMI] {}", ev.summary);
    });

    // Subscribe a simple event logger.
    [[maybe_unused]] auto sub_id = dispatcher.subscribeAll([](const kvm::HvEvent& ev)
    {
        using ET = kvm::EventType;
        switch (ev.type)
        {
            case ET::CpuidAccess: std::print(std::cout, "  [CPUID] "); break;
            case ET::IoRead: std::print(std::cout, "  [IN]    "); break;
            case ET::IoWrite: std::print(std::cout, "  [OUT]   "); break;
            case ET::MsrRead: std::print(std::cout, "  [RDMSR] "); break;
            case ET::MsrWrite: std::print(std::cout, "  [WRMSR] "); break;
            case ET::MemAccess: std::print(std::cout, "  [MMIO]  "); break;
            case ET::GuestHalt: std::print(std::cout, "  [HLT]   "); break;
            case ET::GuestShutdown: std::print(std::cout, "  [SHUT]  "); break;
            default: std::print(std::cout, "  [EVT]   "); break;
        }
        std::println("vcpu={} rip=0x{:x}", ev.vcpu_id, std::get_if<kvm::CpuidEvent>(&ev.payload) ? 0 : ev.rip);
    });

    // builds CPUID table: read from host, apply modifications, log, then install.
    std::vector<kvm_cpuid_entry2> cpuidEntries;
    for (uint32_t leaf : {0x00u, 0x01u, 0x02u, 0x07u, 0x80000000u, 0x80000001u, 0x80000002u, 0x80000003u, 0x80000004u})
    {
        const auto [eax, ebx, ecx, edx] = cpuid_handler.executeHostCpuid(leaf, 0);
        kvm_cpuid_entry2 e{};
        e.function = leaf;
        e.eax = eax;
        e.ebx = ebx;
        e.ecx = ecx;
        e.edx = edx;
        cpuidEntries.push_back(e);

        if (leaf == 0x01)
        {
            e.ecx &= ~(1u << 31);
        }

        if (leaf == 0x00)
        {
            e.eax = std::min(e.eax, 0x0Bu);
        }

        std::println("[+] CPUID leaf=0x{:08x} => EAX=0x{:08x} EBX=0x{:08x} ECX=0x{:08x} EDX=0x{:08x}",
            e.function, e.eax, e.ebx, e.ecx, e.edx);
        std::cout.flush();

        kvm::CpuidEvent ce{};
        ce.leaf    = leaf;
        ce.subleaf = 0;
        ce.eax     = e.eax;
        ce.ebx     = e.ebx;
        ce.ecx     = e.ecx;
        ce.edx     = e.edx;

        kvm::HvEvent ev{};
        ev.type      = kvm::EventType::CpuidAccess;
        ev.vcpu_id   = 0;
        ev.rip       = 0;
        ev.payload   = ce;
        ev.timestamp = std::chrono::steady_clock::now();
        dispatcher.publish(ev);
    }

    if (auto ec = vcpu->installCpuid(cpuidEntries); ec)
    {
        std::println(std::cerr, "[!] KVM_SET_CPUID2 failed: {}", ec.message());
        return 1;
    }
    std::println("[+] CPUID table installed ({} leaves)", cpuidEntries.size());

    auto snapshot = kvm::VirtualMachine::takeSnapShot(vm);
    std::println("[+] VM snapshot taken ({} memory regions)", snapshot.memoryRegions.size());

    // Run
    kvm::InstructionTrapper trapper(vcpu, &cpuid_handler, &io_handler, &msr_handler, &mmio_handler, &dispatcher);

    static constexpr std::array<uint8_t, 3> fuzzInput = { 0x41, 0x42, 0x43 }; // 'A', 'B', 'C' scancodes

    constexpr int max_iterations = 3;
    for (int i = 0; i < max_iterations; ++i)
    {
        if (i > 0)
        {
            kvm::VirtualMachine::restoreSnapshot(vm, snapshot);
            std::println("[+] VM snapshot restored, starting run #{}", i);
        }

        auto& region = vm.memoryRegions()[0];
        auto* host = static_cast<uint8_t*>(region.hostAddr());
        host[0x2000] = fuzzInput[i % fuzzInput.size()]; // for each run inject differnt scancodes..
        std::println("[+] Injected scancode 0x{:02x} at GPA 0x2000", host[0x2000]);

        std::println("[+] Starting guest execution loop #{} …", i);
        const auto result = trapper.runLoop();
        std::println("[+] Guest stopped after {} exits.", trapper.exitCount());

        switch (result)
        {
            case kvm::InstructionTrapper::RunResult::Halt:
                std::println("[+] Guest halted normally.");
                break;
            case kvm::InstructionTrapper::RunResult::Shutdown:
                std::println("[+] Guest requested shutdown.");
                break;
            case kvm::InstructionTrapper::RunResult::Error:
                std::println(std::cerr, "[!] Hypervisor error during guest run.");
                return 1;
            default:
                break;
        }
    }

    std::println("[+] Guest stopped after {} exits.", trapper.exitCount());

    // Dump VMI log
    vmi_agent.dumpEventLog("vmi_events.json");
    std::println("[+] VMI event log written to vmi_events.json");
    std::println("[+] Total events dispatched: {}", dispatcher.publishedCount());

    return 0;
}