#include "hv/GuestLoader.h"
#include "hv/VirtualMachine.h"
#include "hv/MemoryRegion.h"
#include "hv/VCpu.h"
#include <fstream>
#include <iterator>
#include <cstring>

using namespace kvm;

std::error_code GuestLoader::load(VirtualMachine& vm, const GuestLoadParams& params)
{
    const auto bytes = readFile(params.imagePath);
    if (bytes.empty())
    {
        return std::error_code(ENONET, std::generic_category());
    }

    auto regioResult = vm.addMemoryRegion(0, params.memorySize);
    if (!regioResult)
    {
        return regioResult.error();
    }

    const MemoryRegion* region = *regioResult;

    const size_t offset = params.loadAddress;
    if (offset + bytes.size() > region->size())
    {
        return std::error_code(ENOMEM, std::generic_category());
    }

    const auto bytesAsSpan = std::as_bytes(std::span(bytes));
    region->write(offset, bytesAsSpan);

    auto vcpuResult = vm.addVCpu(0);
    if (!vcpuResult)
    {
        return vcpuResult.error();
    }

    VCpu* vcpu = *vcpuResult;

    switch (params.mode)
    {
        case GuestLoadMode::RealMode16:
        {
            return setupRealModeVCpu(*vcpu, static_cast<uint16_t>(params.entryPoint & 0xFFFF));
        }
        case GuestLoadMode::FlatBinary:
        default:
        {
            constexpr uint64_t pgtableBase = 0x2000;
            if (const auto ec = buildIdentityPageTables(vm, pgtableBase); ec)
            {
                return ec;
            }
            return setup64BitVCpu(*vcpu, params.entryPoint, pgtableBase);
        }
    }
}

std::error_code GuestLoader::loadBytes(VirtualMachine& vm, const std::span<const uint8_t> code, const uint64_t load_addr, const size_t memory_size)
{
    auto regionResult = vm.addMemoryRegion(0, memory_size);
    if (!regionResult)
    {
        return regionResult.error();
    }

    const MemoryRegion* region = *regionResult;
    if (load_addr + code.size() > region->size())
    {
        return std::error_code(ENOMEM, std::generic_category());
    }

    const auto bytesAsSpan = std::as_bytes(code);
    region->write(load_addr, bytesAsSpan);

    auto vcpuResult = vm.addVCpu(0);
    if (!vcpuResult)
    {
        return vcpuResult.error();
    }

    return setupRealModeVCpu(**vcpuResult, static_cast<uint16_t>(load_addr & 0xFFFF));
}

std::error_code GuestLoader::setupRealModeVCpu(const VCpu& vcpu, const uint16_t entry_ip)
{
    auto sregsResult = vcpu.getSregs();
    if (!sregsResult)
    {
        return sregsResult.error();
    }

    auto sregs = *sregsResult;

    auto setupSeg = [](kvm_segment& seg, const uint16_t selector)
    {
        seg.selector = selector;
        seg.base = static_cast<uint64_t>(selector) << 4;
        seg.limit = 0xFFFF;
        seg.type = 3;
        seg.present = 1;
        seg.dpl = 0;
        seg.db = 0;
        seg.s = 1;
        seg.l = 0;
        seg.g = 0;
    };

    setupSeg(sregs.cs, 0);
    setupSeg(sregs.ds, 0);
    setupSeg(sregs.es, 0);
    setupSeg(sregs.fs, 0);
    setupSeg(sregs.gs, 0);
    setupSeg(sregs.ss, 0);

    sregs.cr0 &= ~(1ULL); // Clear PE bit for real mode

    if (const auto ec = vcpu.setSregs(sregs); ec)
    {
        return ec;
    }

    kvm_regs regs{};
    regs.rip = entry_ip;
    regs.rsp = 0xFFF0;
    regs.rflags = 0x0002;

    return vcpu.setRegs(regs);
}

std::error_code GuestLoader::setup64BitVCpu(const VCpu& vcpu, const uint64_t rip, const uint64_t cr3)
{
    auto sregsResult = vcpu.getSregs();
    if (!sregsResult)
    {
        return sregsResult.error();
    }

    auto sregs = *sregsResult;

    kvm_segment cs_seg{};
    cs_seg.selector = 0x08;
    cs_seg.base = 0;
    cs_seg.limit = 0xFFFFFFFF;
    cs_seg.type = 11; // Code, execute/read, accessed
    cs_seg.present = 1;
    cs_seg.l = 1; // 64-bit code segment
    cs_seg.db = 0;
    cs_seg.s = 1;
    cs_seg.g = 1;

    kvm_segment ds_seg{};
    ds_seg.selector = 0x10;
    ds_seg.base = 0;
    ds_seg.limit = 0xFFFFFFFF;
    ds_seg.type = 3; // Data, read/write, accessed
    ds_seg.present = 1;
    ds_seg.db = 1;
    ds_seg.s = 1;
    ds_seg.g = 1;

    sregs.cs = cs_seg;
    sregs.ds = ds_seg;
    sregs.es = ds_seg;
    sregs.fs = ds_seg;
    sregs.gs = ds_seg;
    sregs.ss = ds_seg;

    sregs.cr0 = 0x80050033;
    sregs.cr3 = cr3;
    sregs.cr4 = 0x20;
    sregs.efer = 0x500;

    if (const auto ec = vcpu.setSregs(sregs); ec)
    {
        return ec;
    }

    kvm_regs regs{};
    regs.rip = rip;
    regs.rsp = 0x200000;
    regs.rflags = 0x0002;

    return vcpu.setRegs(regs);
}

std::error_code GuestLoader::buildIdentityPageTables(const VirtualMachine& vm, const uint64_t base_addr)
{
    for (auto& region : const_cast<std::vector<MemoryRegion>&>(vm.memoryRegions()))
    {
        const uint64_t rbase = region.guestPhysAddr();
        const uint64_t rend = rbase + region.size();

        if (base_addr < rbase || base_addr >= rend)
        {
            continue; // This region doesn't cover the page tables
        }

        const size_t offset = static_cast<size_t>(base_addr - rbase);
        auto* p = static_cast<uint64_t*>(region.hostAddr());
        auto* tables = reinterpret_cast<uint64_t*>(reinterpret_cast<uint8_t*>(p) + offset);

        // PML4
        uint64_t* pml4 = tables;
        uint64_t* pdpt = tables + 512;
        uint64_t* pd = tables + 1024;

        std::memset(pml4, 0, 4096);
        std::memset(pdpt, 0, 4096);
        std::memset(pd, 0, 4096);

        pml4[0] = (base_addr + 0x1000) | 0x03;
        pdpt[0] = (base_addr + 0x2000) | 0x03;

        for (uint64_t i = 0; i < 512; ++i)
        {
            pd[i] = (i << 21) | 0x83;
        }

        return {};
    }

    return std::error_code(ENONET, std::generic_category());
}

std::vector<uint8_t> GuestLoader::readFile(const std::filesystem::path& path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file)
    {
        return {};
    }
    return std::vector<uint8_t>(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
}
