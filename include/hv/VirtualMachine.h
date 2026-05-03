#pragma once

#include "MemoryRegion.h"
#include "VCpu.h"

#include <cstdint>
#include <memory>
#include <vector>
#include <expected>
#include <system_error>
#include <linux/kvm.h>

namespace kvm
{

    /// @brief Snapshot of a VM's state, including vCPU registers and memory contents. \struct VmSnapShot
    struct VmSnapShot
    {
        kvm_regs regs;
        kvm_sregs sregs;
        std::vector<std::vector<std::byte>> memoryRegions;
    };

    /**
     * @brief Represents a KVM virtual machine (VM file descriptor + resources).
     *
     * VirtualMachine owns the VM fd, all MemoryRegion objects and all VCpu
     * instances associated with this guest.  It is obtained from KvmSystem::createVm().
     */
    class VirtualMachine
    {
    public:
        /**
         * @brief Construct from an existing VM fd and the KVM mmap size.
         * @param vm_fd  File descriptor from KVM_CREATE_VM.
         * @param vcpu_mmap_size Result of KVM_GET_VCPU_MMAP_SIZE.
         */
        VirtualMachine(int vm_fd, int vcpu_mmap_size) noexcept;

        ~VirtualMachine();

        VirtualMachine(const VirtualMachine&) = delete;
        VirtualMachine& operator=(const VirtualMachine&) = delete;
        VirtualMachine(VirtualMachine&&) noexcept;
        VirtualMachine& operator=(VirtualMachine&&) noexcept;

        /**
         * @brief Allocate a new guest-physical memory region.
         * @param guest_phys_addr Base guest-physical address.
         * @param size_bytes Region size (page-aligned).
         * @param flags KVM_MEM_* flags.
         * @return Pointer to the new MemoryRegion (owned by this VM).
         */
        [[nodiscard]] std::expected<MemoryRegion*, std::error_code> addMemoryRegion(uint64_t guest_phys_addr, std::size_t size_bytes, uint32_t flags = 0);

        /**
         * @brief Create a new vCPU and attach it to this VM.
         * @param vcpu_id Logical vCPU index.
         * @return Pointer to the new VCpu (owned by this VM).
         */
        [[nodiscard]] std::expected<VCpu*, std::error_code> addVCpu(uint32_t vcpu_id = 0);

        /**
         * @brief Set a PIC/IOAPIC IRQ level (KVM_IRQ_LINE).
         * @param irq IRQ number.
         * @param level 1 = assert, 0 = deassert.
         */
        [[nodiscard]] std::error_code setIrqLine(uint32_t irq, int level) const;

        /**
         * @brief Create an in-kernel IRQCHIP (i8259 + IOAPIC).
         */
        [[nodiscard]] std::error_code createIrqChip() const;

        /**
         * @brief Create an in-kernel PIT2 (8254 timer).
         */
        [[nodiscard]] std::error_code createPit2() const;

        /**
         * @brief Raw VM file descriptor.
         */
        [[nodiscard]] int fd() const noexcept;

        /**
         * @brief Access all vCPUs attached to this VM.
         */
        [[nodiscard]] const std::vector<VCpu>& vcpus() const noexcept;

        /**
         * @brief Access all vCPUs attached to this VM (mutable).
         */
        [[nodiscard]] std::vector<VCpu>& vcpus() noexcept;

        /**
         * @brief Access all memory regions owned by this VM.
         */
        [[nodiscard]] const std::vector<MemoryRegion>& memoryRegions() const noexcept;

        /**
         * @brief Enables exits for emulated instructions (CPUID, RDTSC, etc.) instead of in-kernel handling.
         * @return A std::error_code indicating success or failure of the ioctl call.
         */
        [[nodiscard]] std::error_code enableEmulationExits() const;

        /**
         * @brief Capture a snapshot of the VM's current state, including vCPU registers and memory contents.
         * @param vm The VirtualMachine instance to snapshot.
         * @return A VmSnapShot structure containing the captured state.
         */
        static VmSnapShot takeSnapShot(VirtualMachine& vm);

        /**
         * @brief Restore a VM's state from a snapshot, including vCPU registers and memory contents.
         * @param vm The VirtualMachine instance to restore.
         * @param snapshot The VmSnapShot containing the state to restore.
         */
        static void restoreSnapshot(VirtualMachine& vm, const VmSnapShot& snapshot);

    private:
        int m_fd{-1};
        int m_vcpuMmapSize{0};
        uint32_t m_nextSlot{0};

        std::vector<MemoryRegion> m_memoryRegions;
        std::vector<VCpu> m_vcpus;
    };
} // namespace kvm