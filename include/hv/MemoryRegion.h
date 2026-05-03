#pragma once

#include <cstdint>
#include <cstddef>
#include <span>
#include <expected>
#include <system_error>

namespace kvm
{
    /**
     * @brief Describes a contiguous region of guest-physical memory.
     *
     * MemoryRegion owns a host-side anonymous mmap that is registered with the VM
     * via KVM_SET_USER_MEMORY_REGION.  On destruction the mmap is released and the
     * slot is unregistered.
     */
    class MemoryRegion
    {
    public:
        /**
         * @brief Allocate and map a guest-physical memory region.
         * @param vm_fd File descriptor of the owning VM.
         * @param slot  KVM memory slot index (unique per VM).
         * @param guest_phys_addr Base guest-physical address.
         * @param size_bytes Region size in bytes (must be page-aligned).
         * @param flags KVM_MEM_* flags (e.g. KVM_MEM_READONLY).
         * @return Initialised MemoryRegion on success, or an error_code.
         */
        [[nodiscard]] static std::expected<MemoryRegion, std::error_code> create(
            int vm_fd,
            uint32_t slot,
            uint64_t guest_phys_addr,
            std::size_t size_bytes,
            uint32_t flags = 0);

        ~MemoryRegion();

        MemoryRegion(const MemoryRegion&) = delete;
        MemoryRegion& operator=(const MemoryRegion&) = delete;
        MemoryRegion(MemoryRegion&&) noexcept;
        MemoryRegion& operator=(MemoryRegion&&) noexcept;

        /**
         * @brief Host virtual address of the mapped memory.
         */
        [[nodiscard]] void* hostAddr() const noexcept;

        /**
         * @brief Guest-physical base address.
         */
        [[nodiscard]] uint64_t guestPhysAddr() const noexcept;

        /**
         * @brief Region size in bytes.
         */
        [[nodiscard]] size_t size() const noexcept;

        /**
         * @brief Write arbitrary bytes into the region at a guest-physical offset.
         * @param guest_offset Byte offset from guestPhysAddr().
         * @param data Source data span.
         */
        void write(size_t guest_offset, std::span<const std::byte> data) const;

        /**
         * @brief Read arbitrary bytes from the region at a guest-physical offset.
         * @param guest_offset Byte offset from guestPhysAddr().
         * @param out Destination span (sized by caller).
         */
        void read(size_t guest_offset, std::span<std::byte> out) const;

    private:
        MemoryRegion(int vm_fd, uint32_t slot, uint64_t guest_phys_addr, size_t size, void* host_addr) noexcept;

        int  m_vmFd{-1};
        uint32_t m_slot{0};
        uint64_t m_guestPhysAddr{0};
        size_t m_size{0};
        void* m_hostAddr{nullptr};
    };
} // namespace kvm