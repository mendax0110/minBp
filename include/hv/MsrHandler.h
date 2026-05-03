#pragma once

#include <cstdint>
#include <functional>
#include <unordered_map>
#include <expected>
#include <system_error>
#include <linux/kvm.h>

namespace kvm
{
    class VCpu;

    /**
     * @brief Intercepts RDMSR/WRMSR exits from the guest.
     *
     * MSR accesses that are not handled in-kernel cause a KVM_EXIT_MSR exit.
     * MsrHandler maintains per-MSR read/write callbacks.  Unregistered reads
     * return 0; unregistered writes are silently discarded.
     *
     * @note To receive MSR exits the hypervisor must first call
     *       KVM_X86_SET_MSR_FILTER with an appropriate bitmap.
     */
    class MsrHandler
    {
    public:
        /**
         * @brief Callback for RDMSR.  Returns the 64-bit value to deliver.
         */
        using ReadCallback = std::function<uint64_t(uint32_t msr_index)>;

        /**
         * @brief Callback for WRMSR.
         */
        using WriteCallback = std::function<void(uint32_t msr_index, uint64_t value)>;

        MsrHandler() = default;
        ~MsrHandler() = default;

        /**
         * @brief Register a callback for RDMSR on a specific index.
         * @param msr_index MSR address.
         * @param cb        Callback returning the value to deliver.
         */
        void registerRead(uint32_t msr_index, ReadCallback cb);

        /**
         * @brief Register a callback for WRMSR on a specific index.
         * @param msr_index MSR address.
         * @param cb        Callback receiving the written value.
         */
        void registerWrite(uint32_t msr_index, WriteCallback cb);

        /**
         * @brief Install the MSR filter bitmap into the VM so that registered
         *        MSRs cause exits instead of being handled in-kernel.
         * @param vm_fd File descriptor of the owning VM.
         * @return std::error_code on failure, default-constructed on success.
         */
        [[nodiscard]] std::error_code installFilter(int vm_fd) const;

        /**
         * @brief Handle a KVM_EXIT_MSR event.
         * @param vcpu The vCPU that triggered the exit.
         * @param run  Reference to the full kvm_run structure.
         * @return true on success.
         */
        [[nodiscard]] bool handle(const VCpu& vcpu, const kvm_run& run);

        /**
         * @brief Total RDMSR exits handled.
         */
        [[nodiscard]] uint64_t readCount() const noexcept;

        /**
         * @brief Total WRMSR exits handled.
         */
        [[nodiscard]] uint64_t writeCount() const noexcept;

    private:
        std::unordered_map<uint32_t, ReadCallback>  m_readCallbacks;
        std::unordered_map<uint32_t, WriteCallback> m_writeCallbacks;
        uint64_t m_readCount{0};
        uint64_t m_writeCount{0};
    };
} // namespace kvm