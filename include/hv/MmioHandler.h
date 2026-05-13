#pragma once

#include <cstdint>
#include <functional>
#include <unordered_map>
#include <linux/kvm.h>

namespace kvm
{
    /**
     * @brief Handles KVM_EXIT_MMIO exits and dispatches read/write callbacks.
     */
    class MmioHandler
    {
    public:
        /// @brief Context passed to MMIO callbacks. \struct ReadContext
        struct ReadContext
        {
            uint64_t addr{0};
            uint8_t size{0};
        };

        /// @brief Context passed to MMIO callbacks. \struct WriteContext
        struct WriteContext
        {
            uint64_t addr{0};
            uint8_t size{0};
            uint64_t value{0};
        };

        /// @brief Callback type for MMIO reads.
        using ReadCallback = std::function<uint64_t(const ReadContext&)>;

        /// @brief Callback type for MMIO writes.
        using WriteCallback = std::function<void(const WriteContext&)>;

        /**
         * @brief Register a callback for MMIO reads at a specific address.
         * @param guest_phys_addr Guest physical address to intercept.
         * @param cb   Callback returning the value to deliver.
         */
        void registerRead(uint64_t guest_phys_addr, ReadCallback cb);

        /**
         * @brief Register a callback for MMIO writes at a specific address.
         * @param guest_phys_addr Guest physical address to intercept.
         * @param cb   Callback receiving the written value.
         */
        void registerWrite(uint64_t guest_phys_addr, WriteCallback cb);

        /**
         * @brief Handle a KVM_EXIT_MMIO exit by dispatching to the appropriate
         *        callback based on the exit qualification.
         * @param vcpu The vCPU that exited.
         * @return true if the exit was handled, false if it should be treated
         *         as an unhandled exit.
         */
        [[nodiscard]] bool handle(const kvm_run& run);

        /**
         * @brief Getter for the read count.
         * @return The Read count.
         */
        [[nodiscard]] uint64_t readCount() const noexcept;

        /**
         * @brief Getter for the write count.
         * @return The Write count.
         */
        [[nodiscard]] uint64_t writeCount() const noexcept;

    private:
        std::unordered_map<uint64_t, ReadCallback> m_readCallbacks;
        std::unordered_map<uint64_t, WriteCallback> m_writeCallbacks;
        uint64_t m_readCount{0};
        uint64_t m_writeCount{0};
    };
} // namespace kvm
