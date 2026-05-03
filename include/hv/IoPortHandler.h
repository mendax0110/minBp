#pragma once

#include <cstdint>
#include <functional>
#include <unordered_map>
#include <span>
#include <linux/kvm.h>

namespace kvm
{
    class VCpu;

    /**
     * @brief Intercepts IN/OUT port I/O exits from the guest.
     *
     * The handler maintains two callback tables — one for IN (read) ports and one
     * for OUT (write) ports.  On a KVM_EXIT_IO event the appropriate callback is
     * looked up by port number.  Unregistered ports are silently ignored (read
     * ports return 0xFF).
     *
     * @par Thread safety
     * Not thread-safe.  All operations must occur on the vCPU thread.
     */
    class IoPortHandler
    {
    public:
        /**
         * @brief Direction of an I/O operation.
         */
        enum class Direction : uint8_t
        {
            In = KVM_EXIT_IO_IN,
            Out = KVM_EXIT_IO_OUT,
        };

        /**
         * @brief Context passed to IN (read) callbacks.
         */
        struct InContext
        {
            uint16_t port{0};     ///< I/O port number.
            uint8_t size{0};     ///< Operand size in bytes (1, 2, or 4).
            uint32_t count{0};    ///< REP prefix repetition count.
        };

        /**
         * @brief Context passed to OUT (write) callbacks.
         */
        struct OutContext
        {
            uint16_t port{0};     ///< I/O port number.
            uint8_t size{0};     ///< Operand size in bytes (1, 2, or 4).
            uint32_t value{0};    ///< Value written by the guest.
            uint32_t count{0};    ///< REP prefix repetition count.
        };

        /**
         * @brief Callback for IN instructions.  Returns the value to deliver.
         */
        using InCallback = std::function<uint32_t(const InContext&)>;

        /**
         * @brief Callback for OUT instructions.
         */
        using OutCallback = std::function<void(const OutContext&)>;

        IoPortHandler()  = default;
        ~IoPortHandler() = default;

        /**
         * @brief Register a handler for reads from a specific port.
         * @param port Port number.
         * @param cb   Callback returning the data to inject into AL/AX/EAX.
         */
        void registerInPort(uint16_t port, InCallback cb);

        /**
         * @brief Register a handler for writes to a specific port.
         * @param port Port number.
         * @param cb   Callback receiving the written value.
         */
        void registerOutPort(uint16_t port, OutCallback cb);

        /**
         * @brief Handle a KVM_EXIT_IO event for the given vCPU.
         * @param vcpu    The vCPU that triggered the exit.
         * @param run
         * @return true on success; false on fatal register error.
         */
        [[nodiscard]] bool handle(VCpu& vcpu, const kvm_run& run);

        /**
         * @brief Total IN exits handled.
         */
        [[nodiscard]] uint64_t inCount() const noexcept;

        /**
         * @brief Total OUT exits handled.
         */
        [[nodiscard]] uint64_t outCount() const noexcept;

    private:
        std::unordered_map<uint16_t, InCallback>  m_inCallbacks;
        std::unordered_map<uint16_t, OutCallback> m_outCallbacks;
        uint64_t m_inCount{0};
        uint64_t m_outCount{0};
    };
} // namespace kvm