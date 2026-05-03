#pragma once

#include "VCpu.h"

#include <functional>
#include <memory>
#include <optional>

namespace kvm
{
    class CpuidHandler;
    class IoPortHandler;
    class MsrHandler;
    class EventDispatcher;

    /**
     * @brief Run-loop that processes vCPU exits and dispatches them to handlers.
     *
     * InstructionTrapper owns the main execution loop for a single vCPU.  On each
     * KVM_RUN exit it classifies the reason and forwards to the appropriate
     * specialised handler.  A "continue" flag returned by each handler controls
     * whether the loop should re-enter the guest.
     *
     * @par Design pattern
     * Strategy + Chain-of-Responsibility: each handler is a swappable strategy; the
     * trapper sequences them without knowing their implementation details.
     */
    class InstructionTrapper
    {
    public:
        /**
         * @brief Outcome of a single trap dispatch iteration.
         */
        enum class RunResult
        {
            Continue,    ///< Re-enter the guest.
            Halt,        ///< Guest executed HLT; stop normally.
            Shutdown,    ///< Guest triple-faulted / issued shutdown.
            Error,       ///< Unrecoverable host-side error.
        };

        /**
         * @brief Construct a trapper for the given vCPU.
         * @param vcpu Non-owning pointer to the vCPU to control.
         * @param cpuid CPUID leaf handler (may be nullptr = passthrough).
         * @param io I/O port handler   (may be nullptr = passthrough).
         * @param msr  MSR handler        (may be nullptr = passthrough).
         * @param dispatch Event dispatcher for VMI notifications (may be nullptr).
         */
        InstructionTrapper(VCpu* vcpu,
                           CpuidHandler*    cpuid,
                           IoPortHandler*   io,
                           MsrHandler*      msr,
                           EventDispatcher* dispatch) noexcept;

        ~InstructionTrapper() = default;

        InstructionTrapper(const InstructionTrapper&) = delete;
        InstructionTrapper& operator=(const InstructionTrapper&) = delete;
        InstructionTrapper(InstructionTrapper&&) = default;
        InstructionTrapper& operator=(InstructionTrapper&&) = default;

        /**
         * @brief Run the guest until halt, shutdown, or an unhandled exit.
         * @param max_iterations Optional limit on iterations (0 = unlimited).
         * @return The final RunResult explaining why the loop stopped.
         */
        [[nodiscard]] RunResult runLoop(uint64_t max_iterations = 0);

        /**
         * @brief Process exactly one vCPU exit.
         * @return RunResult for that single iteration.
         */
        [[nodiscard]] RunResult step();

        /**
         * @brief Total number of exits processed since construction.
         */
        [[nodiscard]] uint64_t exitCount() const noexcept;

    private:
        [[nodiscard]] RunResult dispatchExit(ExitReason reason) const;

        VCpu* m_vcpu{nullptr};
        CpuidHandler* m_cpuid{nullptr};
        IoPortHandler* m_io{nullptr};
        MsrHandler* m_msr{nullptr};
        EventDispatcher* m_dispatch{nullptr};
        uint64_t m_exitCount{0};
    };
} // namespace kvm