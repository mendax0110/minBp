#pragma once

#include <cstdint>
#include <functional>
#include <unordered_map>
#include <optional>
#include <linux/kvm.h>

namespace kvm
{
    class VCpu;

    /**
     * @brief Intercepts and optionally rewrites CPUID exits.
     *
     * When the guest executes a CPUID instruction KVM exits to user-space.
     * CpuidHandler looks up the leaf (EAX) and optionally sub-leaf (ECX),
     * invokes a registered callback, and writes modified EAX/EBX/ECX/EDX back
     * to the guest registers before re-entering.
     *
     * @par Usage
     * Register per-leaf callbacks with registerLeaf().  Unregistered leaves are
     * forwarded to the host CPUID unchanged (pass-through behaviour).
     */
    class CpuidHandler
    {
    public:
        /**
         * @brief CPUID leaf output registers.
         */
        struct LeafResult
        {
            uint32_t eax{0};
            uint32_t ebx{0};
            uint32_t ecx{0};
            uint32_t edx{0};
        };

        /**
         * @brief Callback type for leaf handlers.
         * @param leaf    CPUID leaf (EAX input).
         * @param subleaf CPUID sub-leaf (ECX input).
         * @return Modified register values to inject.
         */
        using LeafCallback = std::function<LeafResult(uint32_t leaf, uint32_t subleaf)>;

        CpuidHandler()  = default;
        ~CpuidHandler() = default;

        CpuidHandler(const CpuidHandler&) = default;
        CpuidHandler& operator=(const CpuidHandler&) = default;
        CpuidHandler(CpuidHandler&&) = default;
        CpuidHandler& operator=(CpuidHandler&&) = default;

        /**
         * @brief Register a callback for a specific CPUID leaf.
         * @param leaf CPUID leaf value (EAX at time of CPUID).
         * @param callback Handler invoked on exit for this leaf.
         */
        void registerLeaf(uint32_t leaf, LeafCallback callback);

        /**
         * @brief Handle a KVM_EXIT_CPUID event for the given vCPU.
         *
         * Reads the leaf/subleaf from the vCPU registers, dispatches to a
         * registered callback (or executes the real host CPUID as passthrough),
         * then injects the result back into the guest register file.
         *
         * @param vcpu The vCPU that triggered the exit.
         * @return false if a fatal register read/write error occurred.
         */
        [[nodiscard]] bool handle(const VCpu& vcpu);

        /**
         * @brief Number of CPUID exits handled since construction.
         */
        [[nodiscard]] uint64_t handledCount() const noexcept;

        /**
         * @brief Execute the host CPUID instruction for a given leaf/subleaf.
         * @param leaf    CPUID leaf (EAX input).
         * @param subleaf CPUID sub-leaf (ECX input).
         * @return The raw CPUID output from the host CPU.
         */
        [[nodiscard]] static LeafResult executeHostCpuid(uint32_t leaf, uint32_t subleaf) noexcept;

    private:
        std::unordered_map<uint32_t, LeafCallback> m_leafCallbacks;
        uint64_t m_handledCount{0};
    };
} // namespace kvm