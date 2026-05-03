#pragma once

#include <cstdint>
#include <memory>
#include <expected>
#include <system_error>
#include <functional>
#include <linux/kvm.h>

namespace kvm
{

    /**
     * @brief Exit reason categories returned after KVM_RUN.
     */
    enum class ExitReason : uint32_t
    {
        Unknown = KVM_EXIT_UNKNOWN,
        Io = KVM_EXIT_IO,
        Hypercall = KVM_EXIT_HYPERCALL,
        Debug = KVM_EXIT_DEBUG,
        Hlt = KVM_EXIT_HLT,
        Mmio = KVM_EXIT_MMIO,
        IrqWindowOpen = KVM_EXIT_IRQ_WINDOW_OPEN,
        Shutdown = KVM_EXIT_SHUTDOWN,
        FailEntry = KVM_EXIT_FAIL_ENTRY,
        Intr = KVM_EXIT_INTR,
        SetTpr = KVM_EXIT_SET_TPR,
        TprAccess = KVM_EXIT_TPR_ACCESS,
        S390Sieic = KVM_EXIT_S390_SIEIC,
        S390Reset = KVM_EXIT_S390_RESET,
        Dcr = KVM_EXIT_DCR,
        Nmi = KVM_EXIT_NMI,
        InternalError = KVM_EXIT_INTERNAL_ERROR,
        Osi = KVM_EXIT_OSI,
        PaprHcall = KVM_EXIT_PAPR_HCALL,
        SystemEvent = KVM_EXIT_SYSTEM_EVENT,
    };

    /**
     * @brief Wraps a KVM vCPU file descriptor and its associated kvm_run page.
     *
     * Each VCpu owns one fd obtained via KVM_CREATE_VCPU and a corresponding
     * kvm_run structure obtained by mmapping that fd.  The kvm_run page is the
     * primary communication channel between host and guest.
     */
    class VCpu
    {
    public:
        /**
         * @brief Create a vCPU inside the given VM.
         * @param vm_fd         File descriptor of the owning VM.
         * @param vcpu_id       Logical vCPU index (0-based).
         * @param mmap_size     Result of KVM_GET_VCPU_MMAP_SIZE.
         * @return Initialised VCpu on success, or an error_code.
         */
        [[nodiscard]] static std::expected<VCpu, std::error_code>
        create(int vm_fd, uint32_t vcpu_id, int mmap_size);

        ~VCpu();

        VCpu(const VCpu&)            = delete;
        VCpu& operator=(const VCpu&) = delete;
        VCpu(VCpu&&) noexcept;
        VCpu& operator=(VCpu&&) noexcept;

        /**
         * @brief Run the vCPU until an exit event occurs.
         * @return The exit reason on success, or an error_code if KVM_RUN fails.
         */
        [[nodiscard]] std::expected<ExitReason, std::error_code> run() const;

        /**
         * @brief Get all general-purpose registers.
         * @param regs Output parameter populated on success.
         */
        [[nodiscard]] std::expected<kvm_regs, std::error_code> getRegs() const;

        /**
         * @brief Set all general-purpose registers.
         * @param regs Register values to apply.
         */
        [[nodiscard]] std::error_code setRegs(const kvm_regs& regs) const;

        /**
         * @brief Get all special registers (segments, CRs, etc.).
         */
        [[nodiscard]] std::expected<kvm_sregs, std::error_code> getSregs() const;

        /**
         * @brief Set all special registers.
         */
        [[nodiscard]] std::error_code setSregs(const kvm_sregs& sregs) const;

        /**
         * @brief Access the kvm_run structure for this vCPU.
         * @return Pointer into the mmap region; valid for the lifetime of VCpu.
         */
        [[nodiscard]] kvm_run* kvmRun() const noexcept;

        /**
         * @brief Raw vCPU file descriptor.
         */
        [[nodiscard]] int fd() const noexcept;

        /**
         * @brief Logical vCPU index.
         */
        [[nodiscard]] uint32_t id() const noexcept;

        /**
         * @brief Enable or disable single-step guest execution (KVM_GUESTDBG_*).
         * @param enable True to enable single-step debug mode.
         */
        [[nodiscard]] std::error_code setSingleStep(bool enable) const;

        /**
         * @brief Install a custom CPUID leaf table for this vCPU.
         * @param entries Vector of kvm_cpuid_entry2 structures defining the leaf table.
         */
        [[nodiscard]] std::error_code installCpuid(const std::vector<kvm_cpuid_entry2>& entries) const;

    private:
        VCpu(int fd, uint32_t id, kvm_run* run_page, std::size_t mmap_size) noexcept;

        int m_fd{-1};
        uint32_t m_id{0};
        kvm_run* m_runPage{nullptr};
        std::size_t m_mmapSize{0};
    };
} // namespace kvm