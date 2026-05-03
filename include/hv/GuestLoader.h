#pragma once

#include <cstdint>
#include <filesystem>
#include <expected>
#include <system_error>
#include <span>
#include <vector>

namespace kvm
{
    class VirtualMachine;
    class VCpu;

    /**
     * @brief Load mode for the guest payload.
     */
    enum class GuestLoadMode
    {
        FlatBinary,  ///< Raw binary loaded at a fixed guest-physical address.
        RealMode16,  ///< 16-bit real-mode binary placed at 0x7C00 (boot sector).
    };

    /**
     * @brief Parameters describing how to load a guest binary.
     */
    struct GuestLoadParams
    {
        std::filesystem::path imagePath;         ///< Path to the binary.
        GuestLoadMode mode{GuestLoadMode::FlatBinary};
        uint64_t loadAddress{0};    ///< Guest-physical load address.
        uint64_t entryPoint{0};     ///< Guest RIP after load (flat binary).
        size_t memorySize{1 << 22}; ///< Total guest RAM (default 4 MiB).
    };

    /**
     * @brief Utility class that sets up guest memory and vCPU registers for a
     *        freshly created VM.
     *
     * GuestLoader is intentionally a collection of static helpers so that it can
     * be used without constructing a persistent object.
     */
    class GuestLoader
    {
    public:
        GuestLoader() = delete;
        ~GuestLoader() = delete;

        /**
         * @brief Load a binary image into guest memory and configure vCPU state.
         * @param vm     Target VM (must have no memory regions or vCPUs yet).
         * @param params Load parameters.
         * @return Default-constructed error_code on success, error on failure.
         */
        [[nodiscard]] static std::error_code load(VirtualMachine& vm, const GuestLoadParams& params);

        /**
         * @brief Load a raw byte span into a VirtualMachine (for unit tests).
         * @param vm          Target VM.
         * @param code        Guest machine code bytes.
         * @param load_addr   Guest-physical address to place the code.
         * @param memory_size Total guest RAM.
         */
        [[nodiscard]] static std::error_code
        loadBytes(VirtualMachine& vm,
                  std::span<const uint8_t> code,
                  uint64_t load_addr   = 0x1000,
                  std::size_t memory_size = 1 << 22);

        /**
         * @brief Configure a vCPU for 16-bit real mode.
         * @param vcpu      The vCPU to configure.
         * @param entry_ip  Initial IP (segment 0).
         */
        [[nodiscard]] static std::error_code setupRealModeVCpu(const VCpu &vcpu, uint16_t entry_ip = 0);

        /**
         * @brief Configure a vCPU for 64-bit long mode with identity-mapped paging.
         * @param vcpu      The vCPU to configure.
         * @param rip       Initial RIP.
         * @param cr3       Page table base (guest-physical).
         */
        [[nodiscard]] static std::error_code setup64BitVCpu(const VCpu &vcpu, uint64_t rip, uint64_t cr3);

    private:
        [[nodiscard]] static std::vector<uint8_t> readFile(const std::filesystem::path& path);

        [[nodiscard]] static std::error_code buildIdentityPageTables(const VirtualMachine &vm, uint64_t base_addr);
    };
} // namespace kvm