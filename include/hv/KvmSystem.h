#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <expected>
#include <system_error>
#include <filesystem>

namespace kvm
{
    class VirtualMachine;

    /**
     * @brief Represents the top-level KVM subsystem handle.
     *
     * KvmSystem wraps /dev/kvm and exposes factory methods for creating
     * VirtualMachine instances. Exactly one KvmSystem should exist per process.
     * Copyable/movable semantics are deleted; use shared_ptr or pass by reference.
     */
    class KvmSystem
    {
    public:
        /**
         * @brief Open /dev/kvm and verify the KVM API version.
         * @param kvm_device Path to the KVM device node (default: /dev/kvm).
         * @return An initialised KvmSystem on success, or an error_code on failure.
         */
        [[nodiscard]] static std::expected<KvmSystem, std::error_code>
        open(const std::filesystem::path& kvm_device = "/dev/kvm");

        ~KvmSystem();

        KvmSystem(const KvmSystem&) = delete;
        KvmSystem& operator=(const KvmSystem&) = delete;
        KvmSystem(KvmSystem&&) noexcept;
        KvmSystem& operator=(KvmSystem&&) noexcept;

        /**
         * @brief Create a new virtual machine.
         * @return A heap-allocated VirtualMachine on success, or an error_code.
         */
        [[nodiscard]] std::expected<std::unique_ptr<VirtualMachine>, std::error_code> createVm() const;

        /**
         * @brief Query the size of the per-vCPU mmap region.
         * @return Number of bytes required for the kvm_run structure.
         */
        [[nodiscard]] int vcpuMmapSize() const noexcept;

        /**
         * @brief Raw file descriptor for the KVM device.
         * @return The fd; valid only while this object is alive.
         */
        [[nodiscard]] int fd() const noexcept;

        /**
         * @brief KVM API version reported by the kernel.
         */
        [[nodiscard]] int apiVersion() const noexcept;

        /**
         * @brief Check if a specific KVM capability is supported by the kernel.
         * @param capability KVM capability ID (e.g. KVM_CAP_USER_MEMORY).
         * @return true if supported, false otherwise.
         */
        [[nodiscard]] bool checkExtension(int capability) const noexcept;

    private:
        explicit KvmSystem(int fd, int api_version, int vcpu_mmap_size) noexcept;

        int m_fd{-1};
        int m_apiVersion{0};
        int m_vcpuMmapSize{0};
    };

} // namespace kvm