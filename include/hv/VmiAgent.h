#pragma once

#include "EventDispatcher.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include <filesystem>
#include <functional>
#include <optional>
#include <chrono>

namespace kvm
{
    class VirtualMachine;
    class MemoryRegion;

    /**
     * @brief Snapshot of guest register state captured during introspection.
     */
    struct GuestSnapshot
    {
        uint64_t rip{0}, rsp{0}, rax{0}, rbx{0}, rcx{0}, rdx{0};
        uint64_t rsi{0}, rdi{0}, r8{0},  r9{0},  r10{0}, r11{0};
        uint64_t r12{0}, r13{0}, r14{0}, r15{0};
        uint64_t rflags{0};
        uint64_t cr0{0}, cr3{0}, cr4{0};
        std::chrono::steady_clock::time_point timestamp;
    };

    /**
     * @brief Lightweight VMI (Virtual Machine Introspection) agent.
     *
     * VmiAgent subscribes to the EventDispatcher and augments events with
     * additional context (register snapshots, memory dumps, call-trace heuristics).
     * It also exposes an API for out-of-band memory reads so that external analysis
     * tools can inspect guest state without modifying guest execution.
     *
     * @par Design pattern
     * Decorator over EventDispatcher — it subscribes as a normal observer but
     * enriches the data stream before forwarding to user-supplied callbacks.
     */
    class VmiAgent
    {
    public:
        /**
         * @brief Enriched introspection event.
         */
        struct IntrospectionEvent
        {
            HvEvent base;         ///< Original hypervisor event.
            GuestSnapshot snapshot;     ///< Register state at time of event.
            std::optional<std::vector<uint8_t>> memDump; ///< Optional memory dump.
            std::string summary;      ///< Human-readable description.
        };

        /**
         * @brief Callback type for introspection consumers.
         */
        using IntrospectionCallback = std::function<void(const IntrospectionEvent&)>;

        /**
         * @brief Construct a VmiAgent attached to a VM and dispatcher.
         * @param vm       Non-owning pointer to the VM under inspection.
         * @param dispatch Non-owning pointer to the event dispatcher.
         */
        VmiAgent(VirtualMachine* vm, EventDispatcher* dispatch);

        ~VmiAgent();

        VmiAgent(const VmiAgent&) = delete;
        VmiAgent& operator=(const VmiAgent&) = delete;
        VmiAgent(VmiAgent&&) = default;
        VmiAgent& operator=(VmiAgent&&)= default;

        /**
         * @brief Register a callback to receive enriched introspection events.
         * @param cb Callback invoked for every event the agent processes.
         */
        void onEvent(IntrospectionCallback cb);

        /**
         * @brief Enable capture of a memory region dump with each event.
         * @param guest_phys_addr Base address to dump.
         * @param size            Number of bytes to include in each dump.
         */
        void enableMemoryDump(uint64_t guest_phys_addr, std::size_t size);

        /**
         * @brief Disable memory dump capture.
         */
        void disableMemoryDump();

        /**
         * @brief Read raw bytes from guest-physical memory.
         * @param guest_phys_addr Guest-physical address to start reading.
         * @param size            Number of bytes to read.
         * @return Byte vector on success, empty on failure.
         */
        [[nodiscard]] std::vector<uint8_t> readGuestPhysMemory(uint64_t guest_phys_addr, std::size_t size) const;

        /**
         * @brief Dump the current guest register state for a given vCPU index.
         * @param vcpu_index Index into the VM's vCPU list.
         * @return GuestSnapshot populated with current register values.
         */
        [[nodiscard]] std::optional<GuestSnapshot> snapshotRegisters(uint32_t vcpu_index = 0) const;

        /**
         * @brief Emit a JSON-formatted event log to a file.
         * @param path Output path.
         */
        void dumpEventLog(const std::filesystem::path& path) const;

        /**
         * @brief All introspection events collected since construction.
         */
        [[nodiscard]] const std::vector<IntrospectionEvent>& eventLog() const noexcept;

    private:
        void handleHvEvent(const HvEvent& event);
        [[nodiscard]] static std::string buildSummary(const HvEvent& event, const GuestSnapshot& snap);

        VirtualMachine* m_vm{nullptr};
        EventDispatcher* m_dispatch{nullptr};

        std::vector<IntrospectionCallback> m_callbacks;
        std::vector<IntrospectionEvent> m_eventLog;

        EventDispatcher::SubscriptionId m_subId{0};

        bool m_memDumpEnabled{false};
        uint64_t m_memDumpAddr{0};
        std::size_t m_memDumpSize{0};
    };
} // namespace kvm