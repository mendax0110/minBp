#pragma once

#include <cstdint>
#include <functional>
#include <vector>
#include <string>
#include <chrono>
#include <variant>
#include <any>

namespace kvm
{
    /**
     * @brief Enumeration of event types published by the hypervisor.
     */
    enum class EventType : uint32_t
    {
        CpuidAccess = 0x01,   ///< Guest executed CPUID.
        IoRead = 0x02,   ///< Guest executed IN.
        IoWrite = 0x03,   ///< Guest executed OUT.
        MsrRead = 0x04,   ///< Guest executed RDMSR.
        MsrWrite = 0x05,   ///< Guest executed WRMSR.
        MemAccess = 0x06,   ///< Guest accessed monitored memory (MMIO/EPT).
        GuestHalt = 0x07,   ///< Guest executed HLT.
        GuestShutdown= 0x08,   ///< Guest shutdown/triple fault.
    };

    /**
     * @brief Payload associated with a CpuidAccess event.
     */
    struct CpuidEvent
    {
        uint32_t leaf{0};
        uint32_t subleaf{0};
        uint32_t eax{0}, ebx{0}, ecx{0}, edx{0};
    };

    /**
     * @brief Payload associated with an I/O port event.
     */
    struct IoEvent
    {
        uint16_t port{0};
        uint8_t size{0};
        uint32_t value{0};
        bool isWrite{false};
    };

    /**
     * @brief Payload associated with an MSR event.
     */
    struct MsrEvent
    {
        uint32_t index{0};
        uint64_t value{0};
        bool isWrite{false};
    };

    /**
     * @brief Union-like event payload.
     */
    using EventPayload = std::variant<CpuidEvent, IoEvent, MsrEvent, std::monostate>;

    /**
     * @brief A single hypervisor event record.
     */
    struct HvEvent
    {
        EventType type;
        uint32_t vcpu_id{0};
        uint64_t rip{0};         ///< Guest RIP at the time of the event.
        std::chrono::steady_clock::time_point timestamp;
        EventPayload payload;
    };

    /**
     * @brief Publish-subscribe event bus for VMI notifications.
     *
     * The EventDispatcher decouples the hypervisor's run-loop from VMI
     * consumers (loggers, analysers, etc.).  Handlers registered via
     * subscribe() are called synchronously during the vCPU exit handler.
     *
     * @par Design pattern
     * Observer / event-bus.
     */
    class EventDispatcher
    {
    public:
        /**
         * @brief Subscription handle. Returned by subscribe(); passed to unsubscribe().
         */
        using SubscriptionId = uint32_t;

        /**
         * @brief Callback type for event subscribers.
         */
        using Handler = std::function<void(const HvEvent&)>;

        EventDispatcher() = default;
        ~EventDispatcher() = default;

        /**
         * @brief Register a handler for all events of a given type.
         * @param type    Event type to watch.
         * @param handler Callback to invoke on each matching event.
         * @return Opaque subscription ID that can be passed to unsubscribe().
         */
        [[nodiscard]] SubscriptionId subscribe(EventType type, Handler handler);

        /**
         * @brief Register a catch-all handler for every event type.
         * @param handler Callback to invoke on all events.
         * @return Opaque subscription ID.
         */
        [[nodiscard]] SubscriptionId subscribeAll(Handler handler);

        /**
         * @brief Unregister a previously registered handler.
         * @param id Subscription ID returned by subscribe() or subscribeAll().
         */
        void unsubscribe(SubscriptionId id);

        /**
         * @brief Dispatch an event to all matching subscribers.
         * @param event The event to publish.
         */
        void publish(const HvEvent& event);

        /**
         * @brief Total number of events published since construction.
         */
        [[nodiscard]] uint64_t publishedCount() const noexcept;

    private:
        struct Subscription
        {
            SubscriptionId id{0};
            std::optional<EventType> filter;   ///< nullopt = catch-all.
            Handler handler;
        };

        std::vector<Subscription> m_subscriptions;
        SubscriptionId m_nextId{1};
        uint64_t m_publishedCount{0};
    };
} // namespace kvm