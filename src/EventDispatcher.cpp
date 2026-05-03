#include "hv/EventDispatcher.h"
#include <algorithm>
#include <ranges>

using namespace kvm;

EventDispatcher::SubscriptionId EventDispatcher::subscribe(EventType type, Handler handler)
{
    const SubscriptionId id = m_nextId++;
    m_subscriptions.push_back(Subscription{id, type, std::move(handler)});
    return id;
}

EventDispatcher::SubscriptionId EventDispatcher::subscribeAll(Handler handler)
{
    const SubscriptionId id = m_nextId++;
    m_subscriptions.push_back(Subscription{id, std::nullopt, std::move(handler)});
    return id;
}

void EventDispatcher::unsubscribe(SubscriptionId id)
{
    std::erase_if(m_subscriptions, [id](const Subscription& s)
    {
       return s.id == id;
    });
}

void EventDispatcher::publish(const HvEvent& event)
{
    ++m_publishedCount;
    for (const auto& sub : m_subscriptions)
    {
        if (!sub.filter.has_value() || sub.filter.value() == event.type)
        {
            sub.handler(event);
        }
    }
}

uint64_t EventDispatcher::publishedCount() const noexcept
{
    return m_publishedCount;
}
