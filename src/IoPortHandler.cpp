#include "hv/IoPortHandler.h"
#include "hv/VCpu.h"
#include <cstring>

using namespace kvm;

void IoPortHandler::registerInPort(const uint16_t port, InCallback cb)
{
    m_inCallbacks[port] = std::move(cb);
}

void IoPortHandler::registerOutPort(const uint16_t port, OutCallback cb)
{
    m_outCallbacks[port] = std::move(cb);
}

bool IoPortHandler::handle(VCpu& vcpu, const kvm_run& run)
{
    const auto& io = run.io;
    const uint16_t port = io.port;
    const uint8_t size = io.size;
    const uint32_t count = io.count;

    auto* dataPtr = reinterpret_cast<const uint8_t*>(&run) + run.io.data_offset;

    if (io.direction == KVM_EXIT_IO_OUT)
    {
        uint32_t value = 0;
        std::memcpy(&value, dataPtr, std::min<uint8_t>(size, 4));

        const OutContext ctx{port, size, value, count};
        if (const auto it = m_outCallbacks.find(port); it != m_outCallbacks.end())
        {
            it->second(ctx);
        }

        ++m_outCount;
    }
    else
    {
        const InContext ctx{port, size, count};
        uint32_t result = 0xFFFFFFFF;

        if (const auto it = m_inCallbacks.find(port); it != m_inCallbacks.end())
        {
            result = it->second(ctx);
        }

        auto* outPtr = reinterpret_cast<uint8_t*>(const_cast<kvm_run*>(&run)) + run.io.data_offset;
        std::memcpy(outPtr, &result, std::min<uint8_t>(size, 4));

        ++m_inCount;
    }

    return true;
}

uint64_t IoPortHandler::inCount() const noexcept
{
    return m_inCount;
}

uint64_t IoPortHandler::outCount() const noexcept
{
    return m_outCount;
}
