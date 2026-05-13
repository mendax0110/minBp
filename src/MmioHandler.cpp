#include "hv/MmioHandler.h"

#include <algorithm>
#include <cstring>

using namespace kvm;

void MmioHandler::registerRead(const uint64_t guest_phys_addr, ReadCallback cb)
{
    m_readCallbacks[guest_phys_addr] = std::move(cb);
}

void MmioHandler::registerWrite(const uint64_t guest_phys_addr, WriteCallback cb)
{
    m_writeCallbacks[guest_phys_addr] = std::move(cb);
}

bool MmioHandler::handle(const kvm_run& run)
{
    const auto&[phys_addr, data, len, is_write] = run.mmio;
    const uint64_t addr = phys_addr;
    const uint8_t size = len;

    if (size == 0 || size > 8)
    {
        return false;
    }

    if (is_write)
    {
        uint64_t value = 0;
        std::memcpy(&value, data, std::min<uint8_t>(size, 8));

        if (const auto it = m_writeCallbacks.find(addr); it != m_writeCallbacks.end())
        {
            it->second(WriteContext{addr, size, value});
        }

        ++m_writeCount;
        return true;
    }

    uint64_t value = 0xFFFF'FFFF'FFFF'FFFFULL;
    if (const auto it = m_readCallbacks.find(addr); it != m_readCallbacks.end())
    {
        value = it->second(ReadContext{addr, size});
    }

    auto* out = const_cast<uint8_t*>(data);
    std::memcpy(out, &value, size);

    ++m_readCount;
    return true;
}

uint64_t MmioHandler::readCount() const noexcept
{
    return m_readCount;
}

uint64_t MmioHandler::writeCount() const noexcept
{
    return m_writeCount;
}
