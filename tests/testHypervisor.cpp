#include <gtest/gtest.h>

#include "hv/CpuidHandler.h"
#include "hv/EventDispatcher.h"
#include "hv/MmioHandler.h"

#include <cstring>

using namespace kvm;

TEST(EventDispatcherTests, PublishRoutesTypeSpecificAndCatchAllSubscribers)
{
    EventDispatcher dispatcher;

    int ioReads = 0;
    int catchAll = 0;

    const auto ioId = dispatcher.subscribe(EventType::IoRead, [&](const HvEvent&)
    {
        ++ioReads;
    });

    const auto allId = dispatcher.subscribeAll([&](const HvEvent&)
    {
        ++catchAll;
    });

    (void) ioId;
    (void) allId;

    const HvEvent ioEvent{
        .type = EventType::IoRead,
        .vcpu_id = 0,
        .rip = 0x1000,
        .timestamp = std::chrono::steady_clock::now(),
        .payload = IoEvent{.port = 0x60, .size = 1, .value = 0x41, .isWrite = false}
    };

    const HvEvent msrEvent{
        .type = EventType::MsrWrite,
        .vcpu_id = 0,
        .rip = 0x2000,
        .timestamp = std::chrono::steady_clock::now(),
        .payload = MsrEvent{.index = 0xC0000080, .value = 0, .isWrite = true}
    };

    dispatcher.publish(ioEvent);
    dispatcher.publish(msrEvent);

    EXPECT_EQ(ioReads, 1);
    EXPECT_EQ(catchAll, 2);
    EXPECT_EQ(dispatcher.publishedCount(), 2);
}

TEST(EventDispatcherTests, UnsubscribeStopsNotifications)
{
    EventDispatcher dispatcher;
    int calls = 0;

    const auto id = dispatcher.subscribe(EventType::GuestHalt, [&](const HvEvent&)
    {
        ++calls;
    });

    dispatcher.unsubscribe(id);

    dispatcher.publish(HvEvent{
        .type = EventType::GuestHalt,
        .vcpu_id = 0,
        .rip = 0,
        .timestamp = std::chrono::steady_clock::now(),
        .payload = std::monostate{}
    });

    EXPECT_EQ(calls, 0);
    EXPECT_EQ(dispatcher.publishedCount(), 1);
}

TEST(CpuidHandlerTests, ExecuteHostCpuidReturnsVendorLeafData)
{
    const auto leaf0 = CpuidHandler::executeHostCpuid(0, 0);

    EXPECT_GT(leaf0.eax, 0u);
    EXPECT_NE(leaf0.ebx, 0u);
    EXPECT_NE(leaf0.ecx, 0u);
    EXPECT_NE(leaf0.edx, 0u);
}

TEST(MmioHandlerTests, ReadCallbackWritesValueBackToRunBuffer)
{
    MmioHandler mmio;

    mmio.registerRead(0xFEE00030, [](const MmioHandler::ReadContext& ctx)
    {
        EXPECT_EQ(ctx.addr, 0xFEE00030u);
        EXPECT_EQ(ctx.size, 4u);
        return 0x11223344u;
    });

    kvm_run run{};
    run.exit_reason = KVM_EXIT_MMIO;
    run.mmio.phys_addr = 0xFEE00030;
    run.mmio.len = 4;
    run.mmio.is_write = 0;

    ASSERT_TRUE(mmio.handle(run));

    uint32_t value = 0;
    std::memcpy(&value, run.mmio.data, sizeof(value));
    EXPECT_EQ(value, 0x11223344u);
    EXPECT_EQ(mmio.readCount(), 1);
    EXPECT_EQ(mmio.writeCount(), 0);
}

TEST(MmioHandlerTests, WriteCallbackReceivesDecodedValue)
{
    MmioHandler mmio;

    uint64_t capturedAddr = 0;
    uint8_t capturedSize = 0;
    uint64_t capturedValue = 0;

    mmio.registerWrite(0xFEE00040, [&](const MmioHandler::WriteContext& ctx)
    {
        capturedAddr = ctx.addr;
        capturedSize = ctx.size;
        capturedValue = ctx.value;
    });

    kvm_run run{};
    run.exit_reason = KVM_EXIT_MMIO;
    run.mmio.phys_addr = 0xFEE00040;
    run.mmio.len = 8;
    run.mmio.is_write = 1;

    const uint64_t writeValue = 0xAABBCCDD11223344ULL;
    std::memcpy(run.mmio.data, &writeValue, sizeof(writeValue));

    ASSERT_TRUE(mmio.handle(run));

    EXPECT_EQ(capturedAddr, 0xFEE00040u);
    EXPECT_EQ(capturedSize, 8u);
    EXPECT_EQ(capturedValue, writeValue);
    EXPECT_EQ(mmio.readCount(), 0);
    EXPECT_EQ(mmio.writeCount(), 1);
}
