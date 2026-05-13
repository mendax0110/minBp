add_executable(kvm_hypervisor_tests
        testHypervisor.cpp
)

target_link_libraries(kvm_hypervisor_tests
        PRIVATE
        kvm_hypervisor_lib
        GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(kvm_hypervisor_tests)
