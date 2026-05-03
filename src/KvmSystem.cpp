#include "hv/KvmSystem.h"
#include "hv/VirtualMachine.h"
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <linux/kvm.h>
#include <cerrno>
#include <cstring>
#include <utility>

using namespace kvm;

std::expected<KvmSystem, std::error_code> KvmSystem::open(const std::filesystem::path& kvm_device)
{
    const int fd = ::open(kvm_device.c_str(), O_RDWR | O_CLOEXEC);
    if (fd < 0)
    {
        return std::unexpected(std::error_code(errno, std::generic_category()));
    }

    const int version = ::ioctl(fd, KVM_GET_API_VERSION, 0);
    if (version < 0)
    {
        ::close(fd);
        return std::unexpected(std::error_code(errno, std::generic_category()));
    }

    if (version != KVM_API_VERSION)
    {
        ::close(fd);
        return std::unexpected(std::error_code(ENOTSUP, std::generic_category()));
    }

    const int mmapSize = ::ioctl(fd, KVM_GET_VCPU_MMAP_SIZE, 0);
    if (mmapSize < 0)
    {
        ::close(fd);
        return std::unexpected(std::error_code(errno, std::generic_category()));
    }

    return KvmSystem(fd, version, mmapSize);
}

KvmSystem::KvmSystem(const int fd, const int api_version, const int vcpu_mmap_size) noexcept
    : m_fd(fd)
    , m_apiVersion(api_version)
    , m_vcpuMmapSize(vcpu_mmap_size)
{

}

KvmSystem::~KvmSystem()
{
    if (m_fd >= 0)
    {
        ::close(m_fd);
    }
}

KvmSystem::KvmSystem(KvmSystem&& other) noexcept
    : m_fd(std::exchange(other.m_fd, -1))
    , m_apiVersion(other.m_apiVersion)
    , m_vcpuMmapSize(other.m_vcpuMmapSize)
{

}


KvmSystem& KvmSystem::operator=(KvmSystem&& other) noexcept
{
    if (this != &other)
    {
        if (m_fd >= 0)
        {
            ::close(m_fd);
            m_fd = std::exchange(other.m_fd, -1);
            m_apiVersion = other.m_apiVersion;
            m_vcpuMmapSize = other.m_vcpuMmapSize;
        }
    }
    return *this;
}

std::expected<std::unique_ptr<VirtualMachine>, std::error_code> KvmSystem::createVm() const
{
    const int vm_fd = ::ioctl(m_fd, KVM_CREATE_VM, 0);
    if (vm_fd < 0)
    {
        return std::unexpected(std::error_code(errno, std::generic_category()));
    }
    return std::make_unique<VirtualMachine>(vm_fd, m_vcpuMmapSize);
}

int KvmSystem::vcpuMmapSize() const noexcept
{
    return m_vcpuMmapSize;
}

int KvmSystem::fd() const noexcept
{
    return m_fd;
}

int KvmSystem::apiVersion() const noexcept
{
    return m_apiVersion;
}

bool KvmSystem::checkExtension(const int capability) const noexcept
{
    return ::ioctl(m_fd, KVM_CHECK_EXTENSION, capability) > 0;
}
