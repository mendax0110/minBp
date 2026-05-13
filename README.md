# minBp - Minimal KVM Hypervisor

A Type-2 hypervisor built on the Linux KVM API. Runs a guest VM in userspace,
intercepts instruction-level exits, and provides a Virtual Machine Introspection
(VMI) agent for transparent guest monitoring.

## What it does

- Creates and manages a KVM virtual machine from userspace
- Traps and handles `IN`/`OUT` port I/O exits with registered callbacks
- Traps and handles `KVM_EXIT_MMIO` reads/writes with guest-physical address callbacks
- Builds and installs a CPUID table via `KVM_SET_CPUID2` with per-leaf modification support
- Masks the hypervisor-present bit in CPUID leaf 1 ECX to hide from the guest
- Publishes all guest exits to an event dispatcher
- VMI agent captures register snapshots and memory dumps on each exit
- Serialises the full event log to JSON
- Snapshot/restore: saves complete VM state (registers + memory) and rewinds to it, enabling repeatable execution and fuzzing loops

## Requirements

- Linux kernel with KVM support (`/dev/kvm` accessible)
- x86-64 host (Intel VT-x or AMD-V)
- GCC 14+ or Clang 17+ (C++23)
- CMake 3.25+
- Linux kernel headers (`linux/kvm.h`)

```
sudo apt install build-essential cmake linux-headers-$(uname -r)
```

Verify KVM access:
```
ls -la /dev/kvm
# if permission denied:
sudo usermod -aG kvm $USER
```

Verify nasm installed for guest binary
```
sudo apt install nasm
```

## Build

```bash
cmake -B cmake-build-debug -DCMAKE_BUILD_TYPE=Debug
cmake --build cmake-build-debug -j$(nproc)

cd cmake-build-debug
nams -f bin -o simpleGuest.bin ../guest/simpleGuest.asm
```

## Run

```bash
./cmake-build-debug/kvm_hypervisor
```

The binary loads a minimal 16-bit real-mode guest (`IN 0x60` -> `CPUID` -> `HLT`) or the simpleGuest.bin from the guest folder.
runs it for 3 snapshot iterations, and writes `vmi_events.json` to the working directory.

## Tests

Tests use GoogleTest, fetched automatically via CMake FetchContent.

```bash
cmake --build cmake-build-debug --target kvm_hypervisor_tests
cd cmake-build-debug && ctest --output-on-failure
```

## Key KVM ioctls used

| ioctl | Purpose |
|---|---|
| `KVM_CREATE_VM` | Create VM file descriptor |
| `KVM_CREATE_VCPU` | Create vCPU, mmap kvm_run |
| `KVM_SET_USER_MEMORY_REGION` | Map host memory as guest RAM |
| `KVM_SET_CPUID2` | Install CPUID emulation table |
| `KVM_GET_REGS` / `KVM_SET_REGS` | Read/write general-purpose registers |
| `KVM_GET_SREGS` / `KVM_SET_SREGS` | Read/write segment/control registers |
| `KVM_RUN` | Enter guest execution |
| `KVM_ENABLE_CAP` | Enable `KVM_CAP_EXIT_ON_EMULATION_FAILURE` |

## Limitations

- Single vCPU only
- 16-bit real-mode guest in the demo; 64-bit guest support is wired in `GuestLoader`
  but requires a proper page table setup and a compiled guest binary
- CPUID exits are not available on stock kernels; interception happens at
  `KVM_SET_CPUID2` install time, not at guest execution time
- No EPT violation hooks (planned)
- No multi-threaded vCPU support