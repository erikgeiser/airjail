<p align="center">
  <h1 align="center"><b>airjail</b></h1>
  <p align="center"><i>Lightweight, Flexible and Rule-Based Network Isolation</i></p>
  <p align="center">
    <a href="https://github.com/erikgeiser/airjail/releases/latest"><img alt="Release" src="https://img.shields.io/github/release/erikgeiser/airjail.svg?style=for-the-badge"></a>
    <a href="https://pkg.go.dev/github.com/airjail/airjail"><img alt="Go Doc" src="https://img.shields.io/badge/godoc-reference-blue.svg?style=for-the-badge"></a>
    <a href="https://github.com/erikgeiser/airjail/actions?workflow=Build"><img alt="GitHub Action: Build" src="https://img.shields.io/github/actions/workflow/status/erikgeiser/airjail/build.yml?branch=main&style=for-the-badge"></a>
    </br>
    <a href="https://github.com/erikgeiser/airjail/actions?workflow=Check"><img alt="GitHub Action: Check" src="https://img.shields.io/github/actions/workflow/status/erikgeiser/airjail/check.yml?branch=main&style=for-the-badge&label=Check"></a>
    <a href="/LICENSE"><img alt="Software License" src="https://img.shields.io/badge/license-MIT-brightgreen.svg?style=for-the-badge"></a>
  </p>
</p>

`airjail` provides lightweight, rootless and flexible rule-based network
isolation for Linux in order to remove or restrict network access for programs.
For example, it can be used to run `npx`, but restrict the network access to
only allow downloading packages:

```sh
$ airjail --allow registry.npmjs.org -- npx prettier --check .
```

It follows these design principles:

- **Only Network Isolation:** The purpose of `airjail` is only network
  isolation. All other isolation types are well served by tools such as
  `firejail` or `bubblewrap` and both of these tools can be combined with
  `airjail` for exhaustive sandboxing. The only exception in `airjail` is
  blocking access to Unix domain and vsock sockets, which is an opt-in feature
  intended to support the network isolation in certain scenarios.
- **Transparent:** `airjail` aims to act like a transparent shim that interferes
  with the execution of the program as little as possible. It is therefore
  designed to provide the same experience regarding
  foregrounding/backgrounding/signaling/TTY as if the program was started
  without `airjail`.
- **Unprivileged:** No privileges or capabilities are required for `airjail`.
  When existing capabilities permit direct network namespace creation, airjail
  preserves the caller's identity and permissions except for dangerous
  capabilities that could bypass isolation or compromise the kernel. Without
  namespace setup capabilities, the process only loses supplementary groups
  except for the primary user group, which should not matter in most cases.
- **Easy to Use:** `airjail` is a single dependency-free binary that can easily
  be (cross-)compiled as it does not depend on `cgo`.

## Configuration

**Operating Modes:**

It is possible to configure `airjail` on-the-fly with CLI arguments or with a
YAML config. It can be used in the modes:

- **No network access**: Without `allow` or `block` rules, it blocks all network
  traffic.
- **Allowlist:** With only `allow` rules, it blocks all traffic except to the
  configured hosts.
- **Blocklist:** With only `block` rules, it allows any traffic except for the
  blocked hosts.
- **Mixed:** Mixing rules restricts access to the allowed hosts, but it allows
  `block` rules to formulate exceptions to wildcards or CIDR networks (e.g.
  `--allow '*.example.com'` `--block 'bad.example.com'`).

**Destination Types:**

Each rule can reference destinations in multiple ways:

- **IP Address:** References a single IP, for example `--allow 10.0.0.1`.
- **CIDR Network:** References an entire network, for example `--allow 10.0.0.1/8`
- **Hostname:** Hostnames will be resolved and the rule will be applied for the
  hostname itself as well as the IP addresses it resolves to. If the hostname
  does not resolve, `airjail` will return an error, unless
  `--allow-unresolved-rules` or `allow_unresolved_rules: true` is set.
- **Wildcard:** Hostnames can be specified with a wildcard `*`. This can be used
  to reference all subdomains (`--allow '*.example.com'`). In this case, it
  matches `sub.example.com`, but not `example.com`. Since wildcards cannot be
  resolved, these rules are not expanded to include the respective IP addresses.
- **Ports:** Each of the aforementioned types of destinations can be specified
  with and without port. Omitting the port means all ports are matched.

**Local Sockets:**

Airjail can optionally deny creation of Unix domain and vsock sockets. While
Unix sockets are local IPC rather than network access, they can often be used to
circumvent network restrictions. Vsock can similarly reach host or hypervisor
services without traversing the network namespace. For example, when SSH is used
with the `ControlMaster` feature on the host, network isolated processes could
connect to the `ControlMaster` socket in order to SSH into machines through an
existing connection that was established outside of the network isolation. On
the other hand, Unix domain sockets are also used extensively for normal
purposes. As such, this feature remains opt-in. Alternatively, however,
`airjail` can be used together with `firejail`, `bubblewrap` or a container to
remove dangerous sockets from the filesystem.

**Dangerous Capabilities:**

In permission-preserving namespace mode, airjail drops `CAP_SYS_ADMIN`,
`CAP_NET_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_SYS_RAWIO`, `CAP_BPF`,
`CAP_PERFMON`, and `CAP_CHECKPOINT_RESTORE` from the child and its capability
bounding set. A capability can be preserved explicitly with a repeatable unsafe
option:

```sh
airjail --keep-unsafe-capability CAP_SYS_ADMIN command
```

Keeping dangerous capabilities is only recommended when there is an additional
sandboxing layer such as `firejail` or `bubblewrap` that ensures a safe runtime
environment. Rootless namespace mode continues to drop all setup capabilities.

**CLI and Config:**

If both a config and CLI rules are provided, the CLI rules
extend (if applicable, e.g. for `allow/block`) or overwrite the config values.
All arguments after and including the first positional arguments belong to the
sandboxed program. Optionally, `airjail` arguments and program arguments can be
separated with `--` for clarity. The following two invocations are identical:

```bash
$ airjail \
    --allow "127.0.0.1/8" --allow "example.com" --allow '*.example.com' \
    --block "bad.example.com" --block "127.0.0.1:53" \
    --restrict-sockets \
    program -flag-a arg-b
$ airjail --config airjail.yml -- program -flag-a arg-b
```

With `airjail.yaml:`

```yaml
allow:
  - "127.0.0.1/8"
  - "example.com"
  - "*.example.com"
block:
  - "bad.example.com"
  - "127.0.0.1:53"
restrict_sockets: true
allow_unresolved_rules: false
```

## Building

`airjail` does not require `cgo` and can be compiled or cross-compiled with the
following command:

```sh
GOOS=linux go build .
```

The following command runs all tests but has to be executed on Linux:

```sh
go test ./...
```

## Technical Design and Implementation

Airjail creates network isolation by launching a program in an empty network
namespace that only creates a private loopback device. Initially, this prevents
the program from establishing any incoming or outgoing network traffic. If the
caller does not have the capabilities `CAP_SYS_ADMIN` and `CAP_NET_ADMIN`,
creating the network namespace is only possible when combining it with a user
namespace. If this is the case, the `uid` and `gid` is mapped in order to
preserve user and group permissions, but permissions from supplementary groups
are lost. If `airjail` is invoked without any configuration, this is all it
does. However, if rules are present, it creates a SOCKS and an HTTP/HTTPS proxy
outside of the namespace that each listen on a Unix domain socket and only proxy
allowed traffic. Inside the namespace, TCP listeners forward proxy-aware traffic
to those sockets. nftables redirects other TCP connections to a transparent
listener, which obtains the original destination and connects to it through the
same policy-enforcing SOCKS server. Proxy environment variables continue to let
proxy-aware programs provide destination hostnames directly. For non-proxy-aware
programs, nftables redirects DNS over TCP and UDP to a filtered outer resolver.
Approved A and AAAA responses temporarily associate their addresses with matching
hostname rules before transparent TCP connections are permitted.

The opt-in feature to restrict local sockets loads `seccomp` `BPF` rules that
are assembled in pure Go. These rules restrict access to the syscalls `socket`
and `socketpair` when called with `AF_UNIX` or `AF_VSOCK`. It also restricts
`io_uring_setup` and the legacy syscall `socketcall`, as these could also be
used to establish domain socket connections. It also forbids 32-bit syscalls.

## Why airjail and not firejail, bubblewrap or sandbox-runtime?

The reason for `airjail`'s development was the frustration about certain aspects
of other available tools. Each of these tools works great, but does not fit all
use-cases. Therefore, `airjail` solves specific network isolation use-cases
while allowing to be combined with the other tools for more exhaustive
sandboxing.

**firejail:**

- **Namespace Setup:** `firejail`'s network isolation is not flexible enough for
  many use cases. While `--net=none` works great for complete isolation,
  selective access is harder because it requires either specifying an IP or
  performing DHCP on a bridged interface. Specifying an IP is fine for servers
  but hard for workstations that often switch networks or multiple sandboxed
  process that each need a different IP. DHCP introduces a significant startup
  delay and can exhaust the DHCP pool if many sandboxed processes are started.
  Also, some network-related option do not support IPv6.
- **Access Rules:** Selective network access in `firejail` works by specifying
  and `iptables` config file which applied to the bridged interface. Having to
  create a config file prevents flexible on-the-fly filtering and writing
  `iptables` rules is way harder than specifying destinations with `--allow` or
  `--deny` and the additional firewall capabilities are rarely need for such
  use-cases.
- **Privileges:** Firejail required `root` access and is therefore packaged as a
  `suid` binary.

You can profit from all other sandboxing capabilities of `firejail` while
leaving the network sandboxing to `airjail` by combining both:

```sh
firejail --noprofile --private -- airjail --allow example.com -- bash -i
```

**bubblewrap:**

In contrast to `firejail` and `airjail`, `bubblewrap` does not allow selective
networking at all. It either allows all traffic or no traffic at all. Therefore,
it's feature set only slightly overlaps with `airjail`. You can keep using
`bubblewrap` and add selective network filtering by combining it with `airjail`.

**sandbox-runtime:**

Apart from the fact that `sandbox-runtime` also performs filesystem sandboxing,
the network isolation works similar to `airjail` by using proxy servers through
Unix domain sockets for outbound raffic. For some use-cases, `airjail`'s network
isolation may still be desired in order to avoid the following issues:

- **Execution Artifacts:** `sandbox-runtime`'s approach to prevent the creation
  of blocked files that did not exist before causes empty files to be created.
  While these are cleaned on exit, they remain if `srt` is killed and can affect
  programs at runtime while they still exist. This also happens when no
  filesystem rules are configured because `srt` still applies mandatory rules.
  These artifacts are not acceptable for a use-case in which only network
  sandboxing is required.
- **Dependencies:** `sandbox-runtime` requires `ripgrep`, `fd` to be installed.
  Another undocumented dependency is `which` which is not present in many
  containers. If `which` is not present, `srt` claims that `ripgrep` and `fd`
  are also not installed even though they are.
- **Mandatory Config File:** `sandbox-runtime` has to be configured with a
  config file and therefore it cannot be used to start network sandboxed
  programs with custom rules on-the-fly.
- **C-Based seccomp Loader:** In order to apply `seccomp` rules,
  `sandbox-runtime` uses a custom loader written in C. When running `srt`, it
  looks for the loader in its `node_modules` and when it is not at the expected
  location (because its build command was not invoked), it silently skips
  applying `seccomp` rules. This can only be notices with debug logs.

## Roadmap and Missing Features

- **Additional DNS and UDP support:** Filtered DNS currently supports A and
  AAAA queries with CNAME chains. HTTPS/SVCB records for ECH, arbitrary UDP,
  and upstream SOCKS5 UDP ASSOCIATE support are planned afterwards.
- **Inbound Traffic:** Currently `airjail` prevents other processes from
  accessing ports opened by the sandboxed process. An `--expose` option is
  planned that forwards out-of-namespace traffic into the sandbox.
