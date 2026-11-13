<p align="center">
  <h1 align="center"><b>airjail</b></h1>
  <p align="center"><i>Lightweight, Flexible and Rule-Based Network Isolation</i></p>
  <p align="center">
    <a href="https://github.com/erikgeiser/airjail/releases/latest"><img alt="Release" src="https://img.shields.io/github/release/erikgeiser/airjail.svg?style=for-the-badge"></a>
    <a href="https://github.com/erikgeiser/airjail/actions?workflow=Build"><img alt="GitHub Action: Build" src="https://img.shields.io/github/actions/workflow/status/erikgeiser/airjail/build.yml?branch=main&style=for-the-badge"></a>
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
  restricting access to external Unix domain and vsock sockets by default to
  prevent local services from bypassing network isolation.
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
- **Easy to Use:** `airjail` is a single runtime-dependency-free binary that can
  easily be (cross-)compiled as it does not depend on `cgo`.

## Configuration

**Operating Modes:**

It is possible to configure `airjail` on-the-fly with CLI arguments, a YAML
config or a mix of both. It can be used in the modes:

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
- **CIDR Network:** References an entire network, for example `--allow 10.0.0.1/8`.
- **Hostname:** Exact hostnames are resolved once at startup. If the hostname
  does not resolve, `airjail` returns an error unless `--allow-unresolved-rules`
  or `allow_unresolved_rules: true` is set. A static snapshot can instead be
  supplied directly, avoiding the lookup, for example
  `'example.com@10.0.0.1@fe80::1'`.
- **Wildcard:** Hostnames can be specified with a wildcard `*`. This can be used
  to reference all subdomains (`--allow '*.example.com'`). In this case, it
  matches `sub.example.com`, but not `example.com`. Since wildcards cannot be
  resolved, these rules are not expanded to include the respective IP addresses.
- **Ports:** Each of the aforementioned types of destinations can be specified
  with and without port. Omitting the port means all ports are matched.

**Local Sockets:**

Airjail restricts external Unix domain and vsock sockets by default. While Unix
sockets are local IPC rather than network access, they can often be used to
circumvent network restrictions (e.g. by spawning an out-of-namespace process
with `systemd-run --user` or establishing a DNS tunnel through the
`systemd-resolved` socket). On newer kernels, `airjail` allows the jailed
process to create sockets and connect to them but prevents access to outside
sockets. However, it is possible to allow access to specific sockets
(`--allow-socket /path/to/socket`) or disable socket restrictions altogether
(`--allow-all-sockets`). Older kernels only support wholesale blocking of all
sockets, both outside and inside of the jail.

Vsock can similarly reach host or hypervisor services without traversing the
network namespace. Therefore, they are also wholesale blocked by default, which
can be disabled with `--allow-vsocks`.

Alternatively, `airjail` can be used together with `firejail`, `bubblewrap` or a
container to remove dangerous sockets from the filesystem. This is especially
useful when jailing a program that internally uses sockets on an old kernel that
only supports wholesale socket restrictions otherwise.

**Dangerous Capabilities:**

When starting `airjail` with administrative capabilities or as `root`, airjail
drops `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`,
`CAP_SYS_RAWIO`, `CAP_BPF`, `CAP_PERFMON`, and `CAP_CHECKPOINT_RESTORE` from the
child and its capability bounding set. A capability can be preserved explicitly
with a repeatable unsafe option:

```sh
airjail --keep-unsafe-capability CAP_SYS_ADMIN command
```

Keeping dangerous capabilities is only recommended when there is an additional
sandboxing layer such as `firejail` or `bubblewrap` that ensures a safe runtime
environment. Rootless namespace mode continues to drop all setup capabilities.

**CLI and Config:**

If both a config and CLI rules are provided, the CLI rules
extend (if applicable, e.g. for `allow/block`) or overwrite the config values.
All arguments after and including the first positional argument belong to the
sandboxed program. Optionally, `airjail` arguments and program arguments can be
separated with `--` for clarity. The following two invocations are identical:

```bash
$ airjail \
    --allow "127.0.0.1/8" --allow "example.com" --allow '*.example.com' \
    --block "bad.example.com" --block "127.0.0.1:53" \
    --disable-transparent-fallback --private-loopback \
    program -flag-a arg-b
$ airjail --config airjail.yml -- program -flag-a arg-b
```

With `airjail.yaml`:

```yaml
allow:
  - "127.0.0.1/8"
  - "example.com"
  - "*.example.com"
block:
  - "bad.example.com"
  - "127.0.0.1:53"
log: warning
allow_sockets: []
allow_all_sockets: false
allow_vsocks: false
allow_unresolved_rules: false
allow_arbitrary_dns: false
proxy: http://proxy.example:8080
connect_timeout: 5s
transparent_fallback: false
private_loopback: true
```

Logging defaults to warnings. Use `--log traffic` to see allowed and blocked
connections and lookups, `--log info` to add operational messages, `--log debug`
to add detailed diagnostics, or use `--log silent` to disable logging
altogether.

Transparent TCP and filtered DNS are enabled by default for non-empty policies.
Use `--disable-transparent-fallback` or `transparent_fallback: false` for
proxy-only operation. In that mode, applications that ignore the injected HTTP
and SOCKS proxy settings have no network egress.

By default, loopback destinations refer to services in the outer namespace. Use
`--private-loopback` or `private_loopback: true` to keep `127.0.0.0/8` and `::1`
connections inside the child namespace instead. Outer localhost remains
available to applications that explicitly use an airjail proxy and override the
private-loopback `NO_PROXY` exclusion.

By default, exact hostname rules and their CNAME aliases are answered from the
startup snapshot without another upstream query. In allowlist mode, only names
matched by hostname allow rules, including authorized CNAME chains, may reach an
upstream DNS resolver. Hostname-only blocklists permit DNS except for names
blocked on all ports. Blocklists containing explicit IP/CIDR rules and
IP/CIDR-only allowlists do not authorize arbitrary child-supplied hostnames.
In blocklist mode, an info-level log explains this restriction. Use
`--allow-arbitrary-dns` or `allow_arbitrary_dns: true` to permit arbitrary DNS
resolution if the risk of DNS exfiltration is acceptable. Connection policy is
still enforced on every answer, but query names can carry data to an
authoritative DNS server.

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

When contributing to this repository, please check and format your code with
`golangci-lint`:

```sh
golangci-lint fmt ./...
golangci-lint run ./...
```

## Technical Design and Implementation

Airjail creates network isolation by launching a program in an empty network
namespace that only creates a private loopback device. Initially, this prevents
the program from establishing any incoming or outgoing network traffic. If the
caller does not have the capabilities `CAP_SYS_ADMIN` and `CAP_NET_ADMIN`,
creating the network namespace is only possible when combining it with a user
namespace. If this is the case, the `uid` and `gid` are mapped in order to
preserve user and group permissions, but permissions from supplementary groups
are lost and other users map to `nobody`.

If `airjail` is invoked without any configuration, this is all it does. However,
if rules are present, it creates a SOCKS and an HTTP/HTTPS proxy outside of the
namespace that each listen on a Unix domain socket and only proxy allowed
traffic. Inside the namespace, TCP listeners forward proxy-aware traffic to
those sockets. The HTTP bridge listens on `127.97.105.114:19080` and the SOCKS
bridge on `127.97.105.114:19081`. When spawning the jailed process, `airjail`
sets all proxy environment variables (e.g. `HTTP_PROXY`, `ALL_PROXY`, ...) that
are automatically picked up on by most programs.

For all other programs, direct TCP connections are automatically redirected
through the SOCKS proxy by namespace-scoped `nftables` rules. However, finding
the original destination is only possible by accepting the connection first.
Attempting to connect to a blocked host will therefore cause the connection to
be accepted by `airjail` and closed again, which may confuse some programs. DNS
lookups are redirected to a simple DNS proxy allowing only `A` and `AAAA`
lookups to domains that comply with the `allow`/`block` ruleset, preventing DNS
tunneling to blocked hosts.

Local socket isolation uses Landlock ABI 9 to restrict external Unix sockets,
with explicit pathname exceptions. Pure-Go seccomp BPF filters deny vsock and,
when suitable Landlock support is unavailable, Unix socket creation. While
seccomp socket restrictions are needed, airjail also denies `io_uring_setup`,
non-native syscall architectures, and the legacy `socketcall` on 386.

## Tips

- **Containers:** By default, containers apply a lot of constraints that prevent
  processes from creating namespaces. As a result, running `airjail` in a
  container may require options such as `--security-opt=seccomp=unconfined` or
  `--security-opt=apparmor=unconfined` depending on your container runtime.
- **Combining Sandboxes:** Combine `airjail` with other sandboxes such as
  `firejail`, for example to restrict the process to the current working
  directory:

```sh
$ firejail --noprofile --whitelist="$(pwd -P)" --private-tmp \
    -- airjail --allow example.com -- bash -i
```

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
  Also, some network-related options (e.g. DNS) do not support IPv6.
- **Access Rules:** Selective network access in `firejail` works by specifying
  an `iptables` config file that is applied to the bridged interface. Having to
  create a config file prevents flexible on-the-fly filtering and writing
  `iptables` rules is way harder than specifying destinations with `--allow` or
  `--block` and the additional firewall capabilities are rarely needed for such
  use-cases.
- **Privileges:** Firejail requires superuser privileges and is therefore
  packaged as a `suid` binary.

You can profit from all other sandboxing capabilities of `firejail` while
leaving the network sandboxing to `airjail` by combining both:

```sh
firejail --noprofile --private -- airjail --allow example.com -- bash -i
```

**bubblewrap:**

In contrast to `firejail` and `airjail`, `bubblewrap` does not allow selective
networking at all. It either allows all traffic or no traffic at all. Therefore,
its feature set only slightly overlaps with `airjail`. You can keep using
`bubblewrap` and add selective network filtering by combining it with `airjail`.

**sandbox-runtime:**

Apart from the fact that `sandbox-runtime` also performs filesystem sandboxing,
the network isolation works similarly to `airjail` by using proxy servers
through Unix domain sockets for outbound traffic. For some use-cases,
`airjail`'s network isolation may still be desired in order to avoid the
following issues:

- **Execution Artifacts:** `sandbox-runtime`'s approach to prevent the creation
  of blocked files that did not exist before causes empty files to be created.
  While these are cleaned on exit, they remain if `srt` is killed and can affect
  programs at runtime while they still exist. This also happens when no
  filesystem rules are configured because `srt` still applies mandatory rules.
  These artifacts are not acceptable for a use-case in which only network
  sandboxing is required.
- **Dependencies:** `sandbox-runtime` requires `ripgrep` to be installed.
  Another undocumented dependency is `which` which is not present in many
  containers. If `which` is not present, `srt` claims that `ripgrep` is also not
  installed even though it is.
- **Mandatory Config File:** `sandbox-runtime` has to be configured with a
  config file and therefore it cannot be used to start network sandboxed
  programs with custom rules on-the-fly.
- **C-Based seccomp Loader:** In order to apply `seccomp` rules,
  `sandbox-runtime` uses a custom loader written in C. When running `srt`, it
  looks for the loader in its `node_modules` and when it is not at the expected
  location (because its build command was not invoked), it silently skips
  applying `seccomp` rules. This can only be noticed with debug logs. It also
  blocks sockets that are internally created by child processes.

## Roadmap and Missing Features

- **Extensive DNS Support:** Filtered DNS currently supports A and AAAA queries
  with CNAME chains. MX and HTTPS/SVCB records for ECH are planned.
- **UDP Support:** Support for UDP egress is planned.
- **Inbound Traffic:** Currently `airjail` prevents other processes from
  accessing ports opened by the sandboxed process. An `--expose` option is
  planned that forwards out-of-namespace traffic into the sandbox.
