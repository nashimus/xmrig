# XMRig

:warning: **[Monero will change PoW algorithm on October 18](https://github.com/xmrig/xmrig/issues/753), all miners and proxy should be updated to [v2.8+](https://github.com/xmrig/xmrig/releases/tag/v2.8.1)** :warning:

[![Github All Releases](https://img.shields.io/github/downloads/xmrig/xmrig/total.svg)](https://github.com/xmrig/xmrig/releases)
[![GitHub release](https://img.shields.io/github/release/xmrig/xmrig/all.svg)](https://github.com/xmrig/xmrig/releases)
[![GitHub Release Date](https://img.shields.io/github/release-date-pre/xmrig/xmrig.svg)](https://github.com/xmrig/xmrig/releases)
[![GitHub license](https://img.shields.io/github/license/xmrig/xmrig.svg)](https://github.com/xmrig/xmrig/blob/master/LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/xmrig/xmrig.svg)](https://github.com/xmrig/xmrig/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/xmrig/xmrig.svg)](https://github.com/xmrig/xmrig/network)

XMRig is a high performance Monero (XMR) CPU miner, with official support for Windows.
Originally based on cpuminer-multi with heavy optimizations/rewrites and removing a lot of legacy code, since version 1.0.0 completely rewritten from scratch on C++.

* This is the **CPU-mining** version, there is also a [NVIDIA GPU version](https://github.com/xmrig/xmrig-nvidia) and [AMD GPU version]( https://github.com/xmrig/xmrig-amd).
* [Roadmap](https://github.com/xmrig/xmrig/issues/106) for next releases.

<img src="http://i.imgur.com/OKZRVDh.png" width="619" >

#### Table of contents
* [Features](#features)
* [Download](#download)
* [Usage](#usage)
* [Algorithm variations](#algorithm-variations)
* [Build](https://github.com/xmrig/xmrig/wiki/Build)
* [Common Issues](#common-issues)
* [Other information](#other-information)
* [Donations](#donations)
* [Release checksums](#release-checksums)
* [Contacts](#contacts)

## Features
* High performance.
* Official Windows support.
* Small Windows executable, without dependencies.
* x86/x64 support.
* Support for backup (failover) mining server.
* keepalived support.
* Command line options compatible with cpuminer.
* CryptoNight-Lite support for AEON.
* Smart automatic [CPU configuration](https://github.com/xmrig/xmrig/wiki/Threads).
* Nicehash support
* It's open source software.

## Download
* Binary releases: https://github.com/xmrig/xmrig/releases
* Git tree: https://github.com/xmrig/xmrig.git
  * Clone with `git clone https://github.com/xmrig/xmrig.git` :hammer: [Build instructions](https://github.com/xmrig/xmrig/wiki/Build).

## Usage
Use [config.xmrig.com](https://config.xmrig.com/xmrig) to generate, edit or share configurations.

### Options
```
  -a, --algo=ALGO          specify the algorithm to use
                             cryptonight
                             cryptonight-lite
                             cryptonight-heavy
  -o, --url=URL            URL of mining server
  -O, --userpass=U:P       username:password pair for mining server
  -u, --user=USERNAME      username for mining server
  -p, --pass=PASSWORD      password for mining server
      --rig-id=ID          rig identifier for pool-side statistics (needs pool support)
  -t, --threads=N          number of miner threads
  -v, --av=N               algorithm variation, 0 auto select
  -k, --keepalive          send keepalived packet for prevent timeout (needs pool support)
      --nicehash           enable nicehash.com support
      --tls                enable SSL/TLS support (needs pool support)
      --tls-fingerprint=F  pool TLS certificate fingerprint, if set enable strict certificate pinning
  -r, --retries=N          number of times to retry before switch to backup server (default: 5)
  -R, --retry-pause=N      time to pause between retries (default: 5)
      --cpu-affinity       set process affinity to CPU core(s), mask 0x3 for cores 0 and 1
      --cpu-priority       set process priority (0 idle, 2 normal to 5 highest)
      --no-huge-pages      disable huge pages support
      --no-color           disable colored output
      --variant            algorithm PoW variant
      --donate-level=N     donate level, default 5% (5 minutes in 100 minutes)
      --user-agent         set custom user-agent string for pool
  -B, --background         run the miner in the background
  -c, --config=FILE        load a JSON-format configuration file
  -l, --log-file=FILE      log all output to a file
  -S, --syslog             use system log for output messages
      --max-cpu-usage=N    maximum CPU usage for automatic threads mode (default 75)
      --safe               safe adjust threads and av settings for current CPU
      --asm=ASM            ASM code for cn/2, possible values: auto, none, intel, ryzen.
      --print-time=N       print hashrate report every N seconds
      --api-port=N         port for the miner API
      --api-access-token=T access token for API
      --api-worker-id=ID   custom worker-id for API
      --api-id=ID          custom instance ID for API
      --api-ipv6           enable IPv6 support for API
      --api-no-restricted  enable full remote access (only if API token set)
      --dry-run            test configuration and exit
  -h, --help               display this help and exit
  -V, --version            output version information and exit
```

Also you can use configuration via config file, default name **config.json**. Some options available only via config file: [`autosave`](https://github.com/xmrig/xmrig/issues/767), [`hw-aes`](https://github.com/xmrig/xmrig/issues/563). `watch` option currently not implemented in miners only in proxy.

## Algorithm variations

- `av` option used for automatic and simple threads mode (when you specify only threads count).
- For [advanced threads mode](https://github.com/xmrig/xmrig/issues/563) each thread configured individually and `av` option not used.

| av | Hashes per round | Hardware AES |
|----|------------------|--------------|
| 1  | 1 (Single)       | yes          |
| 2  | 2 (Double)       | yes          |
| 3  | 1 (Single)       | no           |
| 4  | 2 (Double)       | no           |
| 5  | 3 (Triple)       | yes          |
| 6  | 4 (Quard)        | yes          |
| 7  | 5 (Penta)        | yes          |
| 8  | 3 (Triple)       | no           |
| 9  | 4 (Quard)        | no           |
| 10 | 5 (Penta)        | no           |

## Common Issues
### HUGE PAGES unavailable
* Run XMRig as Administrator.
* Since version 0.8.0 XMRig automatically enables SeLockMemoryPrivilege for current user, but reboot or sign out still required. [Manual instruction](https://msdn.microsoft.com/en-gb/library/ms190730.aspx).

## Other information
* No HTTP support, only stratum protocol support.
* Default donation 5% (5 minutes in 100 minutes) can be reduced to 1% via option `donate-level`.


### CPU mining performance
* **Intel i7-7700** - 307 H/s (4 threads)
* **AMD Ryzen 7 1700X** - 560 H/s (8 threads)

Please note performance is highly dependent on system load. The numbers above are obtained on an idle system. Tasks heavily using a processor cache, such as video playback, can greatly degrade hashrate. Optimal number of threads depends on the size of the L3 cache of a processor, 1 thread requires 2 MB of cache.

### POWER performance comparison, CNv7 to CNv8:
* 4 and 8 core POWER9 CPUs will see performance at only ~62% of CNv7.  This is because the 4 and 8 core CPUs were essentially being used as an AES round and cache memory ASIC, and CNv8 "wants" to see proof of existence of other parts of a general purpose CPU.  The limiting factor is now the internal cache bus, which was never designed for the kind of bandwidth needed to have all 4 SMT threads operating at full capacity on many different execution units.
* Higher core count POWER9 CPUs will see performance at around 70% of CNv7.  CNv8 integrated two uncommonly used instructions (integer square root, integer divide) that leverage unique hardware in specific x86 CPUs.

### POWER performance discussion
POWER deemphasised the two rarely used integer square root / integer divide instructions that are key for CNv8 performance, focusing more on improving performance for other areas of the core design.  Unfortunately a more balanced CNv8 algorithm, testing other parts of the CPU in addition to these two instructions, would have been a better choice.  As it stands Monero requires a specific type of ASIC (Core i / Xeon / Zen CPU) for maximum performance by design.  These CPUs are owner-hostile and present serious risks in the form of the ME and PSP vendor DRM systems.

The current bottleneck in exploiting POWER9's SMT4 support to work around the slow div() instruction, which uses a separate execution unit that is shared between SMT2 slices, is actually the TLB.  When more than two threads are running on the same core, first a slowdown affecting all loads (including load hints such as dcbt) is observed.  If the number of threads is increased further, a large spike in dTLB misses is observed.  The net effect of this is that increasing the number of threads on a chiplet, even though it would better feed the division unit, actually maintains around the same hashrate as before, if not lower.  Work continues to remove the dTLB bottleneck on these systems.

### Maximum performance for POWER9 4 and 8 core CPUs
4 threads per core, power save == 1

### Maximum performance for POWER9 CPUs greater than 8 cores
1 thread per core, power save == 2
(2 threads per chiplet)

### Maximum performance checklist
* Idle operating system.
* Do not exceed optimal thread count.
* Use modern CPUs with AES-NI instruction set.
* Try setup optimal cpu affinity.
* Enable fast memory (Large/Huge pages).

## Donations
### xmrig general
* XMR: `48edfHu7V9Z84YzzMa6fUueoELZ9ZRXq9VetWzYGzKt52XU5xvqgzYnDK9URnRoJMk1j8nLwEVsaSWJ4fhdUyZijBGUicoD`
* BTC: `1P7ujsXeX7GxQwHNnJsRMgAdNkFZmNVqJT`
### POWER port
* XMR: `458isHDaTqAStk6pFHrvMWEdXgGFQNSsk4g4kxeHF8pYSmTuCAnf3d17S5hDowk1vT8W5uKSqRSyHhBmqeAShi4iN8tnWSt`

## Contacts
* support@xmrig.com
* [reddit](https://www.reddit.com/user/XMRig/)
* [twitter](https://twitter.com/xmrig_dev)
