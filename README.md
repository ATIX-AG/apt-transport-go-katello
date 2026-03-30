# apt-transport-katello

Based on https://github.com/candlepin/subscription-manager/blob/main/debian-stuff/katello

This go application need to be built with the following command:

```bash
make build
```

## Compile-time debug logging

Debug logging is disabled in normal builds.

To compile a debug-enabled binary, use the `katello_debug` build tag:

```bash
go build -tags katello_debug -o katello .
```

In a debug-enabled build, additional traces are written to `stderr` only (never to `stdout`, so apt method protocol output is not affected).

Example to capture method traces on a live system:

```bash
sudo apt-get update 2>/tmp/katello-debug.log
```

It need to be in the apt method directory '/usr/lib/apt/methods/' and have the right permissions:

```bash
sudo cp katello /usr/lib/apt/methods/
sudo chmod 755 /usr/lib/apt/methods/katello
```
