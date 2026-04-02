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

## Manually testing the binary

Start ./katello in your shell

```
600 Aquire
200 URI Start
URI: katello://7561127256828111111;repopath=test-host.machine%2fpulp%2fcontent%2fORG1%2fdevelopment%2fDebian%2fcustom%2fDebian_Product%2fDebian_Repo_main%2f@test-host.machine/7f82e612b1e987ec/ORG1-Debian-Debian-Repo-main/pool/main/d/a-nice-package/a-nice-package_1.0.0-0_all.deb
Filename: a-nice-package_1.0.0-0_all.deb
201 URI Done
```
