# apt-transport-katello

Based on https://github.com/candlepin/subscription-manager/blob/main/debian-stuff/katello

This go application need to be built with the following command:

```bash
make build
```

It need to be in the apt method directory '/usr/lib/apt/methods/' and have the right permissions:

```bash
sudo cp katello /usr/lib/apt/methods/
sudo chmod 755 /usr/lib/apt/methods/katello
```
