# Форк Docker Registry (Distribution) для [huecker.io](https://huecker.io).

В конфиг добавлены параметры `subnet`, `subnetmasklength`, `closeinterval`:

```yml
proxy:
  remoteurl: https://registry-1.docker.io
  username: username
  password: password
  subnet: "fe80::"
  subnetmasklength: 64
  closeinterval: 1m
```

Для каждого соединения с Remote Registry используется новый IPv6 адрес из заданной подсети.

## Конфиг `ndppd`

```
proxy eth0 {
    router no
    rule fe80::/64 {
        static
    }
}
```

## Конфиг `sysctl`

```
net.ipv6.ip_nonlocal_bind=1
net.ipv6.conf.all.proxy_ndp=1
```

## Сервис `systemd`

```
[Unit]
Description=Add IPv6 route
After=network.target

[Service]
Type=oneshot
ExecStart=ip route add fe80::/64 dev eth0
RemainAfterExit=true

[Install]
WantedBy=multi-user.target
```
