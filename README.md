# eirprobe
A probe to calculate imei-check response time on GSM_MAP and DIAMETER protocol

## Dependecies

You need install pyshark & redis-client packages from pip repository and redis-server from OS repository.

### 1. Install pyshark

```shell
> pip install pyshark
```

### 2. Install python redis client
```shell
> pip install redis
```
### 3. Install redis server from centos official repository
```shell
> yum install redis
> systemctl start redis
> systemctl enable redis
```