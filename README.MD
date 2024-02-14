# 方式一

## 准备工作
* 准备一个域名，并将 A 记录添加好；
* 安装好 `wget`

## 安装（Xray 前置）

支持配置方式

- VLESS + TCP + TLS

- VLESS + TCP + TLS  + Nginx 及 VLESS + TCP + TLS + Nginx + WebSocket 回落模式

```
wget -N --no-check-certificate -q -O install_tls.sh "https://raw.githubusercontent.com/susudos/xray_reality_onekey/main/install_tls.sh" && chmod +x install_tls.sh && bash install_tls.sh
```

## 启动方式

未正常启动Nginx状态查看: `systemctl status nginx`

停止 Nginx + Xray：`systemctl stop nginx && systemctl stop xray`

启动 Nginx + Xray：`systemctl start nginx && systemctl start xray`

## 相关目录

Web 目录：`/www/xray_web`

Xray 服务端配置：`/usr/local/etc/xray/config.json`

Nginx 目录： `/etc/nginx`

证书文件： `/ssl/xray.key`（私钥）和 `/ssl/xray.crt`（证书公钥）


---

# 方式二：


## 安装（REALITY）

支持配置方式

- VLESS + TCP + REALITY 

```
wget -N --no-check-certificate -q -O install_reality.sh "https://raw.githubusercontent.com/susudos/Xray_Reality_Onekey/main/install_reality.sh" && chmod +x install_reality.sh && bash install_reality.sh
```

## 启动方式


停止 Xray：`systemctl stop xray`

启动Xray：`systemctl start xray`

## 相关目录

Xray 服务端配置：`/usr/local/etc/xray/config.json`

KEY文件：`/usr/local/etc/xray/KEY`
