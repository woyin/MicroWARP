FROM alpine:latest

# 安装内核级 WireGuard 工具、网络控制组件以及纯 C 语言的 microsocks 服务器
RUN apk add --no-cache wireguard-tools iptables iproute2 wget curl microsocks

WORKDIR /app
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

# 暴露 SOCKS5 端口
EXPOSE 1080

CMD ["./entrypoint.sh"]
