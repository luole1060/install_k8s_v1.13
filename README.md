# k8s 集群二进制安装

![image-20181210153539793](/Volumes/mac-d/markdown/image/image-20181210153539793.png)

## 机器信息

| Ip          | 主机名      | 角色   | 部署组件                                                     |
| ----------- | ----------- | ------ | ------------------------------------------------------------ |
| 10.16.18.40 |             | vip    |                                                              |
| 10.16.18.41 | K8s-master1 | Master | Kubelet,docker,apiserver,etcd,haproxy,keepalived,scheduler,cni |
| 10.16.18.42 | K8s-master2 | Master | Kubelet,docker,apiserver,etcd,haproxy,keepalived,scheduler,cni |
| 10.16.18.43 | K8s-master3 | Master | Kubelet,docker,apiserver,etcd,haproxy,keepalived,scheduler,cni |
| 10.16.18.44 | K8s-node1   | Node   | Kubelet,docker,cni,kube-proxy,gluster                        |
| 10.16.18.45 | K8s-node2   | Node   | Kubelet,docker,cni,kube-proxy,gluster                        |
| 10.16.18.46 | K8s-node3   | Node   | Kubelet,docker,cni,kube-proxy,gluster                        |

## 安装包下载

链接：<https://pan.baidu.com/s/1T22upmhgn1GRzLz9I6t31A> 

提取码：cc4z



## 设置主机名

```
vim /etc/hostname 
K8S-master1

vim /etc/hosts
10.16.18.41 K8S-master1
10.16.18.42 K8S-master2
10.16.18.43 K8S-master3
10.16.18.44 K8S-node1
10.16.18.45 K8S-node2
10.16.18.46 K8S-node3
10.116.18.93 harbor.iquantex.com
```

### 添加k8s和docker 账户

需要在每台机器上添加k8s 和docker 账户，可以无密码sudo：

```
useradd -m k8s
sh -c 'echo 123456 | passwd k8s --stdin'
visudo
# %wheel        ALL=(ALL)       NOPASSWD: ALL  #需要去掉#

grep '%wheel.*NOPASSWD: ALL' /etc/sudoers
%wheel    ALL=(ALL)    NOPASSWD: ALL
gpasswd -a k8s wheel

useradd -m docker
gpasswd -a k8s docker
mkdir -p  /etc/docker/
cat /etc/docker/daemon.json
{
    "registry-mirrors": ["https://hub-mirror.c.163.com", "https://docker.mirrors.ustc.edu.cn"],
    "max-concurrent-downloads": 20
}
```

### 配置免密登陆

```
ssh-keygen -t rsa
ssh-copy-id root@10.16.18.42
ssh-copy-id root@10.16.18.43
ssh-copy-id root@10.16.18.44
ssh-copy-id root@10.16.18.45
ssh-copy-id root@10.16.18.46
```

### 安装依赖包

```
yum install -y conntrack ipvsadm ipset jq sysstat curl iptables libseccomp
```

### 关闭防火墙

```
 sudo systemctl stop firewalld
 sudo systemctl disable firewalld
 sudo iptables -F && sudo iptables -X && sudo iptables -F -t nat && sudo iptables -X -t nat
 sudo sudo iptables -P FORWARD ACCEPT
```

### 关闭selinux

```
setenforce 0
vim /etc/sysconfig/selinux

```

### 关闭swap 分区

```
swapoff -a
sed -i '/ swap / s/^\(.*\)$/#\1/g' /etc/fstab
```

### 加载内核模块

```
modprobe br_netfilter
modprobe ip_vs
```

### 设置系统参数

```
cat > kubernetes.conf <<EOF
net.bridge.bridge-nf-call-iptables=1
net.bridge.bridge-nf-call-ip6tables=1
net.ipv4.ip_forward=1
net.ipv4.tcp_tw_recycle=0
vm.swappiness=0
vm.overcommit_memory=1
vm.panic_on_oom=0
fs.inotify.max_user_watches=89100
fs.file-max=52706963
fs.nr_open=52706963
net.ipv6.conf.all.disable_ipv6=1
net.netfilter.nf_conntrack_max=2310720
EOF
cp kubernetes.conf  /etc/sysctl.d/kubernetes.conf
sysctl -p /etc/sysctl.d/kubernetes.conf
mount -t cgroup -o cpu,cpuacct none /sys/fs/cgroup/cpu,cpuacct
```

- tcp_tw_recycle 和 Kubernetes 的 NAT 冲突，必须关闭 ，否则会导致服务不通；
- 关闭不使用的 IPV6 协议栈，防止触发 docker BUG；

### 创建k8s 目录

```
mkdir -p /opt/k8s/bin
chown -R k8s /opt/k8s

sudo mkdir -p /etc/kubernetes/cert
chown -R k8s /etc/kubernetes

mkdir -p /etc/etcd/cert
chown -R k8s /etc/etcd/cert

mkdir -p /var/lib/etcd && chown -R k8s /etc/etcd/cert
```

## 安装ca证书和密钥

### 安装cfssl 工具集

```
sudo mkdir -p /opt/k8s/cert && sudo chown -R k8s /opt/k8s && cd /opt/k8s
wget https://pkg.cfssl.org/R1.2/cfssl_linux-amd64
mv cfssl_linux-amd64 /opt/k8s/bin/cfssl

wget https://pkg.cfssl.org/R1.2/cfssljson_linux-amd64
mv cfssljson_linux-amd64 /opt/k8s/bin/cfssljson

wget https://pkg.cfssl.org/R1.2/cfssl-certinfo_linux-amd64
mv cfssl-certinfo_linux-amd64 /opt/k8s/bin/cfssl-certinfo

chmod +x /opt/k8s/bin/*
export PATH=/opt/k8s/bin:$PATH
```

### 创建根证书（CA）

CA 证书是集群所有节点共享的，后续创建的所有证书都由它签名。

### 创建配置文件

```
cat > ca-config.json << EOF
{
  "signing": {
    "default": {
      "expiry": "876000h"
    },
    "profiles": {
      "kubernetes": {
        "usages": [
            "signing",
            "key encipherment",
            "server auth",
            "client auth"
        ],
        "expiry": "876000h"
      }
    }
  }
}
EOF
```

- `signing`：表示该证书可用于签名其它证书，生成的 `ca.pem` 证书中 `CA=TRUE`；
- `server auth`：表示 client 可以用该该证书对 server 提供的证书进行验证；
- `client auth`：表示 server 可以用该该证书对 client 提供的证书进行验证；

 ### 创建证书签名请求文件

```
cat > ca-csr.json << EOF
{
  "CN": "kubernetes",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "BeiJing",
      "L": "BeiJing",
      "O": "k8s",
      "OU": "4Paradigm"
    }
  ]
}
EOF
```

- CN：`Common Name`，kube-apiserver 从证书中提取该字段作为请求的**用户名 (User Name)**，浏览器使用该字段验证网站是否合法；
- O：`Organization`，kube-apiserver 从证书中提取该字段作为请求用户所属的**组 (Group)**；
- kube-apiserver 将提取的 User、Group 作为 `RBAC` 授权的用户标识；

### 生成CA证书和私钥

```
cfssl gencert -initca ca-csr.json | cfssljson -bare ca
ls ca*
```

## 安装kubectl 命令行工具

```
tar -zxvf kubernetes-client-linux-amd64.tar.gz
cp kubernetes/client/bin/kube* /opt/k8s/bin/
chmod +x /opt/k8s/bin/

#分发
scp  /opt/k8s/bin/kubectl k8s@10.16.18.42:/opt/k8s/bin/
scp  /opt/k8s/bin/kubectl k8s@10.16.18.43:/opt/k8s/bin/
```

### 创建admin证书和私钥

kubectl 与 apiserver https 安全端口通信，apiserver 对提供的证书进行认证和授权。

kubectl 作为集群的管理工具，需要被授予最高权限。这里创建具有**最高权限**的 admin 证书。

```
cat > admin-csr.json << EOF
{
  "CN": "admin",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "BeiJing",
      "L": "BeiJing",
      "O": "system:masters",
      "OU": "4Paradigm"
    }
  ]
}
EOF
```

- O 为 `system:masters`，kube-apiserver 收到该证书后将请求的 Group 设置为 system:masters；
- 预定义的 ClusterRoleBinding `cluster-admin` 将 Group `system:masters` 与 Role `cluster-admin` 绑定，该 Role 授予**所有 API**的权限；
- 该证书只会被 kubectl 当做 client 证书使用，所以 hosts 字段为空；

生成证书和私钥：

```
cfssl gencert -ca=/etc/kubernetes/cert/ca.pem \
  -ca-key=/etc/kubernetes/cert/ca-key.pem \
  -config=/etc/kubernetes/cert/ca-config.json \
  -profile=kubernetes admin-csr.json | cfssljson -bare admin
ls admin*
```

## 创建 kubeconfig 文件

kubeconfig 为 kubectl 的配置文件，包含访问 apiserver 的所有信息，如 apiserver 地址、CA 证书和自身使用的证书；

```
source /opt/k8s/bin/environment.sh
# 设置集群参数
kubectl config set-cluster kubernetes \
  --certificate-authority=/etc/kubernetes/cert/ca.pem \
  --embed-certs=true \
  --server=${KUBE_APISERVER} \
  --kubeconfig=kubectl.kubeconfig

# 设置客户端认证参数
kubectl config set-credentials admin \
  --client-certificate=admin.pem \
  --client-key=admin-key.pem \
  --embed-certs=true \
  --kubeconfig=kubectl.kubeconfig

# 设置上下文参数
kubectl config set-context kubernetes \
  --cluster=kubernetes \
  --user=admin \
  --kubeconfig=kubectl.kubeconfig

# 设置默认上下文
kubectl config use-context kubernetes --kubeconfig=kubectl.kubeconfig
```

- `--certificate-authority`：验证 kube-apiserver 证书的根证书；
- `--client-certificate`、`--client-key`：刚生成的 `admin` 证书和私钥，连接 kube-apiserver 时使用；
- `--embed-certs=true`：将 ca.pem 和 admin.pem 证书内容嵌入到生成的 kubectl.kubeconfig 文件中(不加时，写入的是证书文件路径)；

## 分发 kubeconfig 文件

```
mv kubectl.kubeconfig ~/.kube/config

mkdir .kube/
mkdir /home/k8s/.kube/

scp   ~/.kube/config root@10.16.18.42:~/.kube/
scp   ~/.kube/config root@10.16.18.43:~/.kube/
scp   ~/.kube/config k8s@10.16.18.43:~/.kube/
scp   ~/.kube/config k8s@10.16.18.42:~/.kube/
```

## 创建etcd 集群

- K8S服务使用etcd存储所有数据，etcd为集群，三台机器进行复用。
- 注意：etcd集群最坏不能坏掉最后一台，不然etcd整个挂掉会导致整个k8s无法进行恢复，数据丢失

```
wget https://github.com/coreos/etcd/releases/download/v3.3.7/etcd-v3.3.7-linux-amd64.tar.gz
tar -xvf etcd-v3.3.7-linux-amd64.tar.gz
mv etcd-v3.3.7-linux-amd64/etcd* /usr/local/bin
```

分发证书

```
scp /usr/local/bin/etcd*  root@10.16.18.42:/usr/local/bin/
scp /usr/local/bin/etcd*  root@10.16.18.43:/usr/local/bin/
```

### 创建etcd证书和私钥

```
cat > etcd-csr.json << EOF
{
  "CN": "etcd",
  "hosts": [
    "127.0.0.1",
    "10.16.18.41",
    "10.16.18.42",
    "10.16.18.43"
  ],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "BeiJing",
      "L": "BeiJing",
      "O": "k8s",
      "OU": "4Paradigm"
    }
  ]
}
EOF
```

生产证书和私钥

```
cfssl gencert -ca=/etc/kubernetes/cert/ca.pem \
    -ca-key=/etc/kubernetes/cert/ca-key.pem \
    -config=/etc/kubernetes/cert/ca-config.json \
    -profile=kubernetes etcd-csr.json | cfssljson -bare etcd
ls etcd*
```

分发证书：

```
mkdir /etc/etcd/cert/
cp etcd /etc/etcd/cert/

scp -r /etc/etcd/cert/ root@10.16.18.42:/etc/etcd/cert
scp -r /etc/etcd/cert/ root@10.16.18.43:/etc/etcd/cert
```

### 创建etcd的systemd unit 模版文件

```
cat > etcd.service.template << EOF
[Unit]
Description=Etcd Server
After=network.target
After=network-online.target
Wants=network-online.target
Documentation=https://github.com/coreos

[Service]
User=k8s
Type=notify
WorkingDirectory=/var/lib/etcd/
ExecStart=/opt/k8s/bin/etcd \\
  --data-dir=/var/lib/etcd \\
  --name=K8S-master1 \\
  --cert-file=/etc/etcd/cert/etcd.pem \\
  --key-file=/etc/etcd/cert/etcd-key.pem \\
  --trusted-ca-file=/etc/kubernetes/cert/ca.pem \\
  --peer-cert-file=/etc/etcd/cert/etcd.pem \\
  --peer-key-file=/etc/etcd/cert/etcd-key.pem \\
  --peer-trusted-ca-file=/etc/kubernetes/cert/ca.pem \\
  --peer-client-cert-auth \\
  --client-cert-auth \\
  --listen-peer-urls=https://10.16.18.41:2380 \\
  --initial-advertise-peer-urls=https://10.16.18.41:2380 \\
  --listen-client-urls=https://10.16.18.41:2379,http://127.0.0.1:2379 \\
  --advertise-client-urls=https://10.16.18.41:2379 \\
  --initial-cluster-token=etcd-cluster-0 \\
  --initial-cluster=K8S-node11=https://10.16.18.41:2380,K8S-node2=https://10.16.18.42:2380,K8S-node3=https://10.16.18.43:2380 \\
  --initial-cluster-state=new
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
```

- `User`：指定以 k8s 账户运行；
- `WorkingDirectory`、`--data-dir`：指定工作目录和数据目录为 `/var/lib/etcd`，需在启动服务前创建这个目录；
- `--name`：指定节点名称，当 `--initial-cluster-state` 值为 `new` 时，`--name` 的参数值必须位于 `--initial-cluster` 列表中；
- `--cert-file`、`--key-file`：etcd server 与 client 通信时使用的证书和私钥；
- `--trusted-ca-file`：签名 client 证书的 CA 证书，用于验证 client 证书；
- `--peer-cert-file`、`--peer-key-file`：etcd 与 peer 通信使用的证书和私钥；
- `--peer-trusted-ca-file`：签名 peer 证书的 CA 证书，用于验证 peer 证书；

分发证书：

```
cp etcd.service.template /etc/systemd/system/etcd.service
scp etcd.service.template root@10.16.18.42:/etc/systemd/system/etcd.service
scp etcd.service.template root@10.16.18.43:/etc/systemd/system/etcd.service
```

启动etcd：

```
systemctl daemon-reload 
systemctl start etcd
systemctl enable etcd
```

查看集群状态：

```
etcdctl --endpoints=https://10.16.18.41:2379 --ca-file=/etc/kubernetes/cert/ca.pem --cert-file=/etc/etcd/cert/etcd.pem --key-file=/etc/etcd/cert/etcd-key.pem cluster-health
```



# 部署 flannel 网络

kubernetes 要求集群内各节点(包括 master 节点)能通过 Pod 网段互联互通。flannel 使用 vxlan 技术为各节点创建一个可以互通的 Pod 网络，使用的端口为 UDP 8472，**需要开放该端口**（如公有云 AWS 等）。

flannel 第一次启动时，从 etcd 获取 Pod 网段信息，为本节点分配一个未使用的 `/24` 段地址，然后创建 `flannel.1`（也可能是其它名称，如 flannel1 等） 接口。

flannel 将分配的 Pod 网段信息写入 `/run/flannel/docker` 文件，docker 后续使用这个文件中的环境变量设置 `docker0` 网桥。

下载flannel

```
mkdir flannel
wget https://github.com/coreos/flannel/releases/download/v0.10.0/flannel-v0.10.0-linux-amd64.tar.gz
tar -xzvf flannel-v0.10.0-linux-amd64.tar.gz -C flannel
```

分发flannel 二进制文件：

```
cp flanneld  mk-docker-opts.sh  /opt/k8s/bin/
chown -R k8s:k8s /opt/k8s/bin/
chmod +x /opt/k8s/bin
```

创建flannel 证书和私钥：

flannel 从 etcd 集群存取网段分配信息，而 etcd 集群启用了双向 x509 证书认证，所以需要为 flanneld 生成证书和私钥。

```
cat > flanneld-csr.json << EOF
{
  "CN": "flanneld",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "BeiJing",
      "L": "BeiJing",
      "O": "k8s",
      "OU": "4Paradigm"
    }
  ]
}
EOF
```

生产密钥：

```
cfssl gencert -ca=/etc/kubernetes/cert/ca.pem \
  -ca-key=/etc/kubernetes/cert/ca-key.pem \
  -config=/etc/kubernetes/cert/ca-config.json \
  -profile=kubernetes flanneld-csr.json | cfssljson -bare flanneld
ls flanneld*pem
```

分发证书(需要发布到所有的节点)：

```
mkdir -p /etc/flanneld/cert && chown -R k8s /etc/flanneld
cp flanneld*pem  /etc/flanneld/cert/
chown -R k8s:k8s /etc/flanneld/
scp /etc/flanneld/cert/* k8s@10.16.18.42:/etc/flanneld/cert
scp /etc/flanneld/cert/* k8s@10.16.18.43:/etc/flanneld/cert/
```

向etcd 写入集群pod网段信息(只需要执行一次)

```
etcdctl \
  --endpoints="https://10.16.18.41:2379,https://10.16.18.42:2379,https://10.16.18.43:2379" \
  --ca-file=/etc/kubernetes/cert/ca.pem \
  --cert-file=/etc/flanneld/cert/flanneld.pem \
  --key-file=/etc/flanneld/cert/flanneld-key.pem \
  set /kubernetes/network/config '{"Network":"172.30.0.0/16", "SubnetLen": 24, "Backend": {"Type": "vxlan"}}'
  
  {"Network":"172.30.0.0/16", "SubnetLen": 24, "Backend": {"Type": "vxlan"}}
  
```

创建flanneld的systemd unit 文件

```
cat > flanneld.service << EOF
[Unit]
Description=Flanneld overlay address etcd agent
After=network.target
After=network-online.target
Wants=network-online.target
After=etcd.service
Before=docker.service

[Service]
Type=notify
ExecStart=/opt/k8s/bin/flanneld \\
  -etcd-cafile=/etc/kubernetes/cert/ca.pem \\
  -etcd-certfile=/etc/flanneld/cert/flanneld.pem \\
  -etcd-keyfile=/etc/flanneld/cert/flanneld-key.pem \\
  -etcd-endpoints=https://10.16.18.41:2379,https://10.16.18.42:2379,https://10.16.18.43:2379 \\
  -etcd-prefix=/kubernetes/network \\
  -iface=ens192
ExecStartPost=/opt/k8s/bin/mk-docker-opts.sh -k DOCKER_NETWORK_OPTIONS -d /run/flannel/docker
Restart=on-failure

[Install]
WantedBy=multi-user.target
RequiredBy=docker.service
EOF
```

分发文件并启动服务：

```
scp flanneld.service root@10.16.18.42:/etc/systemd/system/
scp flanneld.service root@10.16.18.42:/etc/systemd/system/

systemctl daemon-reload
systemctl start flanneld
systemctl enable flanneld
```

检查分配给各flanneld 的Pod 网段信息

```
etcdctl \
  --endpoints="https://10.16.18.41:2379,https://10.16.18.42:2379,https://10.16.18.43:2379" \
  --ca-file=/etc/kubernetes/cert/ca.pem \
  --cert-file=/etc/flanneld/cert/flanneld.pem \
  --key-file=/etc/flanneld/cert/flanneld-key.pem \
  get /kubernetes/network/config
```

结果：

```
{"Network":"172.30.0.0/16", "SubnetLen": 24, "Backend": {"Type": "vxlan"}}
```

查看已分配的Pod子网段列表：

```
etcdctl \
  --endpoints="https://10.16.18.41:2379,https://10.16.18.42:2379,https://10.16.18.43:2379" \
  --ca-file=/etc/kubernetes/cert/ca.pem \
  --cert-file=/etc/flanneld/cert/flanneld.pem \
  --key-file=/etc/flanneld/cert/flanneld-key.pem \
  ls /kubernetes/network/subnets
```

结果：

```
/kubernetes/network/subnets/172.30.40.0-24 
/kubernetes/network/subnets/172.30.69.0-24  
/kubernetes/network/subnets/172.30.82.0-24
```

查看某一 Pod 网段对应的节点 IP 和 flannel 接口地址:

```
etcdctl \
  --endpoints="https://10.16.18.41:2379,https://10.16.18.42:2379,https://10.16.18.43:2379" \
  --ca-file=/etc/kubernetes/cert/ca.pem \
  --cert-file=/etc/flanneld/cert/flanneld.pem \
  --key-file=/etc/flanneld/cert/flanneld-key.pem \
  get /kubernetes/network/subnets/172.30.81.0-24
```

# 部署master 节点

kubernetes master 节点运行如下组件：

- kube-apiserver
- kube-scheduler
- kube-controller-manager

kube-scheduler 和 kube-controller-manager 可以以集群模式运行，通过 leader 选举产生一个工作进程，其它进程处于阻塞模式。

对于 kube-apiserver，可以运行多个实例（本文档是 3 实例），但对其它组件需要提供统一的访问地址，该地址需要高可用。本文档使用 keepalived 和 haproxy 实现 kube-apiserver VIP 高可用和负载均衡。

## 下载最新版本的二进制文件

从 [`CHANGELOG`页面](https://github.com/kubernetes/kubernetes/blob/master/CHANGELOG.md) 下载 server tarball 文件。

```
wget https://dl.k8s.io/v1.10.4/kubernetes-server-linux-amd64.tar.gz
tar -xzvf kubernetes-server-linux-amd64.tar.gz
cd kubernetes
tar -xzvf  kubernetes-src.tar.gz
```

将二进制文件拷贝到所有 master 节点：

```
source /opt/k8s/bin/environment.sh
for node_ip in ${NODE_IPS[@]}
  do
    echo ">>> ${node_ip}"
    scp server/bin/* k8s@${node_ip}:/opt/k8s/bin/
    ssh k8s@${node_ip} "chmod +x /opt/k8s/bin/*"
  done
```

 ## 部署高可用组件

本文档讲解使用 keepalived 和 haproxy 实现 kube-apiserver 高可用的步骤：

- keepalived 提供 kube-apiserver 对外服务的 VIP；
- haproxy 监听 VIP，后端连接所有 kube-apiserver 实例，提供健康检查和负载均衡功能；

运行 keepalived 和 haproxy 的节点称为 LB 节点。由于 keepalived 是一主多备运行模式，故至少两个 LB 节点。

本文档复用 master 节点的三台机器，haproxy 监听的端口(8443) 需要与 kube-apiserver 的端口 6443 不同，避免冲突。

keepalived 在运行过程中周期检查本机的 haproxy 进程状态，如果检测到 haproxy 进程异常，则触发重新选主的过程，VIP 将飘移到新选出来的主节点，从而实现 VIP 的高可用。

所有组件（如 kubeclt、apiserver、controller-manager、scheduler 等）都通过 VIP 和 haproxy 监听的 8443 端口访问 kube-apiserver 服务

### 安装keepalived 和haproxy

### 机器信息

| ip          | 主机名  | 权重 |
| ----------- | ------- | ---- |
| 10.16.18.41 | master1 | 120  |
| 10.16.18.42 | master2 | 110  |
| 10.16.18.43 | master3 | 100  |
| 10.16.18.40 | vip     |      |

```
yum install -y keepalived haproxy
```

haproxy 配置文件：

```
cat > haproxy.cfg << EOF
global
    log /dev/log    local0
    log /dev/log    local1 notice
    chroot /var/lib/haproxy
    stats socket /var/run/haproxy-admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy
    daemon
    nbproc 1

defaults
    log     global
    timeout connect 5000
    timeout client  10m
    timeout server  10m

listen  admin_stats
    bind 0.0.0.0:10080
    mode http
    log 127.0.0.1 local0 err
    stats refresh 30s
    stats uri /status
    stats realm welcome login\ Haproxy
    stats auth admin:123456
    stats hide-version
    stats admin if TRUE

listen kube-master
    bind 0.0.0.0:8443
    mode tcp
    option tcplog
    balance source
    server 10.16.18.41 10.16.18.41:6443 check inter 2000 fall 2 rise 2 weight 1
    server 10.16.18.42 10.16.18.42:6443 check inter 2000 fall 2 rise 2 weight 1
    server 10.16.18.43 10.16.18.43:6443 check inter 2000 fall 2 rise 2 weight 1
EOF
```

启动haproxy：

```
systemctl start haproxy
systemctl enable haproxy
```

keepalived master 配置文件：

```
cat > keepalived-master.conf << EOF
global_defs {
    router_id lb-master-40
}

vrrp_script check-haproxy {
    script "killall -0 haproxy"
    interval 5
    weight -30
}

vrrp_instance VI-kube-master {
    state MASTER
    priority 120
    dont_track_primary
    interface ens192
    virtual_router_id 68
    advert_int 3
    track_script {
        check-haproxy
    }
    virtual_ipaddress {
        10.16.18.40
    }
}
EOF
```

- VIP 所在的接口（interface ${VIP_IF}）为 `eth0`；
- 使用 `killall -0 haproxy` 命令检查所在节点的 haproxy 进程是否正常。如果异常则将权重减少（-30）,从而触发重新选主过程；
- router_id、virtual_router_id 用于标识属于该 HA 的 keepalived 实例，如果有多套 keepalived HA，则必须各不相同；

keepalived slave 配置文件：

```
cat  > keepalived-slave.conf << EOF
global_defs {
    router_id lb-master-40
}

vrrp_script check-haproxy {
    script "killall -0 haproxy"
    interval 5
    weight -30
}

vrrp_instance VI-kube-master {
    state MASTER
    priority 110
    dont_track_primary
    interface ens192
    virtual_router_id 68
    advert_int 3
    track_script {
        check-haproxy
    }
    virtual_ipaddress {
        10.16.18.40
    }
}
EOF
```

- VIP 所在的接口（interface ${VIP_IF}）为 `eth0`；
- 使用 `killall -0 haproxy` 命令检查所在节点的 haproxy 进程是否正常。如果异常则将权重减少（-30）,从而触发重新选主过程；
- router_id、virtual_router_id 用于标识属于该 HA 的 keepalived 实例，如果有多套 keepalived HA，则必须各不相同；
- priority 的值必须小于 master 的值；

启动keepalived：

```
systemctl start keeplived 
systemctl enable keepalived
```

### 查看haproxy 状态页面

http://10.16.18.40:10080/status  用户和密码定义在haproxy 文件里： admin/123456

![image-20181221204750347](/Volumes/mac-d/markdown/image/haproxy.png)

## 部署kube-apiserver 

创建kubernetes 证书和私钥

```
cat > kubernetes-csr.json << EOF
{
  "CN": "kubernetes",
  "hosts": [
    "127.0.0.1",
    "10.16.18.41",
    "10.16.18.42",
    "10.16.18.43",
    "10.16.18.40",
    "10.254.0.1",
    "kubernetes",
    "kubernetes.default",
    "kubernetes.default.svc",
    "kubernetes.default.svc.cluster",
    "kubernetes.default.svc.cluster.local"
  ],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "BeiJing",
      "L": "BeiJing",
      "O": "k8s",
      "OU": "4Paradigm"
    }
  ]
}
EOF
```

- hosts 字段指定授权使用该证书的 **IP 或域名列表**，这里列出了 VIP 、apiserver 节点 IP、kubernetes 服务 IP 和域名；
- 域名最后字符不能是 `.`(如不能为 `kubernetes.default.svc.cluster.local.`)，否则解析时失败，提示： `x509: cannot parse dnsName "kubernetes.default.svc.cluster.local."`；
- 如果使用非 `cluster.local` 域名，如 `opsnull.com`，则需要修改域名列表中的最后两个域名为：`kubernetes.default.svc.opsnull`、`kubernetes.default.svc.opsnull.com`
- kubernetes 服务 IP 是 apiserver 自动创建的，一般是 `--service-cluster-ip-range` 参数指定的网段的**第一个IP**，后续可以通过如下命令获取：

```
$ kubectl get svc kubernetes
```

生成证书和私钥：

```
cfssl gencert -ca=/etc/kubernetes/cert/ca.pem \
  -ca-key=/etc/kubernetes/cert/ca-key.pem \
  -config=/etc/kubernetes/cert/ca-config.json \
  -profile=kubernetes kubernetes-csr.json | cfssljson -bare kubernetes
ls kubernetes*pem
```

分发证书：

```
mkdir -p /etc/kubernetes/cert/ && sudo chown -R k8s /etc/kubernetes/cert/
cp kubernetes*.pem k8s@10.16.18.41:/etc/kubernetes/cert/
cp kubernetes*.pem k8s@10.16.18.42:/etc/kubernetes/cert/
cp kubernetes*.pem k8s@10.16.18.42:/etc/kubernetes/cert/
```

创建加密配置文件

```
cat > encryption-config.yaml << EOF
kind: EncryptionConfig
apiVersion: v1
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: J5N4f3Ch93KoXS+z2Kp6IMX9zWrN2I/kCRB05BgJ3Ns=
      - identity: {}
EOF
```

分发配置文件

```
scp encryption-config.yaml k8s@10.16.18.41:/etc/kubernetes/
scp encryption-config.yaml k8s@10.16.18.42:/etc/kubernetes/
scp encryption-config.yaml k8s@10.16.18.43:/etc/kubernetes/
```

创建kube-apiserver systemd unit 模板文件

```
cat > kube-apiserver.service.template << EOF
[Unit]
Description=Kubernetes API Server
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=network.target

[Service]
ExecStart=/opt/k8s/bin/kube-apiserver \\
  --enable-admission-plugins=Initializers,NamespaceLifecycle,NodeRestriction,LimitRanger,ServiceAccount,DefaultStorageClass,ResourceQuota \\
  --anonymous-auth=false \\
  --experimental-encryption-provider-config=/etc/kubernetes/encryption-config.yaml \\
  --advertise-address=10.16.18.41 \\
  --bind-address=10.16.18.41 \\
  --insecure-port=0 \\
  --authorization-mode=Node,RBAC \\
  --runtime-config=api/all \\
  --enable-bootstrap-token-auth \\
  --service-cluster-ip-range=10.254.0.0/16 \\
  --service-node-port-range=30000-35000 \\
  --tls-cert-file=/etc/kubernetes/cert/kubernetes.pem \\
  --tls-private-key-file=/etc/kubernetes/cert/kubernetes-key.pem \\
  --client-ca-file=/etc/kubernetes/cert/ca.pem \\
  --kubelet-client-certificate=/etc/kubernetes/cert/kubernetes.pem \\
  --kubelet-client-key=/etc/kubernetes/cert/kubernetes-key.pem \\
  --service-account-key-file=/etc/kubernetes/cert/ca-key.pem \\
  --etcd-cafile=/etc/kubernetes/cert/ca.pem \\
  --etcd-certfile=/etc/kubernetes/cert/kubernetes.pem \\
  --etcd-keyfile=/etc/kubernetes/cert/kubernetes-key.pem \\
  --etcd-servers=https://10.16.18.41:2379,https://10.16.18.42:2379,https://10.16.18.43:2379 \\
  --enable-swagger-ui=true \\
  --allow-privileged=true \\
  --apiserver-count=3 \\
  --audit-log-maxage=30 \\
  --audit-log-maxbackup=3 \\
  --audit-log-maxsize=100 \\
  --audit-log-path=/var/log/kube-apiserver-audit.log \\
  --event-ttl=1h \\
  --alsologtostderr=true \\
  --logtostderr=false \\
  --log-dir=/var/log/kubernetes \\
  --v=2
Restart=on-failure
RestartSec=5
Type=notify
User=k8s
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
```

- `--experimental-encryption-provider-config`：启用加密特性；
- `--authorization-mode=Node,RBAC`： 开启 Node 和 RBAC 授权模式，拒绝未授权的请求；
- `--enable-admission-plugins`：启用 `ServiceAccount` 和 `NodeRestriction`；
- `--service-account-key-file`：签名 ServiceAccount Token 的公钥文件，kube-controller-manager 的 `--service-account-private-key-file` 指定私钥文件，两者配对使用；
- `--tls-*-file`：指定 apiserver 使用的证书、私钥和 CA 文件。`--client-ca-file` 用于验证 client (kue-controller-manager、kube-scheduler、kubelet、kube-proxy 等)请求所带的证书；
- `--kubelet-client-certificate`、`--kubelet-client-key`：如果指定，则使用 https 访问 kubelet APIs；需要为证书对应的用户(上面 kubernetes*.pem 证书的用户为 kubernetes) 用户定义 RBAC 规则，否则访问 kubelet API 时提示未授权；
- `--bind-address`： 不能为 `127.0.0.1`，否则外界不能访问它的安全端口 6443；
- `--insecure-port=0`：关闭监听非安全端口(8080)；
- `--service-cluster-ip-range`： 指定 Service Cluster IP 地址段；
- `--service-node-port-range`： 指定 NodePort 的端口范围；
- `--runtime-config=api/all=true`： 启用所有版本的 APIs，如 autoscaling/v2alpha1；
- `--enable-bootstrap-token-auth`：启用 kubelet bootstrap 的 token 认证；
- `--apiserver-count=3`：指定集群运行模式，多台 kube-apiserver 会通过 leader 选举产生一个工作节点，其它节点处于阻塞状态；
- `User=k8s`：使用 k8s 账户运行；

分发文件

```
scp kube-apiserver k8s@10.16.18.41:/opt/k8s/bin
mkdir -p /var/log/kubernetes && chown -R k8s /var/log/kubernetes
cp kube-apiserver.service.template  /etc/systemd/system/
```

打印kube-apiserver 写入etcd的数据

```
etcdctl \
  --endpoints="https://10.16.18.41:2379,https://10.16.18.42:2379,https://10.16.18.43:2379" \
  --ca-file=/etc/kubernetes/cert/ca.pem \
  --cert-file=/etc/etcd/cert/etcd.pem \
  --key-file=/etc/etcd/cert/etcd-key.pem \
  get /registry/ --prefix --keys-only 
```

检查集群状态：

```
[root@K8S-master1 ~]# kubectl cluster-info
Kubernetes master is running at https://10.16.18.40:8443

To further debug and diagnose cluster problems, use 'kubectl cluster-info dump'.
[root@K8S-master1 ~]# kubectl get all --all-namespaces
NAMESPACE   NAME                 TYPE        CLUSTER-IP   EXTERNAL-IP   PORT(S)   AGE
default     service/kubernetes   ClusterIP   10.254.0.1   <none>        443/TCP   10m
[root@K8S-master1 ~]# kubectl get componentstatuses
NAME                 STATUS      MESSAGE                                                                                     ERROR
controller-manager   Unhealthy   Get http://127.0.0.1:10252/healthz: dial tcp 127.0.0.1:10252: connect: connection refused
scheduler            Unhealthy   Get http://127.0.0.1:10251/healthz: dial tcp 127.0.0.1:10251: connect: connection refused
etcd-0               Healthy     {"health":"true"}
etcd-2               Healthy     {"health":"true"}
etcd-1               Healthy     {"health":"true"}
[root@K8S-master1 ~]# netstat -lnpt|grep kube
tcp        0      0 10.16.18.41:6443        0.0.0.0:*               LISTEN      8795/kube-apiserver
```

## 授予 kubernetes 证书访问 kubelet API 的权限

在执行 kubectl exec、run、logs 等命令时，apiserver 会转发到 kubelet。这里定义 RBAC 规则，授权 apiserver 调用 kubelet API。

```
$ kubectl create clusterrolebinding kube-apiserver:kubelet-apis --clusterrole=system:kubelet-api-admin --user kubernetes
```

## 部署controller-manager 集群

该集群包含 3 个节点，启动后将通过竞争选举机制产生一个 leader 节点，其它节点为阻塞状态。当 leader 节点不可用后，剩余节点将再次进行选举产生新的 leader 节点，从而保证服务的可用性。

为保证通信安全，本文档先生成 x509 证书和私钥，kube-controller-manager 在如下两种情况下使用该证书：

1. 与 kube-apiserver 的安全端口通信时;
2. 在**安全端口**(https，10252) 输出 prometheus 格式的 metrics；

创建kube-controller-manager 证书和密钥

```
cat > kube-controller-manager-csr.json << EOF
{
    "CN": "system:kube-controller-manager",
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "hosts": [
      "127.0.0.1",
      "10.16.18.41",
      "10.16.18.42",
      "10.16.18.43"
    ],
    "names": [
      {
        "C": "CN",
        "ST": "BeiJing",
        "L": "BeiJing",
        "O": "system:kube-controller-manager",
        "OU": "4Paradigm"
      }
    ]
}
EOF
```

- hosts 列表包含**所有** kube-controller-manager 节点 IP；
- CN 为 system:kube-controller-manager、O 为 system:kube-controller-manager，kubernetes 内置的 ClusterRoleBindings system:kube-controller-manager 赋予 kube-controller-manager 工作所需的权限

生成证书和密码：

```
cfssl gencert -ca=/etc/kubernetes/cert/ca.pem \
  -ca-key=/etc/kubernetes/cert/ca-key.pem \
  -config=/etc/kubernetes/cert/ca-config.json \
  -profile=kubernetes kube-controller-manager-csr.json | cfssljson -bare kube-controller-manager
```

分发证书：

```
scp kube-controller-manager*.pem k8s@10.16.18.41:/etc/kubernetes/cert/
scp kube-controller-manager*.pem k8s@10.16.18.42:/etc/kubernetes/cert/
scp kube-controller-manager*.pem k8s@10.16.18.43:/etc/kubernetes/cert/
```

创建和分发kubeconfig 文件：

```
kubectl config set-cluster kubernetes \
  --certificate-authority=/etc/kubernetes/cert/ca.pem \
  --embed-certs=true \
  --server=https://10.16.18.40:8443 \
  --kubeconfig=kube-controller-manager.kubeconfig

kubectl config set-credentials system:kube-controller-manager \
  --client-certificate=kube-controller-manager.pem \
  --client-key=kube-controller-manager-key.pem \
  --embed-certs=true \
  --kubeconfig=kube-controller-manager.kubeconfig

kubectl config set-context system:kube-controller-manager \
  --cluster=kubernetes \
  --user=system:kube-controller-manager \
  --kubeconfig=kube-controller-manager.kubeconfig

kubectl config use-context system:kube-controller-manager --kubeconfig=kube-controller-manager.kubeconfig

 scp kube-controller-manager.kubeconfig k8s@10.16.18.41:/etc/kubernetes/
 scp kube-controller-manager.kubeconfig k8s@10.16.18.42:/etc/kubernetes/
 scp kube-controller-manager.kubeconfig k8s@10.16.18.43:/etc/kubernetes/
```

创建和分发 kube-controller-manager system unit 文件

```
cat > kube-controller-manager.service << EOF
[Unit]
Description=Kubernetes Controller Manager
Documentation=https://github.com/GoogleCloudPlatform/kubernetes

[Service]
ExecStart=/opt/k8s/bin/kube-controller-manager \\
  --port=0 \\
  --secure-port=10252 \\
  --bind-address=127.0.0.1 \\
  --kubeconfig=/etc/kubernetes/kube-controller-manager.kubeconfig \\
  --service-cluster-ip-range=10.254.0.0/16 \\
  --cluster-name=kubernetes \\
  --cluster-signing-cert-file=/etc/kubernetes/cert/ca.pem \\
  --cluster-signing-key-file=/etc/kubernetes/cert/ca-key.pem \\
  --experimental-cluster-signing-duration=87600h \\
  --root-ca-file=/etc/kubernetes/cert/ca.pem \\
  --service-account-private-key-file=/etc/kubernetes/cert/ca-key.pem \\
  --leader-elect=true \\
  --feature-gates=RotateKubeletServerCertificate=true \\
  --controllers=*,bootstrapsigner,tokencleaner \\
  --horizontal-pod-autoscaler-use-rest-clients=true \\
  --horizontal-pod-autoscaler-sync-period=10s \\
  --tls-cert-file=/etc/kubernetes/cert/kube-controller-manager.pem \\
  --tls-private-key-file=/etc/kubernetes/cert/kube-controller-manager-key.pem \\
  --use-service-account-credentials=true \\
  --alsologtostderr=true \\
  --logtostderr=false \\
  --log-dir=/var/log/kubernetes \\
  --v=2
Restart=on
Restart=on-failure
RestartSec=5
User=k8s

[Install]
WantedBy=multi-user.target
EOF
```

- `--port=0`：关闭监听 http /metrics 的请求，同时 `--address` 参数无效，`--bind-address` 参数有效；
- `--secure-port=10252`、`--bind-address=0.0.0.0`: 在所有网络接口监听 10252 端口的 https /metrics 请求；
- `--kubeconfig`：指定 kubeconfig 文件路径，kube-controller-manager 使用它连接和验证 kube-apiserver；
- `--cluster-signing-*-file`：签名 TLS Bootstrap 创建的证书；
- `--experimental-cluster-signing-duration`：指定 TLS Bootstrap 证书的有效期；
- `--root-ca-file`：放置到容器 ServiceAccount 中的 CA 证书，用来对 kube-apiserver 的证书进行校验；
- `--service-account-private-key-file`：签名 ServiceAccount 中 Token 的私钥文件，必须和 kube-apiserver 的 `--service-account-key-file` 指定的公钥文件配对使用；
- `--service-cluster-ip-range` ：指定 Service Cluster IP 网段，必须和 kube-apiserver 中的同名参数一致；
- `--leader-elect=true`：集群运行模式，启用选举功能；被选为 leader 的节点负责处理工作，其它节点为阻塞状态；
- `--feature-gates=RotateKubeletServerCertificate=true`：开启 kublet server 证书的自动更新特性；
- `--controllers=*,bootstrapsigner,tokencleaner`：启用的控制器列表，tokencleaner 用于自动清理过期的 Bootstrap token；
- `--horizontal-pod-autoscaler-*`：custom metrics 相关参数，支持 autoscaling/v2alpha1；
- `--tls-cert-file`、`--tls-private-key-file`：使用 https 输出 metrics 时使用的 Server 证书和秘钥；
- `--use-service-account-credentials=true`:
- `User=k8s`：使用 k8s 账户运行；

## kube-controller-manager 的权限

ClusteRole: system:kube-controller-manager 的**权限很小**，只能创建 secret、serviceaccount 等资源对象，各 controller 的权限分散到 ClusterRole system:controller:XXX 中。

需要在 kube-controller-manager 的启动参数中添加 `--use-service-account-credentials=true` 参数，这样 main controller 会为各 controller 创建对应的 ServiceAccount XXX-controller。

内置的 ClusterRoleBinding system:controller:XXX 将赋予各 XXX-controller ServiceAccount 对应的 ClusterRole system:controller:XXX 权限。

启动kube-controller-manager 服务

```
scp kube-controller-manager k8s@10.16.18.41:/opt/k8s/bin/
scp kube-controller-manager k8s@10.16.18.42:/opt/k8s/bin/
scp kube-controller-manager k8s@10.16.18.43:/opt/k8s/bin/

mkdir -p /var/log/kubernetes && chown -R k8s /var/log/kubernetes
systemctl daemon-reload && systemctl enable kube-controller-manager && systemctl restart kube-controller-managerc
```

查看服务运行情况

```
systemctl status kube-controller-managerc
```

查看输出的metric

注意：以下命令在 kube-controller-manager 节点上执行。

kube-controller-manager 监听 10252 端口，接收 https 请求：

```
[root@K8S-master1 ~]# netstat -lnpt|grep kube-controll
tcp        0      0 127.0.0.1:10252         0.0.0.0:*               LISTEN      10147/kube-controll
```

测试 kube-controller-manager 集群的高可用

停掉一个或两个节点的 kube-controller-manager 服务，观察其它节点的日志，看是否获取了 leader 权限。

```
[root@K8S-master1 ~]# kubectl get endpoints kube-controller-manager --namespace=kube-system  -o yaml
apiVersion: v1
kind: Endpoints
metadata:
  annotations:
    control-plane.alpha.kubernetes.io/leader: '{"holderIdentity":"K8S-master1_52bda019-052d-11e9-a51d-0050569e1db6","leaseDurationSeconds":15,"acquireTime":"2018-12-21T14:39:58Z","renewTime":"2018-12-21T14:53:06Z","leaderTransitions":2}'
  creationTimestamp: "2018-12-21T14:06:00Z"
  name: kube-controller-manager
  namespace: kube-system
  resourceVersion: "3157"
  selfLink: /api/v1/namespaces/kube-system/endpoints/kube-controller-manager
  uid: 8bc15018-0529-11e9-83b0-0050569e1db6
  
  停掉master1的controller-manager，再看master
  [root@K8S-master1 ~]# kubectl get endpoints kube-controller-manager --namespace=kube-system  -o yaml
apiVersion: v1
kind: Endpoints
metadata:
  annotations:
    control-plane.alpha.kubernetes.io/leader: '{"holderIdentity":"K8S-master3_410071f4-052e-11e9-a3d1-0050569e4520","leaseDurationSeconds":15,"acquireTime":"2018-12-21T14:54:49Z","renewTime":"2018-12-21T14:54:57Z","leaderTransitions":3}'
  creationTimestamp: "2018-12-21T14:06:00Z"
  name: kube-controller-manager
  namespace: kube-system
  resourceVersion: "3242"
  selfLink: /api/v1/namespaces/kube-system/endpoints/kube-controller-manager
  uid: 8bc15018-0529-11e9-83b0-0050569e1db6
  
  可以看到 leader 变成了k8s-master3
```

### 部署 高可用的kube-scheduler 集群

该集群包含 3 个节点，启动后将通过竞争选举机制产生一个 leader 节点，其它节点为阻塞状态。当 leader 节点不可用后，剩余节点将再次进行选举产生新的 leader 节点，从而保证服务的可用性。

为保证通信安全，本文档先生成 x509 证书和私钥，kube-scheduler 在如下两种情况下使用该证书：

1. 与 kube-apiserver 的安全端口通信;
2. 在**安全端口**(https，10251) 输出 prometheus 格式的 metrics；

创建kube-scheduler 证书和私钥

```
cat > kube-scheduler-csr.json << EOF
{
    "CN": "system:kube-scheduler",
    "hosts": [
      "127.0.0.1",
      "10.16.18.41",
      "10.16.18.42",
      "10.16.18.43"
    ],
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
      {
        "C": "CN",
        "ST": "BeiJing",
        "L": "BeiJing",
        "O": "system:kube-scheduler",
        "OU": "4Paradigm"
      }
    ]
}
EOF
```

- hosts 列表包含**所有** kube-scheduler 节点 IP；
- CN 为 system:kube-scheduler、O 为 system:kube-scheduler，kubernetes 内置的 ClusterRoleBindings system:kube-scheduler 将赋予 kube-scheduler 工作所需的权限。

生成证书和密钥

```
cfssl gencert -ca=/etc/kubernetes/cert/ca.pem \
  -ca-key=/etc/kubernetes/cert/ca-key.pem \
  -config=/etc/kubernetes/cert/ca-config.json \
  -profile=kubernetes kube-scheduler-csr.json | cfssljson -bare kube-scheduler
```

创建和分发kubeconfig 文件

```
kubectl config set-cluster kubernetes \
  --certificate-authority=/etc/kubernetes/cert/ca.pem \
  --embed-certs=true \
  --server=https://10.16.18.40:8443 \
  --kubeconfig=kube-scheduler.kubeconfig

kubectl config set-credentials system:kube-scheduler \
  --client-certificate=kube-scheduler.pem \
  --client-key=kube-scheduler-key.pem \
  --embed-certs=true \
  --kubeconfig=kube-scheduler.kubeconfig

kubectl config set-context system:kube-scheduler \
  --cluster=kubernetes \
  --user=system:kube-scheduler \
  --kubeconfig=kube-scheduler.kubeconfig

kubectl config use-context system:kube-scheduler --kubeconfig=kube-scheduler.kubeconfig
```

分发文件

```
scp kube-scheduler.kubeconfig k8s@10.16.18.41:/etc/kubernetes/
scp kube-scheduler.kubeconfig k8s@10.16.18.42:/etc/kubernetes/
scp kube-scheduler.kubeconfig k8s@10.16.18.43:/etc/kubernetes/
```

创建和分发kube-scheduler systemd unit 文件

```
cat > kube-scheduler.service << EOF
[Unit]
Description=Kubernetes Scheduler
Documentation=https://github.com/GoogleCloudPlatform/kubernetes

[Service]
ExecStart=/opt/k8s/bin/kube-scheduler \\
  --address=127.0.0.1 \\
  --kubeconfig=/etc/kubernetes/kube-scheduler.kubeconfig \\
  --leader-elect=true \\
  --alsologtostderr=true \\
  --logtostderr=false \\
  --log-dir=/var/log/kubernetes \\
  --v=2
Restart=on-failure
RestartSec=5
User=k8s

[Install]
WantedBy=multi-user.target
EOF
```

- `--address`：在 127.0.0.1:10251 端口接收 http /metrics 请求；kube-scheduler 目前还不支持接收 https 请求；
- `--kubeconfig`：指定 kubeconfig 文件路径，kube-scheduler 使用它连接和验证 kube-apiserver；
- `--leader-elect=true`：集群运行模式，启用选举功能；被选为 leader 的节点负责处理工作，其它节点为阻塞状态；
- `User=k8s`：使用 k8s 账户运行；

启动kube-scheduler  服务

````
mkdir -p /var/log/kubernetes && chown -R k8s /var/log/kubernetes
systemctl daemon-reload && systemctl enable kube-scheduler && systemctl restart kube-scheduler
````

检查服务状态：

```
systemctl status kube-scheduler
```

## 查看输出的 metric

kube-scheduler 监听 10251 端口，接收 http 请求：

 ```
$ sudo netstat -lnpt|grep kube-sche
tcp        0      0 127.0.0.1:10251         0.0.0.0:*               LISTEN      23783/kube-schedule
$ curl -s http://127.0.0.1:10251/metrics |head
# HELP apiserver_audit_event_total Counter of audit events generated and sent to the audit backend.
# TYPE apiserver_audit_event_total counter
apiserver_audit_event_total 0
# HELP go_gc_duration_seconds A summary of the GC invocation durations.
# TYPE go_gc_duration_seconds summary
go_gc_duration_seconds{quantile="0"} 9.7715e-05
go_gc_duration_seconds{quantile="0.25"} 0.000107676
go_gc_duration_seconds{quantile="0.5"} 0.00017868
go_gc_duration_seconds{quantile="0.75"} 0.000262444
go_gc_duration_seconds{quantile="1"} 0.001205223
 ```

## 测试 kube-scheduler 集群的高可用

随便找一个或两个 master 节点，停掉 kube-scheduler 服务，看其它节点是否获取了 leader 权限（systemd 日志）。

查看当前的leader

```
[root@K8S-master1 ~]# kubectl get endpoints kube-scheduler --namespace=kube-system  -o yaml
apiVersion: v1
kind: Endpoints
metadata:
  annotations:
    control-plane.alpha.kubernetes.io/leader: '{"holderIdentity":"K8S-master2_0031df8d-0532-11e9-8cc4-0050569e5d59","leaseDurationSeconds":15,"acquireTime":"2018-12-21T15:06:55Z","renewTime":"2018-12-21T15:08:31Z","leaderTransitions":1}'
  creationTimestamp: "2018-12-21T15:05:58Z"
  name: kube-scheduler
  namespace: kube-system
  resourceVersion: "3965"
  selfLink: /api/v1/namespaces/kube-system/endpoints/kube-scheduler
  uid: ec185f90-0531-11e9-bd41-0050569e1db6
```

停掉leader后,leader 切换到master3 了。

```
[root@K8S-master1 ~]# kubectl get endpoints kube-scheduler --namespace=kube-system  -o yaml
apiVersion: v1
kind: Endpoints
metadata:
  annotations:
    control-plane.alpha.kubernetes.io/leader: '{"holderIdentity":"K8S-master3_0093134a-0532-11e9-b886-0050569e4520","leaseDurationSeconds":15,"acquireTime":"2018-12-21T15:09:41Z","renewTime":"2018-12-21T15:09:41Z","leaderTransitions":2}'
  creationTimestamp: "2018-12-21T15:05:58Z"
  name: kube-scheduler
  namespace: kube-system
  resourceVersion: "4047"
  selfLink: /api/v1/namespaces/kube-system/endpoints/kube-scheduler
  uid: ec185f90-0531-11e9-bd41-0050569e1db6
```

# 部署work 节点

kubernetes work 节点运行如下组件：

- docker
- kubelet
- kube-proxy

## 安装和配置 flanneld

创建k8s和docker 用户

```
useradd -m k8s
sh -c 'echo 123456 | passwd k8s --stdin'
visudo
# %wheel        ALL=(ALL)       NOPASSWD: ALL  #需要去掉#

grep '%wheel.*NOPASSWD: ALL' /etc/sudoers
%wheel    ALL=(ALL)    NOPASSWD: ALL
gpasswd -a k8s wheel

useradd -m docker
gpasswd -a k8s docker
mkdir -p  /etc/docker/
cat /etc/docker/daemon.json
{
    "registry-mirrors": ["https://hub-mirror.c.163.com", "https://docker.mirrors.ustc.edu.cn","harbor.iquantex.com"],
    "max-concurrent-downloads": 20
}
```

分发 flanneld 二进制文件到所有节点：

```
scp flannel/{flanneld,mk-docker-opts.sh} k8s@10.16.18.44:/opt/k8s/bin/
scp flannel/{flanneld,mk-docker-opts.sh} k8s@10.16.18.45:/opt/k8s/bin/
scp flannel/{flanneld,mk-docker-opts.sh} k8s@10.16.18.46:/opt/k8s/bin/
```

分发生成的证书和私钥到节点：

```
mkdir -p /etc/flanneld/cert && chown -R k8s /etc/flanneld
mkdir -p /etc/kubernetes/cert && chown -R k8s /etc/flanneld
scp flanneld*.pem k8s@10.16.18.44:/etc/flanneld/cert
scp flanneld*.pem k8s@10.16.18.45:/etc/flanneld/cert
scp flanneld*.pem k8s@10.16.18.46:/etc/flanneld/cert
scp -r /etc/kubernetes/cert  root@10.16.18.44:/etc/kubernetes/cert
scp -r /etc/kubernetes/cert  root@10.16.18.45:/etc/kubernetes/cert
scp -r /etc/kubernetes/cert  root@10.16.18.46:/etc/kubernetes/cert
```

分发flanneld systemd unit 文件

```
scp flanneld.service root@10.16.18.44:/etc/systemd/system/
scp flanneld.service root@10.16.18.45:/etc/systemd/system/
scp flanneld.service root@10.16.18.46:/etc/systemd/system/
```

## 部署kubelet

 kubelet 运行在每个 worker 节点上，接收 kube-apiserver 发送的请求，管理 Pod 容器，执行交互式命令，如 exec、run、logs 等。

kublet 启动时自动向 kube-apiserver 注册节点信息，内置的 cadvisor 统计和监控节点的资源使用情况。

为确保安全，本文档只开启接收 https 请求的安全端口，对请求进行认证和授权，拒绝未授权的访问(如 apiserver、heapster)。                                                                                                                                                                                                                                                                                

分发kubelet二进制文件：

```
scp kubelet k8s@10.16.18.44:/opt/k8s/bin/
scp kubelet k8s@10.16.18.45:/opt/k8s/bin/
scp kubelet k8s@10.16.18.46:/opt/k8s/bin/
```

创建库格勒天bootstrap kubeconfig 文件

```
 export BOOTSTRAP_TOKEN=$(kubeadm token create \
      --description kubelet-bootstrap-token \
      --groups system:bootstrappers:k8s-master1 \
      --kubeconfig ~/.kube/config)

# 设置集群参数
    kubectl config set-cluster kubernetes \
      --certificate-authority=/etc/kubernetes/cert/ca.pem \
      --embed-certs=true \
      --server=${KUBE_APISERVER} \
      --kubeconfig=kubelet-bootstrap-k8s-master1.kubeconfig

    # 设置客户端认证参数
    kubectl config set-credentials kubelet-bootstrap \
      --token=${BOOTSTRAP_TOKEN} \
      --kubeconfig=kubelet-bootstrap-k8s-master1.kubeconfig

    # 设置上下文参数
    kubectl config set-context default \
      --cluster=kubernetes \
      --user=kubelet-bootstrap \
      --kubeconfig=kubelet-bootstrap-k8s-master1.kubeconfig

    # 设置默认上下文
    kubectl config use-context default --kubeconfig=kubelet-bootstrap-k8s-master1.kubeconfig
```

查看创建结果：

```
[root@K8S-master1 ~]# kubeadm token list --kubeconfig ~/.kube/config
TOKEN                     TTL       EXPIRES                     USAGES                   DESCRIPTION               EXTRA GROUPS
0iyzyo.hdqioymj37zmsxx3   23h       2018-12-26T15:42:02+08:00   authentication,signing   kubelet-bootstrap-token   system:bootstrappers:k8s-master2
6foksn.q1iae6pg6ra2yoge   23h       2018-12-26T15:42:02+08:00   authentication,signing   kubelet-bootstrap-token   system:bootstrappers:k8s-master1
9kceqr.kb13wq77q3makgxl   23h       2018-12-26T15:42:02+08:00   authentication,signing   kubelet-bootstrap-token   system:bootstrappers:k8s-node1
u5yfq1.cp77cvh9f2uhzxct   23h       2018-12-26T15:42:03+08:00   authentication,signing   kubelet-bootstrap-token   system:bootstrappers:k8s-node2
xne568.ilbzrkndatu4q3vh   23h       2018-12-26T15:42:03+08:00   authentication,signing   kubelet-bootstrap-token   system:bootstrappers:k8s-node3
zfj4an.albhhi17c4p3i8yl   23h       2018-12-26T15:42:02+08:00   authentication,signing   kubelet-bootstrap-token   system:bootstrappers:k8s-master3
```

分发kubeconfig 文件到所有的worker 节点

```
scp kubelet-bootstrap-k8s-master1.kubeconfig  k8s@10.16.18.44:/etc/kubernetes/kubelet-bootstrap.kubeconfig
```

创建 kubelet 参数配置文件

```
source /opt/k8s/bin/environment.sh
cat > kubelet.config.json.template <<EOF
{
  "kind": "KubeletConfiguration",
  "apiVersion": "kubelet.config.k8s.io/v1beta1",
  "authentication": {
    "x509": {
      "clientCAFile": "/etc/kubernetes/cert/ca.pem"
    },
    "webhook": {
      "enabled": true,
      "cacheTTL": "2m0s"
    },
    "anonymous": {
      "enabled": false
    }
  },
  "authorization": {
    "mode": "Webhook",
    "webhook": {
      "cacheAuthorizedTTL": "5m0s",
      "cacheUnauthorizedTTL": "30s"
    }
  },
  "address": "##NODE_IP##",
  "port": 10250,
  "readOnlyPort": 0,
  "cgroupDriver": "systemd",
  "hairpinMode": "promiscuous-bridge",
  "serializeImagePulls": false,
  "featureGates": {
    "RotateKubeletClientCertificate": true,
    "RotateKubeletServerCertificate": true
  },
  "clusterDomain": "${CLUSTER_DNS_DOMAIN}",
  "clusterDNS": ["${CLUSTER_DNS_SVC_IP}"]
}
```

- address：API 监听地址，不能为 127.0.0.1，否则 kube-apiserver、heapster 等不能调用 kubelet 的 API；
- readOnlyPort=0：关闭只读端口(默认 10255)，等效为未指定；
- authentication.anonymous.enabled：设置为 false，不允许匿名�访问 10250 端口；
- authentication.x509.clientCAFile：指定签名客户端证书的 CA 证书，开启 HTTP 证书认证；
- authentication.webhook.enabled=true：开启 HTTPs bearer token 认证；
- 对于未通过 x509 证书和 webhook 认证的请求(kube-apiserver 或其他客户端)，将被拒绝，提示 Unauthorized；
- authroization.mode=Webhook：kubelet 使用 SubjectAccessReview API 查询 kube-apiserver 某 user、group 是否具有操作资源的权限(RBAC)；
- featureGates.RotateKubeletClientCertificate、featureGates.RotateKubeletServerCertificate：自动 rotate 证书，证书的有效期取决于 kube-controller-manager 的 --experimental-cluster-signing-duration 参数；
- 需要 root 账户运行；

分发文件：

```
scp kubelet.config.json.template root@10.16.18.44:/etc/kubernetes/kubelet.config.json
```

创建kubelet systemd unit 文件

```
cat > kubelet.service.template <<EOF
[Unit]
Description=Kubernetes Kubelet
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=docker.service
Requires=docker.service

[Service]
WorkingDirectory=/var/lib/kubelet
ExecStart=/opt/k8s/bin/kubelet \\
  --bootstrap-kubeconfig=/etc/kubernetes/kubelet-bootstrap.kubeconfig \\
  --cert-dir=/etc/kubernetes/cert \\
  --kubeconfig=/etc/kubernetes/kubelet.kubeconfig \\
  --config=/etc/kubernetes/kubelet.config.json \\
  --hostname-override=##NODE_NAME## \\
  --pod-infra-container-image=registry.access.redhat.com/rhel7/pod-infrastructure:latest \\
  --allow-privileged=true \\
  --alsologtostderr=true \\
  --logtostderr=false \\
  --log-dir=/var/log/kubernetes \\
  --runtime-cgroups=/systemd/system.slice \\
  --kubelet-cgroups=/systemd/system.slice  \\
  --v=2
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

- 如果设置了 `--hostname-override` 选项，则 `kube-proxy` 也需要设置该选项，否则会出现找不到 Node 的情况；
- `--bootstrap-kubeconfig`：指向 bootstrap kubeconfig 文件，kubelet 使用该文件中的用户名和 token 向 kube-apiserver 发送 TLS Bootstrapping 请求；
- K8S approve kubelet 的 csr 请求后，在 `--cert-dir` 目录创建证书和私钥文件，然后写入 `--kubeconfig` 文件；

分发文件：

```
scp  kubelet.service.template  k8s@10.16.18.44:/etc/kubernetes/ kubelet.service
```

## Bootstrap Token Auth 和授予权限

kublet 启动时查找配置的 --kubeletconfig 文件是否存在，如果不存在则使用 --bootstrap-kubeconfig 向 kube-apiserver 发送证书签名请求 (CSR)。

kube-apiserver 收到 CSR 请求后，对其中的 Token 进行认证（事先使用 kubeadm 创建的 token），认证通过后将请求的 user 设置为 system:bootstrap:，group 设置为 system:bootstrappers，这一过程称为 Bootstrap Token Auth。

默认情况下，这个 user 和 group 没有创建 CSR 的权限，kubelet 启动失败，错误日志如下：

```
$ sudo journalctl -u kubelet -a |grep -A 2 'certificatesigningrequests'
May 06 06:42:36 kube-node1 kubelet[26986]: F0506 06:42:36.314378   26986 server.go:233] failed to run Kubelet: cannot create certificate signing request: certificatesigningrequests.certificates.k8s.io is forbidden: User "system:bootstrap:lemy40" cannot create certificatesigningrequests.certificates.k8s.io at the cluster scope
May 06 06:42:36 kube-node1 systemd[1]: kubelet.service: Main process exited, code=exited, status=255/n/a
May 06 06:42:36 kube-node1 systemd[1]: kubelet.service: Failed with result 'exit-code'.
```

解决办法是：创建一个 clusterrolebinding，将 group system:bootstrappers 和 clusterrole system:node-bootstrapper 绑定：

```
$ kubectl create clusterrolebinding kubelet-bootstrap --clusterrole=system:node-bootstrapper --group=system:bootstrappers
```

 ### 启动kubelet 服务

```
mkdir -p /var/lib/kubelet
swapoff -a
mkdir -p /var/log/kubernetes 
chown -R k8s /var/log/kubernetes
systemctl daemon-reload && systemctl enable kubelet && systemctl restart kubelet
```

kubelet 启动后使用 --bootstrap-kubeconfig 向 kube-apiserver 发送 CSR 请求，当这个 CSR 被 approve 后，kube-controller-manager 为 kubelet 创建 TLS 客户端证书、私钥和 --kubeletconfig 文件。

注意：kube-controller-manager 需要配置 `--cluster-signing-cert-file` 和 `--cluster-signing-key-file`参数，才会为 TLS Bootstrap 创建证书和私钥。

```
$ kubectl get csr
NAME                                                   AGE       REQUESTOR                 CONDITION
node-csr-QzuuQiuUfcSdp3j5W4B2UOuvQ_n9aTNHAlrLzVFiqrk   43s       system:bootstrap:zkiem5   Pending
node-csr-oVbPmU-ikVknpynwu0Ckz_MvkAO_F1j0hmbcDa__sGA   27s       system:bootstrap:mkus5s   Pending
node-csr-u0E1-ugxgotO_9FiGXo8DkD6a7-ew8sX2qPE6KPS2IY   13m       system:bootstrap:k0s2bj   Pending

$ kubectl get nodes
No resources found.
```

- 三个 work 节点的 csr 均处于 pending 状态；

## approve kubelet CSR 请求



手动 approver CSR 请求：

```
$ kubectl certificate approve node-csr-QzuuQiuUfcSdp3j5W4B2UOuvQ_n9aTNHAlrLzVFiqrk
certificatesigningrequest.certificates.k8s.io "node-csr-QzuuQiuUfcSdp3j5W4B2UOuvQ_n9aTNHAlrLzVFiqrk" approved
```

查看 Approve 结果：

```
$ kubectl describe  csr node-csr-QzuuQiuUfcSdp3j5W4B2UOuvQ_n9aTNHAlrLzVFiqrk
Name:               node-csr-QzuuQiuUfcSdp3j5W4B2UOuvQ_n9aTNHAlrLzVFiqrk
Labels:             <none>
Annotations:        <none>
CreationTimestamp:  Wed, 13 Jun 2018 16:05:04 +0800
Requesting User:    system:bootstrap:zkiem5
Status:             Approved
Subject:
         Common Name:    system:node:kube-node2
         Serial Number:
         Organization:   system:nodes
Events:  <none>
```

- `Requesting User`：请求 CSR 的用户，kube-apiserver 对它进行认证和授权；
- `Subject`：请求签名的证书信息；
- 证书的 CN 是 system:node:kube-node2， Organization 是 system:nodes，kube-apiserver 的 Node 授权模式会授予该证书的相关权限；

 自动 approve CSR 请求：

创建三个 ClusterRoleBinding，分别用于自动 approve client、renew client、renew server 证书：

```
cat > csr-crb.yaml <<EOF
 # Approve all CSRs for the group "system:bootstrappers"
 kind: ClusterRoleBinding
 apiVersion: rbac.authorization.k8s.io/v1
 metadata:
   name: auto-approve-csrs-for-group
 subjects:
 - kind: Group
   name: system:bootstrappers
   apiGroup: rbac.authorization.k8s.io
 roleRef:
   kind: ClusterRole
   name: system:certificates.k8s.io:certificatesigningrequests:nodeclient
   apiGroup: rbac.authorization.k8s.io
---
 # To let a node of the group "system:nodes" renew its own credentials
 kind: ClusterRoleBinding
 apiVersion: rbac.authorization.k8s.io/v1
 metadata:
   name: node-client-cert-renewal
 subjects:
 - kind: Group
   name: system:nodes
   apiGroup: rbac.authorization.k8s.io
 roleRef:
   kind: ClusterRole
   name: system:certificates.k8s.io:certificatesigningrequests:selfnodeclient
   apiGroup: rbac.authorization.k8s.io
---
# A ClusterRole which instructs the CSR approver to approve a node requesting a
# serving cert matching its client cert.
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: approve-node-server-renewal-csr
rules:
- apiGroups: ["certificates.k8s.io"]
  resources: ["certificatesigningrequests/selfnodeserver"]
  verbs: ["create"]
---
 # To let a node of the group "system:nodes" renew its own server credentials
 kind: ClusterRoleBinding
 apiVersion: rbac.authorization.k8s.io/v1
 metadata:
   name: node-server-cert-renewal
 subjects:
 - kind: Group
   name: system:nodes
   apiGroup: rbac.authorization.k8s.io
 roleRef:
   kind: ClusterRole
   name: approve-node-server-renewal-csr
   apiGroup: rbac.authorization.k8s.io
EOF
```

- auto-approve-csrs-for-group：自动 approve node 的第一次 CSR； 注意第一次 CSR 时，请求的 Group 为 system:bootstrappers；
- node-client-cert-renewal：自动 approve node 后续过期的 client 证书，自动生成的证书 Group 为 system:nodes;
- node-server-cert-renewal：自动 approve node 后续过期的 server 证书，自动生成的证书 Group 为 system:nodes;

 生效配置：

```
kubectl apply -f csr-crb.yaml
```

## 查看 kublet 的情况

等待一段时间(1-10 分钟)，三个节点的 CSR 都被自动 approve：

```
$ kubectl get nodes
NAME         STATUS    ROLES     AGE       VERSION
kube-node1   Ready     <none>    18m       v1.10.4
kube-node2   Ready     <none>    10m       v1.10.4
kube-node3   Ready     <none>    11m       v1.10.4
```

kube-controller-manager 为各 node 生成了 kubeconfig 文件和公私钥：

```
ls -l /etc/kubernetes/kubelet.kubeconfig
-rw------- 1 root root 2293 Jun 13 17:07 /etc/kubernetes/kubelet.kubeconfig

$ ls -l /etc/kubernetes/cert/|grep kubelet
-rw-r--r-- 1 root root 1046 Jun 13 17:07 kubelet-client.crt
-rw------- 1 root root  227 Jun 13 17:07 kubelet-client.key
-rw------- 1 root root 1334 Jun 13 17:07 kubelet-server-2018-06-13-17-07-45.pem
lrwxrwxrwx 1 root root   58 Jun 13 17:07 kubelet-server-current.pem -> /etc/kubernetes/cert/kubelet-server-2018-06-13-17-07-45.pem
```

kublet 启动后监听多个端口，用于接收 kube-apiserver 或其它组件发送的请求：

```
[root@K8S-node1 kubernetes]# netstat  -anlp|grep kubelet
tcp        0      0 127.0.0.1:37502         0.0.0.0:*               LISTEN      5498/kubelet
tcp        0      0 127.0.0.1:10248         0.0.0.0:*               LISTEN      5498/kubelet
tcp        0      0 10.16.18.44:10250       0.0.0.0:*               LISTEN      5498/kubelet
tcp        0      0 10.16.18.44:46966       10.16.18.40:8443        ESTABLISHED 5498/kubelet
```

- 4194: cadvisor http 服务；
- 10248: healthz http 服务；
- 10250: https API 服务；注意：未开启只读端口 10255；

例如执行 `kubectl ec -it nginx-ds-5rmws -- sh` 命令时，kube-apiserver 会向 kubelet 发送如下请求：

```
POST /exec/default/nginx-ds-5rmws/my-nginx?command=sh&input=1&output=1&tty=1
```

kubelet 接收 10250 端口的 https 请求：

- /pods、/runningpods
- /metrics、/metrics/cadvisor、/metrics/probes
- /spec
- /stats、/stats/container
- /logs
- /run/、"/exec/", "/attach/", "/portForward/", "/containerLogs/" 等管理；

详情参考：<https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/server/server.go#L434:3>

 由于关闭了匿名认证，同时开启了 webhook 授权，所有访问 10250 端口 https API 的请求都需要被认证和授权。

预定义的 ClusterRole system:kubelet-api-admin 授予访问 kubelet 所有 API 的权限：

```
$ kubectl describe clusterrole system:kubelet-api-admin
Name:         system:kubelet-api-admin
Labels:       kubernetes.io/bootstrapping=rbac-defaults
Annotations:  rbac.authorization.kubernetes.io/autoupdate=true
PolicyRule:
  Resources      Non-Resource URLs  Resource Names  Verbs
  ---------      -----------------  --------------  -----
  nodes          []                 []              [get list watch proxy]
  nodes/log      []                 []              [*]
  nodes/metrics  []                 []              [*]
  nodes/proxy    []                 []              [*]
  nodes/spec     []                 []              [*]
  nodes/stats    []                 []              [*]
```

### 部署kube-proxy 组件

kube-proxy 运行在所有 worker 节点上，，它监听 apiserver 中 service 和 Endpoint 的变化情况，创建路由规则来进行服务负载均衡。

本文档讲解部署 kube-proxy 的部署，使用 ipvs 模式。

创建证书：

```
cat > kube-proxy-csr.json << EOF
{
  "CN": "system:kube-proxy",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "BeiJing",
      "L": "BeiJing",
      "O": "k8s",
      "OU": "4Paradigm"
    }
  ]
}
EOF
```

- CN：指定该证书的 User 为 `system:kube-proxy`；
- 预定义的 RoleBinding `system:node-proxier` 将User `system:kube-proxy` 与 Role `system:node-proxier` 绑定，该 Role 授予了调用 `kube-apiserver` Proxy 相关 API 的权限；
- 该证书只会被 kube-proxy 当做 client 证书使用，所以 hosts 字段为空；

生成证书和私钥：

```
cfssl gencert -ca=/etc/kubernetes/cert/ca.pem \
  -ca-key=/etc/kubernetes/cert/ca-key.pem \
  -config=/etc/kubernetes/cert/ca-config.json \
  -profile=kubernetes  kube-proxy-csr.json | cfssljson -bare kube-proxy
```

创建kubeconfig 文件：

```
source /opt/k8s/bin/environment.sh
kubectl config set-cluster kubernetes \
  --certificate-authority=/etc/kubernetes/cert/ca.pem \
  --embed-certs=true \
  --server=${KUBE_APISERVER} \
  --kubeconfig=kube-proxy.kubeconfig

kubectl config set-credentials kube-proxy \
  --client-certificate=kube-proxy.pem \
  --client-key=kube-proxy-key.pem \
  --embed-certs=true \
  --kubeconfig=kube-proxy.kubeconfig

kubectl config set-context default \
  --cluster=kubernetes \
  --user=kube-proxy \
  --kubeconfig=kube-proxy.kubeconfig

kubectl config use-context default --kubeconfig=kube-proxy.kubeconfig
```

- `--embed-certs=true`：将 ca.pem 和 admin.pem 证书内容嵌入到生成的 kubectl-proxy.kubeconfig 文件中(不加时，写入的是证书文件路径)；

分发 kubeconfig 文件：

```
scp kube-proxy.kubeconfig k8s@10.16.18.44:/etc/kubernetes
```

创建kube-proxy 配置文件

从 v1.10 开始，kube-proxy **部分参数**可以配置文件中配置。可以使用 `--write-config-to` 选项生成该配置文件，或者参考 kubeproxyconfig 的类型定义源文件 ：

<https://github.com/kubernetes/kubernetes/blob/master/pkg/proxy/apis/kubeproxyconfig/types.go>

创建 kube-proxy config 文件模板：

```
cat >kube-proxy.config.yaml.template <<EOF
apiVersion: kubeproxy.config.k8s.io/v1alpha1
bindAddress: ##NODE_IP##
clientConnection:
  kubeconfig: /etc/kubernetes/kube-proxy.kubeconfig
clusterCIDR: ${CLUSTER_CIDR}
healthzBindAddress: ##NODE_IP##:10256
hostnameOverride: ##NODE_NAME##
kind: KubeProxyConfiguration
metricsBindAddress: ##NODE_IP##:10249
mode: "ipvs"
EOF
```

- `bindAddress`: 监听地址；

- `clientConnection.kubeconfig`: 连接 apiserver 的 kubeconfig 文件；

- `clusterCIDR`: kube-proxy 根据 `--cluster-cidr` 判断集群内部和外部流量，指定 `--cluster-cidr` 或 `--masquerade-all` 选项后 kube-proxy 才会对访问 Service IP 的请求做 SNAT；

- `hostnameOverride`: 参数值必须与 kubelet 的值一致，否则 kube-proxy 启动后会找不到该 Node，从而不会创建任何 ipvs 规则；

- `mode`: 使用 ipvs 模式；

  分发 kube-proxy 配置文件：

  ```
  scp kube-proxy.config.yaml.template root@10.16.18.44:/etc/kubernetes/kube-proxy.config.yaml
  ```

创建 kube-proxy systemd unit 文件：

```
source /opt/k8s/bin/environment.sh
cat > kube-proxy.service <<EOF
[Unit]
Description=Kubernetes Kube-Proxy Server
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=network.target

[Service]
WorkingDirectory=/var/lib/kube-proxy
ExecStart=/opt/k8s/bin/kube-proxy \\
  --config=/etc/kubernetes/kube-proxy.config.yaml \\
  --alsologtostderr=true \\
  --logtostderr=false \\
  --log-dir=/var/log/kubernetes \\
  --v=2
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
```

分发文件：

```
scp kube-proxy.service root@10.16.18.44:/etc/systemd/system
```

启动 kube-proxy 服务:

```
mkdir -p /var/lib/kube-proxy
mkdir -p /var/log/kubernetes && chown -R k8s /var/log/kubernetes
systemctl daemon-reload && systemctl enable kube-proxy && systemctl restart kube-proxy
```

## 查看监听端口和 metrics

```
[k8s@kube-node1 ~]$ sudo netstat -lnpt|grep kube-prox
tcp        0      0 172.27.129.105:10249    0.0.0.0:*               LISTEN      16847/kube-proxy
tcp        0      0 172.27.129.105:10256    0.0.0.0:*               LISTEN      16847/kube-proxy
```

- 10249：http prometheus metrics port;
- 10256：http healthz port;

```
[root@K8S-node3 system]# ipvsadm -ln
IP Virtual Server version 1.2.1 (size=4096)
Prot LocalAddress:Port Scheduler Flags
  -> RemoteAddress:Port           Forward Weight ActiveConn InActConn
TCP  10.254.0.1:443 rr
  -> 10.16.18.41:6443             Masq    1      0          0
  -> 10.16.18.42:6443             Masq    1      0          0
  -> 10.16.18.43:6443             Masq    1      0          0
```

可见将所有到 kubernetes cluster ip 443 端口的请求都转发到 kube-apiserver 的 6443 端口；

# 验证集群功能

本文档使用 daemonset 验证 master 和 worker 节点是否工作正常。

```
[root@K8S-master2 system]# kubectl  get nodes
NAME        STATUS   ROLES    AGE   VERSION
k8s-node1   Ready    <none>   20h   v1.13.0
k8s-node2   Ready    <none>   19h   v1.13.0
k8s-node3   Ready    <none>   19h   v1.13.0
```

创建测试文件

```
cat > nginx-ds.yml <<EOF
apiVersion: v1
kind: Service
metadata:
  name: nginx-ds
  labels:
    app: nginx-ds
spec:
  type: NodePort
  selector:
    app: nginx-ds
  ports:
  - name: http
    port: 80
    targetPort: 80
---
apiVersion: extensions/v1beta1
kind: DaemonSet
metadata:
  name: nginx-ds
  labels:
    addonmanager.kubernetes.io/mode: Reconcile
spec:
  template:
    metadata:
      labels:
        app: nginx-ds
    spec:
      containers:
      - name: my-nginx
        image: nginx:1.7.9
        ports:
        - containerPort: 80
EOF
```

# 安装集群插件

插件是集群的附件组件，丰富和完善了集群的功能。

## 部署coredns 插件

coredns 对应的目录是：`cluster/addons/dns`。

修改配置文件

```
[root@K8S-master1 coredns]# diff  coredns.yaml ../kubernetes/cluster/addons/dns/coredns/coredns.yaml.base
67c67
<         kubernetes cluster.local. in-addr.arpa ip6.arpa {
---
>         kubernetes __PILLAR__DNS__DOMAIN__ in-addr.arpa ip6.arpa {
115c115
<         image: docker.io/coredns/coredns:1.2.6
---
>         image: k8s.gcr.io/coredns:1.2.6
180c180
<   clusterIP: 10.254.0.2
---
>   clusterIP: __PILLAR__DNS__SERVER__
```

## 部署dashboard 插件

dashboard 对应的目录是：`cluster/addons/dashboard`。

 修改配置文件：

```
diff dashboard-controller.yaml{,.orig}
33c33
<         image: siriuszg/kubernetes-dashboard-amd64:v1.10.0
---
>         image: k8s.gcr.io/kubernetes-dashboard-amd64:v1.10.0

$ cp dashboard-service.yaml{,.orig}

$ diff dashboard-service.yaml.orig dashboard-service.yaml
10a11
>   type: NodePort
```

访问：https://10.16.18.44:30525/

## 创建登录 Dashboard 的 token 和 kubeconfig 配置文件

上面提到，Dashboard 默认只支持 token 认证，所以如果使用 KubeConfig 文件，需要在该文件中指定 token，不支持使用 client 证书认证。

### 创建登录 token

```
kubectl create sa dashboard-admin -n kube-system
kubectl create clusterrolebinding dashboard-admin --clusterrole=cluster-admin --serviceaccount=kube-system:dashboard-admin
ADMIN_SECRET=$(kubectl get secrets -n kube-system | grep dashboard-admin | awk '{print $1}')
DASHBOARD_LOGIN_TOKEN=$(kubectl describe secret -n kube-system ${ADMIN_SECRET} | grep -E '^token' | awk '{print $2}')
echo ${DASHBOARD_LOGIN_TOKEN}
```

使用输出的 token 登录 Dashboard。

### 创建使用 token 的 KubeConfig 文件

```
source /opt/k8s/bin/environment.sh
# 设置集群参数
kubectl config set-cluster kubernetes \
  --certificate-authority=/etc/kubernetes/cert/ca.pem \
  --embed-certs=true \
  --server=${KUBE_APISERVER} \
  --kubeconfig=dashboard.kubeconfig

# 设置客户端认证参数，使用上面创建的 Token
kubectl config set-credentials dashboard_user \
  --token=${DASHBOARD_LOGIN_TOKEN} \
  --kubeconfig=dashboard.kubeconfig

# 设置上下文参数
kubectl config set-context default \
  --cluster=kubernetes \
  --user=dashboard_user \
  --kubeconfig=dashboard.kubeconfig

# 设置默认上下文
kubectl config use-context default --kubeconfig=dashboard.kubeconfig
```

用生成的 dashboard.kubeconfig 登录 Dashboard。



## 查看 dashboard 支持的命令行参数

```
$ kubectl exec --namespace kube-system -it kubernetes-dashboard-65f7b4f486-wgc6j  -- /dashboard --help
2018/06/13 15:17:44 Starting overwatch
Usage of /dashboard:
      --alsologtostderr                   log to standard error as well as files
      --apiserver-host string             The address of the Kubernetes Apiserver to connect to in the format of protocol://address:port, e.g., http://localhost:8080. If not specified, the assumption is that the binary runs inside a Kubernetes cluster and local discovery is attempted.
      --authentication-mode stringSlice   Enables authentication options that will be reflected on login screen. Supported values: token, basic. Default: token.Note that basic option should only be used if apiserver has '--authorization-mode=ABAC' and '--basic-auth-file' flags set. (default [token])
      --auto-generate-certificates        When set to true, Dashboard will automatically generate certificates used to serve HTTPS. Default: false.
      --bind-address ip                   The IP address on which to serve the --secure-port (set to 0.0.0.0 for all interfaces). (default 0.0.0.0)
      --default-cert-dir string           Directory path containing '--tls-cert-file' and '--tls-key-file' files. Used also when auto-generating certificates flag is set. (default "/certs")
      --disable-settings-authorizer       When enabled, Dashboard settings page will not require user to be logged in and authorized to access settings page.
      --enable-insecure-login             When enabled, Dashboard login view will also be shown when Dashboard is not served over HTTPS. Default: false.
      --heapster-host string              The address of the Heapster Apiserver to connect to in the format of protocol://address:port, e.g., http://localhost:8082. If not specified, the assumption is that the binary runs inside a Kubernetes cluster and service proxy will be used.
      --insecure-bind-address ip          The IP address on which to serve the --port (set to 0.0.0.0 for all interfaces). (default 127.0.0.1)
      --insecure-port int                 The port to listen to for incoming HTTP requests. (default 9090)
      --kubeconfig string                 Path to kubeconfig file with authorization and master location information.
      --log_backtrace_at traceLocation    when logging hits line file:N, emit a stack trace (default :0)
      --log_dir string                    If non-empty, write log files in this directory
      --logtostderr                       log to standard error instead of files
      --metric-client-check-period int    Time in seconds that defines how often configured metric client health check should be run. Default: 30 seconds. (default 30)
      --port int                          The secure port to listen to for incoming HTTPS requests. (default 8443)
      --stderrthreshold severity          logs at or above this threshold go to stderr (default 2)
      --system-banner string              When non-empty displays message to Dashboard users. Accepts simple HTML tags. Default: ''.
      --system-banner-severity string     Severity of system banner. Should be one of 'INFO|WARNING|ERROR'. Default: 'INFO'. (default "INFO")
      --tls-cert-file string              File containing the default x509 Certificate for HTTPS.
      --tls-key-file string               File containing the default x509 private key matching --tls-cert-file.
      --token-ttl int                     Expiration time (in seconds) of JWE tokens generated by dashboard. Default: 15 min. 0 - never expires (default 900)
  -v, --v Level                           log level for V logs
      --vmodule moduleSpec                comma-separated list of pattern=N settings for file-filtered logging
command terminated with exit code 2
$
```

## 部署metrics-server插件

创建metrics-server证书：

```
cat > metrics-server-csr.json <<EOF
{
  "CN": "aggregator",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "BeiJing",
      "L": "BeiJing",
      "O": "k8s",
      "OU": "4Paradigm"
    }
  ]
}
EOF
```

- 注意： CN 名称为 aggregator，需要与 kube-apiserver 的 --requestheader-allowed-names 参数配置一致；

生成 metrics-server 证书和私钥：

```
cfssl gencert -ca=/etc/kubernetes/cert/ca.pem \
  -ca-key=/etc/kubernetes/cert/ca-key.pem  \
  -config=/etc/kubernetes/cert/ca-config.json  \
  -profile=kubernetes metrics-server-csr.json | cfssljson -bare metrics-server
```

将生成的证书和私钥文件拷贝到 kube-apiserver 节点：

```
scp metrics-server*.pem k8s@${node_ip}:/etc/kubernetes/cert/
```

修改 kubernetes 控制平面组件的配置以支持 metrics-server

Kube-apiserver 添加配置参数：

````
--requestheader-client-ca-file=/etc/kubernetes/cert/ca.pem
--requestheader-allowed-names=""
--requestheader-extra-headers-prefix="X-Remote-Extra-"
--requestheader-group-headers=X-Remote-Group
--requestheader-username-headers=X-Remote-User
--proxy-client-cert-file=/etc/kubernetes/cert/metrics-server.pem
--proxy-client-key-file=/etc/kubernetes/cert/metrics-server-key.pem
--runtime-config=api/all=true
````

- `--requestheader-XXX`、`--proxy-client-XXX` 是 kube-apiserver 的 aggregator layer 相关的配置参数，metrics-server & HPA 需要使用；
- `--requestheader-client-ca-file`：用于签名 `--proxy-client-cert-file` 和 `--proxy-client-key-file` 指定的证书；在启用了 metric aggregator 时使用；
- 如果 --requestheader-allowed-names 不为空，则--proxy-client-cert-file 证书的 CN 必须位于 allowed-names 中，默认为 aggregator;

如果 kube-apiserver 机器**没有**运行 kube-proxy，则还需要添加 `--enable-aggregator-routing=true` 参数；

关于 `--requestheader-XXX` 相关参数，参考：

- <https://github.com/kubernetes-incubator/apiserver-builder/blob/master/docs/concepts/auth.md>
- <https://docs.bitnami.com/kubernetes/how-to/configure-autoscaling-custom-metrics/>

注意：requestheader-client-ca-file 指定的 CA 证书，必须具有 client auth and server auth；

### kube-controllr-manager

添加如下配置参数：

```--horizontal-pod-autoscaler-use-rest-clients=true```

用于配置 HPA 控制器使用 REST 客户端获取 metrics 数据。

![image-20181227153940605](/Volumes/mac-d/markdown/image/image-20181227153940605.png)

## 部署EFK插件

EFK 对应目录：kubernetes/cluster/addons/fluentd-elasticsearch







### 问题：open /etc/docker/certs.d/registry.access.redhat.com/redhat-ca.crt: no such file or directory

解决方法：

```
yum install *rhsm*
这两个命令会生成/etc/rhsm/ca/redhat-uep.pem文件.
wget http://mirror.centos.org/centos/7/os/x86_64/Packages/python-rhsm-certificates-1.19.10-1.el7_4.x86_64.rpm
rpm2cpio python-rhsm-certificates-1.19.10-1.el7_4.x86_64.rpm | cpio -iv --to-stdout ./etc/rhsm/ca/redhat-uep.pem | tee /etc/rhsm/ca/redhat-uep.pem
```

### 问题二： docker 通过yum安装的,k8s 分配pod的ip 是通过本地的docker0 网卡分配的。

解决办法：

```
在`/usr/lib/systemd/system/docker.service` 增加 EnvironmentFile=-/run/flannel/docker

注意有多个EnvironmentFile时，需要填到最后的EnvironmentFile里。
```

### 问题三：metric-server 启动error ，提示找不到 host

解决办法：

![image-20181227135917249](/Volumes/mac-d/markdown/image/image-20181227135917249.png)

````
在 metrics-server-deployment.yaml 增加
        - --kubelet-preferred-address-types=InternalIP,Hostname,InternalDNS,ExternalDNS,ExternalIP 
````

### 问题四：metric-server 启动error，提示访问node 10255端口问题

解决办法：

![image-20181227140100086](/Volumes/mac-d/markdown/image/image-20181227140100086.png)

```
在metrics-server-deployment.yaml 增加
- --kubelet-insecure-tls 取消证书认证
- --kubelet-port=10250 将10255 改成10250
#- --deprecated-kubelet-completely-insecure=true 注释掉
```

