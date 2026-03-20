FROM ubuntu:latest

# 设置环境变量
ENV DEBIAN_FRONTEND=noninteractive
ENV HTTP_PROXY=http://127.0.0.1:7890
ENV HTTPS_PROXY=http://127.0.0.1:7890

# 配置中国镜像源（清华镜像）
RUN sed -i 's|http://archive.ubuntu.com|http://mirrors.tuna.tsinghua.edu.cn|g' /etc/apt/sources.list \
    && sed -i 's|http://security.ubuntu.com|http://mirrors.tuna.tsinghua.edu.cn|g' /etc/apt/sources.list

# 更新并安装 OpenLDAP 开发包
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        slapd \
        libldap-dev \
        ldap-utils \
        build-essential \
        make \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# 复制项目文件
WORKDIR /workspace/ppolicy-extensions
COPY . /workspace/ppolicy-extensions/

# 编译
RUN make clean && make all

# 默认命令
CMD ["/bin/bash"]
