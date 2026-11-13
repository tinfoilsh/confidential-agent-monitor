FROM docker.io/library/ubuntu:24.04@sha256:224a1869083a311ef3f13648a154ba79832fbef6364d31493642ca03082da254
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git openssh-server openssh-client python3 sudo \
    iproute2 util-linux procps tar xz-utils \
    && rm -rf /var/lib/apt/lists/* \
    && if id ubuntu >/dev/null 2>&1; then userdel -r ubuntu; fi
ARG TARGETARCH
ARG SING_BOX=1.14.3
RUN cd /tmp && file=sing-box-$SING_BOX-linux-$TARGETARCH \
    && curl -fsSLO "https://github.com/SagerNet/sing-box/releases/download/v$SING_BOX/$file.tar.gz" \
    && printf '%s  %s\n' \
       e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee "sing-box-$SING_BOX-linux-amd64.tar.gz" \
       29dae24d76bea3bc62d07dd3e60cfc12003de7debbd6b768df9be9c68360174e "sing-box-$SING_BOX-linux-arm64.tar.gz" \
       | sha256sum -c --ignore-missing --quiet \
    && tar -xzf "$file.tar.gz" --strip-components=1 -C /usr/local/bin "$file/sing-box" \
    && mkdir -p /usr/local/share/licenses/sing-box \
    && tar -xOzf "$file.tar.gz" "$file/LICENSE" > /usr/local/share/licenses/sing-box/LICENSE \
    && rm "$file.tar.gz"
RUN useradd -m -u 1000 -s /bin/bash agent \
    && passwd -d agent \
    && printf 'agent ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/agent \
    && chmod 440 /etc/sudoers.d/agent \
    && install -d -o agent -g agent /workspace
COPY init.sh /sbin/monitor-init
RUN chmod 755 /sbin/monitor-init \
    && rm -f /etc/ssh/ssh_host_* \
    && printf '%s\n' \
       'ListenAddress 127.0.0.1' 'Port 22' 'HostKey /run/sshd/host_key' \
       'PidFile /run/sshd/sshd.pid' 'PasswordAuthentication no' \
       'KbdInteractiveAuthentication no' 'PermitEmptyPasswords no' \
       'PermitRootLogin no' 'UsePAM no' 'AllowUsers agent' \
       'AllowAgentForwarding no' 'AllowTcpForwarding remote' 'X11Forwarding no' \
       'PermitUserEnvironment no' 'PrintMotd no' \
       > /etc/ssh/sshd_config.monitor
COPY agents.json /tmp/agents.json
RUN python3 -c 'import json, platform; [print(name, *map(agent["download"][platform.machine()].get, ("url", "sha256", "binary"))) \
        for name, agent in json.load(open("/tmp/agents.json")).items()]' > /tmp/agents.list \
    && while read -r name url sha256 binary; do \
        mkdir -p "/opt/agents/$name" \
        && curl -fsSL "$url" -o /tmp/agent \
        && echo "$sha256  /tmp/agent" | sha256sum -c --quiet \
        && case $url in \
             *.tar.gz) tar -xzf /tmp/agent -C "/opt/agents/$name" --no-same-owner && rm /tmp/agent ;; \
             *) mv /tmp/agent "/opt/agents/$name/$binary" ;; \
           esac \
        && chmod 755 "/opt/agents/$name/$binary" \
        && ln -s "/opt/agents/$name/$binary" "/usr/local/bin/$name" \
        || exit 1; \
       done < /tmp/agents.list \
    && rm /tmp/agents.json /tmp/agents.list
