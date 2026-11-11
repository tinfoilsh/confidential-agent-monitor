FROM docker.io/library/ubuntu:24.04@sha256:224a1869083a311ef3f13648a154ba79832fbef6364d31493642ca03082da254
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git openssh-server openssh-client python3 sudo \
    iproute2 util-linux procps tar xz-utils \
    && rm -rf /var/lib/apt/lists/* \
    && if id ubuntu >/dev/null 2>&1; then userdel -r ubuntu; fi
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
       'AllowAgentForwarding no' 'AllowTcpForwarding remote' 'PermitListen 127.0.0.1:2223' \
       'X11Forwarding no' 'PermitUserEnvironment no' 'PrintMotd no' \
       > /etc/ssh/sshd_config.monitor
