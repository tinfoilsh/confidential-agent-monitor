FROM ubuntu:24.04
ARG CLAUDE_VERSION=stable
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git openssh-server openssh-client python3 sudo \
    iproute2 util-linux e2fsprogs procps tar xz-utils \
    && rm -rf /var/lib/apt/lists/* \
    && if id ubuntu >/dev/null 2>&1; then userdel -r ubuntu; fi
RUN useradd -m -u 1000 -s /bin/bash agent \
    && passwd -d agent \
    && printf 'agent ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/agent \
    && chmod 440 /etc/sudoers.d/agent
COPY claude-local /tmp/claude-local
RUN if [ -s /tmp/claude-local ]; then \
      install -m 755 /tmp/claude-local /usr/local/bin/claude; \
    else \
      curl -fsSL https://claude.ai/install.sh -o /tmp/install-claude \
      && su - agent -c "bash /tmp/install-claude '${CLAUDE_VERSION}'" \
      && ln -s /home/agent/.local/bin/claude /usr/local/bin/claude \
      && rm /tmp/install-claude; \
    fi \
    && rm /tmp/claude-local \
    && su - agent -c 'claude --version'
COPY init.sh /sbin/monitor-init
COPY guest.py /usr/local/lib/monitor/guest.py
RUN chmod 755 /sbin/monitor-init \
    && rm -f /etc/ssh/ssh_host_* \
    && printf '%s\n' \
       'ListenAddress 127.0.0.1' 'Port 22' 'HostKey /run/sshd/host_key' \
       'PidFile /run/sshd/sshd.pid' 'PasswordAuthentication no' \
       'KbdInteractiveAuthentication no' 'PermitEmptyPasswords no' \
       'PermitRootLogin no' 'UsePAM no' 'AllowUsers agent' \
       'AllowAgentForwarding no' 'AllowTcpForwarding no' 'X11Forwarding no' \
       'PermitUserEnvironment no' 'PrintMotd no' \
       > /etc/ssh/sshd_config.monitor
