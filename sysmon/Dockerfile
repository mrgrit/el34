FROM jrei/systemd-ubuntu:22.04

# sysmon-for-linux + Microsoft apt repo (한 번만 build 시 설치 — startup 빠름)
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl gnupg ca-certificates openssh-server sudo && \
    rm -rf /var/lib/apt/lists/* && \
    curl -sSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /usr/share/keyrings/microsoft-prod.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/microsoft-prod.gpg arch=amd64] https://packages.microsoft.com/ubuntu/22.04/prod jammy main" > /etc/apt/sources.list.d/microsoft-prod.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends sysmonforlinux && \
    rm -rf /var/lib/apt/lists/*

# ccc 사용자 (sshd 진입 + bastion ProxyJump)
RUN useradd -m -s /bin/bash -G sudo ccc && \
    echo 'ccc:ccc' | chpasswd && \
    echo 'ccc ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/ccc && \
    chmod 0440 /etc/sudoers.d/ccc && \
    mkdir -p /run/sshd && \
    sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/^PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    # jrei/systemd-ubuntu 의 PAM 이 신규 user 거부 → ssh 의 UsePAM no 로 우회
    sed -i 's/^UsePAM .*/UsePAM no/; s/^#UsePAM .*/UsePAM no/' /etc/ssh/sshd_config

# sysmon 의 default config (학생이 W11 에서 직접 수정)
RUN mkdir -p /opt/sysmon
COPY sysmon/config.xml /opt/sysmon/config.xml

# Custom entrypoint — sysmon -i config.xml + ssh key 배포 + sshd 시작 (systemd 안에서)
COPY sysmon/init-sysmon.sh /etc/cont-init.d/00-sysmon.sh
RUN chmod +x /etc/cont-init.d/00-sysmon.sh

# jrei/systemd-ubuntu 의 systemd init 이 cont-init.d 를 자동 실행하지 않음 → systemd unit 으로 등록
COPY sysmon/init-sysmon.service /etc/systemd/system/init-sysmon.service
RUN systemctl enable init-sysmon.service

EXPOSE 22
