#!/usr/bin/with-contenv bash
# bastion 의 pubkey 을 ccc 의 authorized_keys 로 배포. sshd 시작 (99) 보다 앞서서 실행.
# 학생 환경마다 다른 키 (호스트 ./keys/id_rsa.pub bind mount, gitignore).
SSH_USER="${SSH_USER:-ccc}"
if [ -f /keys/id_rsa.pub ]; then
    mkdir -p /home/$SSH_USER/.ssh
    cat /keys/id_rsa.pub > /home/$SSH_USER/.ssh/authorized_keys
    chown -R $SSH_USER:$SSH_USER /home/$SSH_USER/.ssh
    chmod 700 /home/$SSH_USER/.ssh
    chmod 600 /home/$SSH_USER/.ssh/authorized_keys
    echo "[cont-init.d/97] siem authorized_keys deployed — bastion ssh ProxyJump 통과 가능"
else
    echo "[cont-init.d/97] WARN: /keys/id_rsa.pub 없음 — password ssh 로 fallback"
fi
exit 0
