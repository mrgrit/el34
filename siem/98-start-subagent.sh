#!/usr/bin/with-contenv bash
# SubAgent (A2A worker on :8002) — agent 자율 lab 수행을 위한 워커.
if [ -f /opt/subagent.py ]; then
    echo '[cont-init.d/98] starting SubAgent on :8002'
    CCC_ROLE=siem nohup python3 /opt/subagent.py > /var/log/subagent.log 2>&1 < /dev/null &
    echo "[cont-init.d/98] subagent pid=$!"
fi
exit 0
