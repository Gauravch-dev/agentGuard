# A trusted administrator supplies an approved digest; no floating base default.
ARG PYTHON_BASE
FROM ${PYTHON_BASE}
COPY platform/profiles/isolation_probe.py /opt/agentguard/isolation_probe.py
RUN python -c "import os; os.mkdir('/opt/agentguard-rootfs-canary', 0o777); os.chmod('/opt/agentguard-rootfs-canary', 0o777)"
USER 65532:65532
WORKDIR /work
ENTRYPOINT ["python", "-I", "/opt/agentguard/isolation_probe.py"]
