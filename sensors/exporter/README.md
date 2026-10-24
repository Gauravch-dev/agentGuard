# Trusted exporter boundary

Live export is not implemented. The process normalizer is `agentguard/sensors.py`; the application journal is `agentguard/store.py`.

Required next work: authenticated host-local collection or mTLS export, source registration, protected append-only raw evidence pointers, durable source offsets, replay protection, loss/export counters, explicit coverage windows, process/container lifecycle mapping, and fail-closed handling of attribution gaps. No HTTP endpoint accepts arbitrary caller-provided host events.
