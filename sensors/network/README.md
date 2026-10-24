# Network observation boundary

No packet capture or flow collector is implemented or running. The isolation lab uses `--network none`, which should prevent direct outbound packets; lack of a flow after denial is not a missing synthetic event to fill in.

Future approved broker egress needs trusted broker receipts correlated with actual observed host flows. Destination, timing and byte counts can support correlation; encrypted flow metadata does not prove plaintext content. No existing third-party anomaly repository has been imported or cleared for reuse.
