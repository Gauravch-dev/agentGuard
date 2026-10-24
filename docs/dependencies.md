# Dependency and supply-chain status

Runtime Python dependency set: **empty**. This first workbench uses Python's standard library (including SQLite). Python itself and its bundled SQLite must be maintained by the host owner. The development host reports Python 3.14.2. A clean third-party package vulnerability scan is not claimed because no package scanner was installed/run.

The optional packaging build backend is pinned to setuptools 80.9.0 in `pyproject.toml`; it is not required for source checkout execution. It has not been installed, audited or used to build a distribution here. The UI is plain local HTML/CSS/JavaScript with no remote fonts, CDN, npm dependencies or analytics. Node is used only for a syntax check.

The Docker capsule base has no default version/digest: an administrator must supply an approved immutable image digest. This avoids fabricating a digest or silently using `latest`. No image was pulled or scanned. Tetragon and any future model runtime require separate pinned versions/digests, license/SBOM review and real host validation.

No source from the previously mentioned third-party network analytics repository has been copied or run. No real API key or production dataset is needed. Local authority/UI keys are generated at runtime under ignored `.agentguard/` and are not source assets.

An explicit source pattern scan for common OpenAI/GitHub/AWS credential formats and private key headers found no matches outside ignored runtime state. This is a narrow check, not a complete secret audit. Distribution packaging, full SBOM/license review, dependency vulnerability scans, an external secret scanner and a CI release pipeline remain open gates before deployment.
