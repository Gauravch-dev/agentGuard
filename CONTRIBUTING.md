# Contribution workflow

Use neutral, task-focused branch names, commit messages, pull requests and handoffs.
Do not add coding-tool/model branding, automated authorship signatures or attribution
trailers. Use the developer identity already configured for the repository. Keep
necessary technical dependency/provider identifiers accurate.

Do not publish local usernames, absolute workspace paths, credentials or runtime
state in reports. Keep evidence timestamps, results and limitations truthful; use
repository-relative paths when sanitizing diagnostic artifacts.

Pull current `main` before each round, run relevant tests and checks, commit focused
changes, and push without force. Coordinate shared schema changes through versioned
decisions and compatibility tests. Never relax readiness, coverage or authorization
gates merely to obtain a successful demo.

Member 2 owns Linux/container/sensor/socket/GPU setup and live platform evidence.
Member 1 owns application behavior and the application-side integration review.
The next round is defined in [Member 2 next steps](docs/MEMBER_2_NEXT_STEPS.md).
