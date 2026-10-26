# Dashboard usability update — 26 October 2026

The workspace now leads with the task's current status and next action. Technical
identifiers, raw JSON and source diagnostics are available through expandable
details rather than filling the main view.

## Try it

1. Open the local dashboard and choose **Connect workspace** after pasting the
   existing local owner token.
2. Choose **New task**, then **Review permissions** and **Create task**.
3. On **Overview**, choose **Start safety check**. This prepares the restricted
   environment; it does not itself admit the AI. Setup normally takes about a minute.
4. If setup succeeds, **Check readiness** performs the existing live admission
   review. Missing monitoring still holds execution.
5. Use **Stop & clean up** to end a staged run, or **Verify cleanup** when cleanup
   still needs verification. **Try a new run** creates a fresh approved revision.

The progress tracker distinguishes permission approval, environment registration,
AI execution and released reports. Expired task permissions prompt creation of a
fresh task. Historical revisions retain read-only execution controls.

## Views

- **Overview:** plain-English status, next action, permissions and recent activity.
- **Activity:** readable timeline, original evidence, filters, paging and review notes.
- **Security checks:** actual monitoring state, unknown loss counts, readiness
  reasons and findings grouped by classification/reason with all supporting records.
- **Report:** genuine released report data, or an explanation of why none is available.
- **How it works:** a short walkthrough and the current development limitations.
- **System details:** the existing platform preflight data.

Search and status filters help locate tasks; stable short task references replace
list numbers that changed when tasks were reordered. Desktop and phone layouts
use the same real API data. The owner token remains masked and in tab memory.
No backend authorization, sensor/admission gate, transport envelope or dependency
was changed. The full protected Finance run remains blocked by the monitoring
gaps tracked in the Linux delivery return.

## Verification

TypeScript/Vite production build and recorder syntax check passed. Browser checks
against the real application verified the new task wizard, persisted review note,
report empty state, monitoring/unknown-loss display, task search, tab navigation,
and historical revisions without launch/retry controls. The new task remained
unadmitted. Layout checks at 390px and 1440px found no page-level horizontal overflow.
The demo recorder's selectors and tab navigation were updated for this UI; a new
full recording was not produced during this UI round.
