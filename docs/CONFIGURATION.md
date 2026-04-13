# Application Configuration

All deployment configurations run out of `config.yaml` utilizing a strict, highly nested block structure to keep deployment readable and logically structured.

## Nested Configuration Maps

### `app`
- **logo**: URL or Path referencing the display logo icon in the topmost Navigations.
- **subtitle**: The subtitle/slogan of the tool presented under the main header.
- **contact_email**: Displayed in the Admin `File > About` menus for routing internal requests.
- **templates_path**: Directory path handling initial `.bpmn` bootstraps when clicking "New Process" (`_default.bpmn` should be present).

### `storage`
- **diagram_path**: Defines the persistent physical storage directory for xml `.bpmn` payload files.
- **sql_instance_type**: Configures SQL context handling (SQLite, MySQL, MSSQL).
- **db_connection_string**: The localized SQLAlchemy `DATABASE_URL` link. (e.g., `sqlite:///./diagrams.db`).

### `auth`
- **method**: Authentication resolution handler. Setting to `iis-header` expects AD payload injection. Backed by local override functionality using `username,password` format explicitly for local dev debugging.
- **credentials**: Global admin login password override required when not configured to IIS parameters.
- **admins**: An explicit Yaml list of usernames possessing rights over the `/admin/` portal, forced Unlocks, and restoring logically deleted Process Maps.

### `sessions`
- **heartbeat_frequency_sec**: Lock-polling rate dictating how often a live-locked Web Client sends `POST /api/diagram/{id}/heartbeat` signaling interaction.
- **idle_timeout_min**: Minutes spanning before an unresponsive process file implicitly releases server locks to allow remote user modifications.

### `git`
- **backup_enabled**: Toggling automated deployment scripts checking all modified records inside SQL instances mapping to `diagram_storage/`.
- **commit_format**: The standardized auto-commit label appended alongside tracking messages.
- **commit_syntax**: Remote CLI syntax targeting exact organizational git tracking.
