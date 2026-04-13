# Platform Features

BPMN Architect acts as a modern mapping standard optimized for intra-organizational Process Mapping, bridging the gap between developers configuring automated environments and departmental mapping logic.

## 1. Zero-Collision Mutual Exclusion
Instead of a complex, load-balanced WebSocket scaling schema, we implement a polling lock **Railway Token System**.
- Whenever a user opens a process map into Editor Mode (`/app/{id}/edit`), the server grants an interactive lock targeting the SQL state.
- Editor UI fires a heartbeat token to `/api/diagram/{id}/heartbeat` tracking UI updates natively.
- Disconnections, idle timeouts, or explicit logouts instantly invalidate the logical heartbeat, enabling remote users to grab locks to map workflows independently without modifying logic over top of another user.

## 2. Advanced Native Editor Interface
- A built-in top-level `<menubar>` component handling programmatic features universally.
- Download mechanics to export your map specifically as a standard `.bpmn` payload, or visually as an SVG with intelligent, sanitized naming logic handling backend interactions securely.
- Visual auto-fitting and responsive layout scaling preventing element clipping when switching between internal Editor formats and Intranet HTML embeds.

## 3. Administrator Lifecycle Management
We explicitly process lifecycle logic without "hard deletes", preventing accidental process corruptions. 
- The centralized `/admin/` Library portal handles real-time fetching logic mapping organizational flow mapping states.
- Administrators possess "Force Unlock" capability natively built into tabular interactions, kicking idle user's active heartbeat locks.
- "Delete" acts as a soft-logical `is_deleted = True` flag. Flow maps remain available exclusively to administrators who can selectively analyze or execute "Restore Diagram" commands mapping them back to functional spaces.

## 4. Seamless Intranet Embedding
- Standard mappings export perfectly directly into other portals via `<iframe>`.
- Embedding operates fully authenticated OR seamlessly unauthenticated leveraging the `/embed/{id}/` routing parameter targeting isolated logic.
- Built-in navigation toolkits float over embed layouts explicitly granting viewers fullscreen viewport access and raw mapping payloads (`.bpmn` files) directly from the embedded portal.

## 5. Cold Storage Data Atomicity
Data operations utilize standard internal atomic components.
- During mapping payload writes, the OS strictly leverages an atomic `<hash>.tmp` overwrite renaming phase preventing file-corruption caused by race limits or spontaneous network drops.
- A decoupled, native Python Git-tracker logic loops explicitly utilizing `get_cold_backup.py`, converting mapped state configurations securely as part of your organizational `.git` structure, bypassing strict IIS API routing architectures entirely.
