# Future Goals & Operational Notes

This document captures important runtime deployment usage notes alongside ongoing organizational future structural goals guiding development optimizations.

## Important Usage Notes 

### SQL Data vs Storage State
File schemas mapping internal structure configurations act completely independently from SQL mappings. 
The core structural payload is held within the XML inside the `.bpmn` file mapping located within the `diagram_storage/` deployment path. 
- If the SQLite data resets or loses data mappings, operations CANNOT structurally be reconnected to isolated storage folders natively without a standalone metadata scanning python restructuring script.
- Always implement the logical cold deployment structure (such as the OS automated `.git` backup hook configured in `config.yaml`) if you expect heavy organizational interaction mapping limits over long lifecycles.

### Diagram Validations
We strictly mandate that process mapping titles respect alphanumeric regex checks structure. Character encoding parameters block inputs utilizing extreme spacing metrics, random specific characters, or logic injections natively mapping the filename structure over `.bpmn` payload endpoints universally across Editors.

## Future Goal Trajectory

While the application structure is purposefully scaled tight for basic server management, scaling requirements over future epochs include:

1. **Integrated Multi-Session Mapping**: While the polling Heartbeat logic successfully guarantees zero collision over independent data changes, transitioning the backend to native `WebSockets` could introduce real-time node dragging mechanics mapped simultaneously among multi-user instances.
2. **Deep Diff Overviews**: Executing Native XML Diffs tracking modifications tracking line alterations over the `.bpmn` payload, rendering explicit branch tracking mechanics directly within the Admin Process tables.
3. **Template Administration UI**: Allowing organizational operations users natively drag and drop foundational internal `.bpmn` configurations directly to the `bpmn_templates/` endpoint rather than mapping it independently onto the remote target server path.
4. **Enhanced Authorization Layering**: Granular permissions (such as assigning explicit Edit constraints preventing overlapping administrative users from altering independent active mapping payloads). Currently, all users map fully accessible interactions over the entirety of available datasets until a user asserts logical file locks.
