# Contributing to BPMN Architect

We actively seek and encourage internal contributions to optimize and streamline process automation and documentation management!

## Philosophy

The structural goal behind the underlying BPMN Architect codebase is to remain explicitly understandable by junior developers, avoiding complex WebSockets and obscure frameworks.
- The `FastAPI` system handles data structures and UI templating through pure `Jinja2`.
- We utilize `Vanilla JS` alongside `Bootstrap 5` to build standard and functional browser mechanics mapping tightly back to single endpoint triggers.
- Complexity and real-time collision detection are accomplished securely via polling and file-storage atomicity mechanics rather than real-time sockets.

## Setting Up Your Development Environment

Check out the explicit localized development variables within [Deployment & Scaling](DEPLOYMENT.md) to initialize your codebase and dependencies. 

## Contribution Guidelines

1. **Keep it Vanilla where possible**: Resist the urge to add frameworks like React or Vue. The frontend focuses heavily on `bpmn-js` mapping; we do not run a Node.js compilation pipeline.
2. **Prioritize Modularity**: If building a specialized helper module, ensure it routes properly alongside `components/models.py` or `components/auth.py`. We explicitly forbid convoluting `main.py` routing.
3. **Admin Actions and Scopes**: Always structure critical components or deletion mechanisms alongside the explicit `current_user in ADMINS` conditional loops or `@app.post("/api/.../{action}")` parameterizations preventing non-administrators from corrupting process layouts.

### Opening Pull Requests
- Format your Git commit message aligned to standard features (`feat:`, `fix:`, `refactor:`).
- Highlight specific UI/UX updates with screenshot visual logs. 
- Outline testing paths explicitly verifying locks, atomic file saves, or `.bpmn` payload updates.

*(Any security-oriented exploits related to IIS bypass should be flagged to the DevOps lead before explicitly opening Public PRs).*
