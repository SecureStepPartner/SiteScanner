# SiteScanner Bruno checks

This public collection contains only safe, read-only development checks. It intentionally excludes scan creation, scan-result retrieval, email addresses, API keys, targets, job IDs, findings, and production endpoints.

Create an ignored `environments/Local.yml` in Bruno and set `sitescanner_base_url` to a local or explicitly approved test deployment. Never point this collection at a client environment or initiate testing without authorization.
