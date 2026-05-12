"""Application configuration loaded from environment variables.

Values are read from the process environment, falling back to a local .env file
during development. Production deployments should set the variables directly via
systemd EnvironmentFile or equivalent.
"""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Backend authentication.
    # Phase 1 does not enforce this header; Phase 2 wires it into the auth dependency.
    sitescanner_api_key: str = Field(default="")

    # ProjectDiscovery Cloud API key. If set, the scanner adds the `-dashboard`
    # flag and Nuclei uploads results to cloud.projectdiscovery.io.
    pdcp_api_key: str = Field(default="")

    # Redis (queue + job state).
    redis_url: str = Field(default="redis://localhost:6379/0")

    # Email delivery.
    email_provider: str = Field(default="stub")
    email_from: str = Field(default="reports@securestep.example")

    # Scan controls.
    scan_timeout_seconds: int = Field(default=900)
    max_concurrent_scans: int = Field(default=3)

    # Server.
    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8000)
    log_level: str = Field(default="info")


settings = Settings()
