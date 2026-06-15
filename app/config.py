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

    # API authentication. Production deployments should set this and configure
    # ChatGPT Actions to send it as either `Authorization: Bearer ...` or
    # `X-API-Key`.
    sitescanner_api_key: str = Field(default="")
    require_api_key: bool = Field(default=False)
    trusted_hosts: str = Field(default="*")

    # ProjectDiscovery Cloud API key. If set, the scanner adds the `-dashboard`
    # flag and Nuclei uploads results to cloud.projectdiscovery.io.
    pdcp_api_key: str = Field(default="")
    pdcp_team_id: str = Field(default="")
    pdcp_enable_cloud_upload: bool = Field(default=True)
    pdcp_disable_cloud_upload_warnings: bool = Field(default=True)

    # Redis (queue + job state).
    redis_url: str = Field(default="redis://localhost:6379/0")

    # Email delivery.
    email_provider: str = Field(default="resend")
    resend_api_key: str = Field(default="")
    email_from: str = Field(default="reports@securestep.example")

    # AI report generation.
    openai_api_key: str = Field(default="")
    openai_model: str = Field(default="gpt-5.5")
    schedule_meeting_url: str = Field(default="")

    # Scan controls. 15 mins timeout
    scan_timeout_seconds: int = Field(default=900, ge=1, le=900)
    max_concurrent_scans: int = Field(default=3, ge=1)
    rate_limit_per_minute: int = Field(default=5, ge=1)
    rate_limit_per_hour: int = Field(default=30, ge=1)
    max_pending_scans: int = Field(default=25, ge=1)

    # Server.
    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8000)
    log_level: str = Field(default="info")
    public_base_url: str = Field(
        default="",
        description="Public HTTPS base URL used in the OpenAPI servers list.",
    )


settings = Settings()
