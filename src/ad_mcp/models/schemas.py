"""
Entity schemas and parameter definitions for Active Directory objects.
"""

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class GroupScope(str, Enum):
    GLOBAL = "Global"
    UNIVERSAL = "Universal"
    DOMAIN_LOCAL = "DomainLocal"


class GroupCategory(str, Enum):
    SECURITY = "Security"
    DISTRIBUTION = "Distribution"


class DnsRecordType(str, Enum):
    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    PTR = "PTR"
    MX = "MX"
    TXT = "TXT"
    SRV = "SRV"
    NS = "NS"


class ReportFormat(str, Enum):
    JSON = "json"
    CSV = "csv"
    HTML = "html"


class ADUserSummary(BaseModel):
    sam_account_name: str
    user_principal_name: Optional[str] = None
    distinguished_name: str
    display_name: Optional[str] = None
    enabled: bool = True
    mail: Optional[str] = None
    title: Optional[str] = None
    department: Optional[str] = None
    when_created: Optional[str] = None
    last_logon_timestamp: Optional[str] = None
    password_never_expires: bool = False
    locked_out: bool = False


class ADGroupSummary(BaseModel):
    sam_account_name: str
    distinguished_name: str
    group_scope: str = "Global"
    group_category: str = "Security"
    description: Optional[str] = None
    member_count: int = 0


class ADComputerSummary(BaseModel):
    name: str
    dns_host_name: Optional[str] = None
    distinguished_name: str
    operating_system: Optional[str] = None
    operating_system_version: Optional[str] = None
    enabled: bool = True
    last_logon_timestamp: Optional[str] = None


class ADOUSummary(BaseModel):
    name: str
    distinguished_name: str
    description: Optional[str] = None
    protected_from_accidental_deletion: bool = True


class ADGPOSummary(BaseModel):
    id: str
    display_name: str
    gpo_status: str
    creation_time: Optional[str] = None
    modification_time: Optional[str] = None
    links: List[str] = Field(default_factory=list)


class ADDNSRecordSummary(BaseModel):
    zone_name: str
    host_name: str
    record_type: str
    record_data: str
    ttl: Optional[int] = None


class FsmoRoles(BaseModel):
    schema_master: Optional[str] = None
    domain_naming_master: Optional[str] = None
    pdc_emulator: Optional[str] = None
    rid_master: Optional[str] = None
    infrastructure_master: Optional[str] = None


class ComplianceCheckResult(BaseModel):
    rule_id: str
    title: str
    category: str
    severity: str  # Critical, High, Medium, Low, Info
    status: str  # PASS, FAIL, WARNING, NOT_APPLICABLE
    details: str
    remediation: Optional[str] = None
