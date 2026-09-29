

export interface UserAccount {
  email: string;
  name: string;
  role: 'Admin' | 'Reviewer' | 'Analyst';
  password?: string;
  createdAt: string;
}

export interface IngestedNode {
  id: string;
  name: string;
  filename: string;
  vendor: string;
  platform: string;
  adapter: string;
  tier: number;
  facts_count: number;
  unknown_count: number;
  coverage_level: number;
  coverage_name: string;
  compliance_score: number;
  compliance_band: string;
  controls_evaluated?: number;
  controls_total?: number;
  ip_address?: string;
  serial?: string;
  hardware_model?: string;
  session_id?: string;
  duplicate?: boolean;
  evidence_id: string;
  hashes: { sha256: string; md5: string };
  raw_lines_count: number;
  raw_config: string;
  os_version?: string;
  device_metadata?: { hostname: string; model_hint: string };
  facts: Array<{ name: string; value: string | boolean | number; confidence: number; source_adapter: string }>;
  control_results: Array<{
    control_id: string;
    title: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    result: 'PASS' | 'FAIL' | 'UNKNOWN';
    detail: string;
    node: string;
  }>;
  unknown_fragments: Array<{
    proposal_id: string;
    raw_path: string;
    raw_text: string;
    category: string;
    suggested_fact?: string;
    suggestion_confidence?: number;
    suggested_by?: string;
  }>;
  decided_fragments: Array<{
    proposal_id: string;
    raw_text: string;
    status: 'APPROVED' | 'REJECTED';
    decided_fact?: string;
    approver: string;
  }>;
}

export interface VerificationItem {
  verification_id: string;
  node_id: string;
  control_id: string;
  control_title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  audit_result: 'PASS' | 'FAIL' | 'UNKNOWN';
  expected_behavior: 'ALLOWED' | 'DENIED' | 'PASS' | 'FAIL';
  batfish_result?: { result: 'PASS' | 'FAIL' | 'UNKNOWN'; detail: string };
  correlation: 'VERIFIED_PASS' | 'VERIFIED_FAIL' | 'CONTRADICTORY' | 'CONFIG_ONLY_PASS' | 'CONFIG_ONLY_FAIL' | 'INCONCLUSIVE';
  execution_status: string;
  created_at: string;
  review?: {
    classification: 'CONFIRMED_FALSE_POSITIVE' | 'AUDIT_RULE_VALID' | 'BATFISH_MODEL_LIMITATION' | 'INSUFFICIENT_CONTEXT' | 'OTHER';
    reason: string;
    reviewer: string;
    reviewed_at: string;
  };
}

export interface MappingPack {
  map_id: string;
  vendor: string;
  platform: string;
  version: string;
  status: 'ACTIVE' | 'PENDING_REVIEW' | 'REJECTED';
  active_rules: number;
  rules_count: number;
  created_by: string;
  created_at: string;
}

export interface AccessRequest {
  id: string;
  name: string;
  email: string;
  requestedRole: 'Admin' | 'Reviewer' | 'Analyst';
  justification: string;
  submittedAt: string;
  status: 'PENDING' | 'APPROVED' | 'REJECTED';
}

const DEFAULT_ACCESS_REQUESTS: AccessRequest[] = [
  {
    id: 'req-101',
    name: 'Sarah Connor',
    email: 'sconnor@defense.corp',
    requestedRole: 'Analyst',
    justification: 'Ingesting DC spine configs and auditing CIS benchmarks',
    submittedAt: '2026-09-24T06:15:00Z',
    status: 'PENDING',
  },
];

const DEFAULT_USERS: UserAccount[] = [
  {
    email: 'admin@inv4r.io',
    name: 'Michael Scott',
    role: 'Admin',
    password: 'admin',
    createdAt: '2026-09-01T08:00:00Z',
  },
  {
    email: 'analyst@inv4r.io',
    name: 'Jim Halpert',
    role: 'Analyst',
    password: 'admin',
    createdAt: '2026-09-05T10:30:00Z',
  },
  {
    email: 'reviewer@inv4r.io',
    name: 'Dwight Schrute',
    role: 'Reviewer',
    password: 'admin',
    createdAt: '2026-09-10T14:15:00Z',
  },
];

const DEFAULT_NODES: IngestedNode[] = [
  {
    id: 'node-cisco-core-01',
    name: 'cisco_core_sw01.cfg',
    filename: 'cisco_core_sw01.cfg',
    vendor: 'Cisco',
    platform: 'IOS-XE Catalyst 3850',
    adapter: 'cisco_iosxe_v2',
    tier: 1,
    facts_count: 48,
    unknown_count: 2,
    coverage_level: 4,
    coverage_name: 'Full Deterministic',
    compliance_score: 91.5,
    compliance_band: 'HIGH',
    evidence_id: 'ev-94a8c3d2e1b0',
    hashes: { sha256: '94a8c3d2e1b04587fa930129bc81734910294857102938475610293847561029', md5: '3c89b21a8f90' },
    raw_lines_count: 412,
    raw_config: `! Cisco IOS-XE Software, Catalyst L3 Switch
hostname cisco_core_sw01
!
service password-encryption
no service dhcp
service timestamps debug datetime msec
service timestamps log datetime msec
!
aaa new-model
aaa authentication login default group radius local
aaa authorization exec default group radius local
!
interface GigabitEthernet1/0/1
 description Trunk to DC Aggregation
 switchport mode trunk
 switchport nonegotiate
!
interface GigabitEthernet1/0/2
 description Mgmt Out-of-Band
 ip address 10.200.1.10 255.255.255.0
 no shutdown
!
ip access-list extended MGMT_ACL
 permit tcp 10.200.0.0 0.0.255.255 host 10.200.1.10 eq 22
 deny   ip any any log
!
line vty 0 4
 access-class MGMT_ACL in
 transport input ssh
 exec-timeout 5 0
!
snmp-server community ********** RO MGMT_ACL
snmp-server enable traps
end`,
    os_version: 'IOS-XE 16.12.5b',
    device_metadata: { hostname: 'cisco_core_sw01', model_hint: 'WS-C3850-48P' },
    facts: [
      { name: 'hostname', value: 'cisco_core_sw01', confidence: 1.0, source_adapter: 'cisco_iosxe_v2' },
      { name: 'service.password_encryption', value: true, confidence: 1.0, source_adapter: 'cisco_iosxe_v2' },
      { name: 'aaa.new_model', value: true, confidence: 1.0, source_adapter: 'cisco_iosxe_v2' },
      { name: 'ssh.version', value: 2, confidence: 0.98, source_adapter: 'cisco_iosxe_v2' },
      { name: 'vty.transport_input', value: 'ssh', confidence: 1.0, source_adapter: 'cisco_iosxe_v2' },
      { name: 'vty.exec_timeout_sec', value: 300, confidence: 1.0, source_adapter: 'cisco_iosxe_v2' },
      { name: 'vty.access_class', value: 'MGMT_ACL', confidence: 1.0, source_adapter: 'cisco_iosxe_v2' },
      { name: 'snmp.communities_restricted', value: true, confidence: 0.95, source_adapter: 'cisco_iosxe_v2' },
      { name: 'logging.timestamps_enabled', value: true, confidence: 1.0, source_adapter: 'cisco_iosxe_v2' },
    ],
    control_results: [
      { control_id: 'CIS-1.1', title: 'Verify SSH Version 2 is Enforced', severity: 'CRITICAL', result: 'PASS', detail: 'SSH v2 enforced globally on vty lines', node: 'cisco_core_sw01.cfg' },
      { control_id: 'CIS-1.2', title: 'Verify Insecure Protocols Disabled (Telnet/HTTP)', severity: 'HIGH', result: 'PASS', detail: 'Telnet and ip http server disabled', node: 'cisco_core_sw01.cfg' },
      { control_id: 'CIS-2.1', title: 'Ensure AAA New-Model is Enabled', severity: 'HIGH', result: 'PASS', detail: 'AAA authentication and authorization active', node: 'cisco_core_sw01.cfg' },
      { control_id: 'CIS-3.1', title: 'Verify VTY Inactive Session Timeout <= 300s', severity: 'MEDIUM', result: 'PASS', detail: 'exec-timeout set to 5 min (300 seconds)', node: 'cisco_core_sw01.cfg' },
      { control_id: 'CIS-4.1', title: 'Ensure Password Minimum Length >= 14', severity: 'HIGH', result: 'FAIL', detail: 'security passwords min-length directive missing', node: 'cisco_core_sw01.cfg' },
      { control_id: 'CIS-5.2', title: 'Ensure SNMPv3 with AuthPriv or Restricted v2c', severity: 'MEDIUM', result: 'PASS', detail: 'SNMP community restricted to MGMT_ACL', node: 'cisco_core_sw01.cfg' },
      { control_id: 'CIS-6.1', title: 'Verify Centralized Syslog Server Configured', severity: 'LOW', result: 'UNKNOWN', detail: 'logging host fact missing in parsed configuration', node: 'cisco_core_sw01.cfg' },
    ],
    unknown_fragments: [
      {
        proposal_id: 'prop-cisco-1',
        raw_path: 'line vty 0 4 -> transport preferred none',
        raw_text: 'transport preferred none',
        category: 'Session Management',
        suggested_fact: 'vty.transport_preferred',
        suggestion_confidence: 0.92,
        suggested_by: 'Learned NLP Pattern v2',
      },
      {
        proposal_id: 'prop-cisco-2',
        raw_path: 'crypto pki certificate chain SLA-TrustPoint',
        raw_text: 'certificate 01 042a9b... quit',
        category: 'PKI Certificate Store',
        suggested_fact: 'pki.trustpoint_chain',
        suggestion_confidence: 0.84,
        suggested_by: 'Learned NLP Pattern v2',
      },
    ],
    decided_fragments: [],
  },
  {
    id: 'node-juniper-srx-01',
    name: 'juniper_edge_srx.conf',
    filename: 'juniper_edge_srx.conf',
    vendor: 'Juniper',
    platform: 'Junos OS SRX300',
    adapter: 'juniper_junos_hierarchical',
    tier: 1,
    facts_count: 52,
    unknown_count: 1,
    coverage_level: 4,
    coverage_name: 'Full Deterministic',
    compliance_score: 94.2,
    compliance_band: 'HIGH',
    evidence_id: 'ev-11f8e4a9c2b3',
    hashes: { sha256: '11f8e4a9c2b34910294857102938475610293847561029485710293847561029', md5: '7f91c01b4e22' },
    raw_lines_count: 520,
    raw_config: `system {
    host-name juniper_edge_srx;
    root-authentication {
        encrypted-password "$6$rounds=656000$encryptedrootpass";
    }
    services {
        ssh {
            protocol-version v2;
            ciphers [ aes256-gcm@openssh.com aes128-gcm@openssh.com ];
        }
    }
    login {
        idle-timeout 5;
    }
}
security {
    zones {
        security-zone trust {
            interfaces {
                ge-0/0/0.0;
            }
        }
        security-zone untrust {
            interfaces {
                ge-0/0/1.0;
            }
        }
    }
}`,
    os_version: 'Junos 19.4R3-S1',
    device_metadata: { hostname: 'juniper_edge_srx', model_hint: 'SRX300' },
    facts: [
      { name: 'hostname', value: 'juniper_edge_srx', confidence: 1.0, source_adapter: 'juniper_junos_hierarchical' },
      { name: 'ssh.version', value: 2, confidence: 1.0, source_adapter: 'juniper_junos_hierarchical' },
      { name: 'login.idle_timeout_min', value: 5, confidence: 1.0, source_adapter: 'juniper_junos_hierarchical' },
    ],
    control_results: [
      { control_id: 'CIS-1.1', title: 'Verify SSH Version 2 is Enforced', severity: 'CRITICAL', result: 'PASS', detail: 'protocol-version v2 configured', node: 'juniper_edge_srx.conf' },
      { control_id: 'CIS-1.2', title: 'Verify Insecure Protocols Disabled (Telnet/HTTP)', severity: 'HIGH', result: 'PASS', detail: 'No telnet or web-management enabled', node: 'juniper_edge_srx.conf' },
      { control_id: 'CIS-4.1', title: 'Ensure Password Minimum Length >= 14', severity: 'HIGH', result: 'PASS', detail: 'SHA-512 with 656k rounds salt enforced', node: 'juniper_edge_srx.conf' },
    ],
    unknown_fragments: [
      {
        proposal_id: 'prop-juniper-1',
        raw_path: 'security -> idp -> sensor-configuration',
        raw_text: 'sensor-configuration packet-log threshold 100',
        category: 'Intrusion Detection & Prevention',
        suggested_fact: 'idp.packet_log_threshold',
        suggestion_confidence: 0.89,
        suggested_by: 'Learned NLP Pattern v2',
      },
    ],
    decided_fragments: [],
  },
  {
    id: 'node-paloalto-fw-01',
    name: 'paloalto_panos.xml',
    filename: 'paloalto_panos.xml',
    vendor: 'Palo Alto',
    platform: 'PAN-OS PA-3220',
    adapter: 'paloalto_panos_xml',
    tier: 1,
    facts_count: 64,
    unknown_count: 0,
    coverage_level: 5,
    coverage_name: 'Verified Golden',
    compliance_score: 96.8,
    compliance_band: 'HIGH',
    evidence_id: 'ev-55e9b8c7d6a1',
    hashes: { sha256: '55e9b8c7d6a14910294857102938475610293847561029485710293847561029', md5: '1a2b3c4d5e6f' },
    raw_lines_count: 890,
    raw_config: `<?xml version="1.0"?>
<config version="10.1.0" urldb="paloaltonetworks">
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig>
        <system>
          <hostname>pa_edge_fw01</hostname>
          <service>
            <disable-telnet>yes</disable-telnet>
            <disable-http>yes</disable-http>
          </service>
        </system>
      </deviceconfig>
    </entry>
  </devices>
</config>`,
    os_version: 'PAN-OS 10.1.4',
    device_metadata: { hostname: 'pa_edge_fw01', model_hint: 'PA-3220' },
    facts: [
      { name: 'hostname', value: 'pa_edge_fw01', confidence: 1.0, source_adapter: 'paloalto_panos_xml' },
      { name: 'service.telnet_disabled', value: true, confidence: 1.0, source_adapter: 'paloalto_panos_xml' },
      { name: 'service.http_disabled', value: true, confidence: 1.0, source_adapter: 'paloalto_panos_xml' },
    ],
    control_results: [
      { control_id: 'CIS-1.1', title: 'Verify SSH Version 2 is Enforced', severity: 'CRITICAL', result: 'PASS', detail: 'SSH enforced, TLS 1.3 for management', node: 'paloalto_panos.xml' },
      { control_id: 'CIS-1.2', title: 'Verify Insecure Protocols Disabled (Telnet/HTTP)', severity: 'HIGH', result: 'PASS', detail: 'disable-telnet yes, disable-http yes', node: 'paloalto_panos.xml' },
    ],
    unknown_fragments: [],
    decided_fragments: [],
  },
];

const DEFAULT_VERIFICATIONS: VerificationItem[] = [
  {
    verification_id: 'ver-run-001',
    node_id: 'cisco_core_sw01.cfg',
    control_id: 'CIS-1.1',
    control_title: 'Verify SSH Version 2 is Enforced',
    severity: 'CRITICAL',
    audit_result: 'PASS',
    expected_behavior: 'ALLOWED',
    batfish_result: { result: 'PASS', detail: 'Forwarding path permits TCP 22 only from 10.200.0.0/16 to management interface' },
    correlation: 'VERIFIED_PASS',
    execution_status: 'COMPLETED',
    created_at: '2026-09-24T12:30:15Z',
    review: {
      classification: 'AUDIT_RULE_VALID',
      reason: 'Both static config audit and Batfish path simulation confirm secure SSH restriction.',
      reviewer: 'Michael Scott',
      reviewed_at: '2026-09-24T12:35:00Z',
    },
  },
  {
    verification_id: 'ver-run-002',
    node_id: 'cisco_core_sw01.cfg',
    control_id: 'CIS-1.2',
    control_title: 'Verify Telnet Port 23 Drop at Edge Boundary',
    severity: 'HIGH',
    audit_result: 'FAIL',
    expected_behavior: 'DENIED',
    batfish_result: { result: 'PASS', detail: 'Batfish forwarding proves packets to TCP 23 are dropped by ACL MGMT_ACL' },
    correlation: 'CONTRADICTORY',
    execution_status: 'COMPLETED',
    created_at: '2026-09-24T12:30:18Z',
    review: undefined,
  },
  {
    verification_id: 'ver-run-003',
    node_id: 'juniper_edge_srx.conf',
    control_id: 'CIS-2.1',
    control_title: 'Verify Unrestricted Inbound Access Denied',
    severity: 'HIGH',
    audit_result: 'FAIL',
    expected_behavior: 'DENIED',
    batfish_result: { result: 'FAIL', detail: 'Path analysis reveals default-permit policy allows ingress probe on ge-0/0/1' },
    correlation: 'VERIFIED_FAIL',
    execution_status: 'COMPLETED',
    created_at: '2026-09-24T12:30:22Z',
    review: {
      classification: 'AUDIT_RULE_VALID',
      reason: 'Verified real security breach. Inbound traffic allowed through untrusted zone.',
      reviewer: 'Dwight Schrute',
      reviewed_at: '2026-09-24T12:38:00Z',
    },
  },
  {
    verification_id: 'ver-run-004',
    node_id: 'cisco_core_sw01.cfg',
    control_id: 'CIS-6.1',
    control_title: 'Verify Centralized Syslog Server Configured',
    severity: 'LOW',
    audit_result: 'UNKNOWN',
    expected_behavior: 'PASS',
    batfish_result: undefined,
    correlation: 'INCONCLUSIVE',
    execution_status: 'SKIPPED_INSUFFICIENT_CONTEXT',
    created_at: '2026-09-24T12:30:25Z',
  },
];

const DEFAULT_MAPPINGS: MappingPack[] = [
  {
    map_id: 'map-cisco-iosxe-v2.1',
    vendor: 'Cisco',
    platform: 'IOS-XE',
    version: '2.1.0',
    status: 'ACTIVE',
    active_rules: 142,
    rules_count: 142,
    created_by: 'Michael Scott',
    created_at: '2026-09-18T09:00:00Z',
  },
  {
    map_id: 'map-juniper-junos-v1.4',
    vendor: 'Juniper',
    platform: 'Junos OS',
    version: '1.4.2',
    status: 'ACTIVE',
    active_rules: 98,
    rules_count: 98,
    created_by: 'Michael Scott',
    created_at: '2026-09-19T11:20:00Z',
  },
  {
    map_id: 'map-vendorx-switchos-v0.9',
    vendor: 'VendorX',
    platform: 'SwitchOS 7',
    version: '0.9.1-preview',
    status: 'PENDING_REVIEW',
    active_rules: 24,
    rules_count: 28,
    created_by: 'Dwight Schrute',
    created_at: '2026-09-24T05:30:00Z',
  },
];

// Mirrors inv4r/core/facts.py CANONICAL_FACTS (schema 1.2.0) — the closed
// vocabulary the engine can emit and the training UI can offer.
export const CLOSED_VOCABULARY = [
  { fact: 'acl.binding', type: 'string', description: 'Where an ACL is applied (surface/direction/owner)' },
  { fact: 'acl.default_action', type: 'string', description: 'DEPRECATED global alias — see acl.terminal_action' },
  { fact: 'acl.present', type: 'boolean', description: 'At least one ACL/firewall rule set defined' },
  { fact: 'acl.rule_count', type: 'integer', description: 'Number of rules in a specific ACL' },
  { fact: 'acl.terminal_action', type: 'string', description: 'Per-ACL terminal behavior (explicit_deny | explicit_permit | implicit_deny)' },
  { fact: 'authentication.aaa.enabled', type: 'boolean', description: 'AAA (authentication/authorization/accounting) enabled' },
  { fact: 'authentication.password.hashing', type: 'string', description: 'DEPRECATED global alias — see credential.* facts' },
  { fact: 'credential.algorithm_class', type: 'string', description: 'Credential algorithm class (scrypt, md5, reversible, plaintext, unknown)' },
  { fact: 'credential.plaintext.present', type: 'boolean', description: 'At least one plaintext credential exists' },
  { fact: 'credential.reversible.present', type: 'boolean', description: 'At least one reversible-encoded credential exists' },
  { fact: 'credential.storage_type', type: 'string', description: 'Per-credential storage/encoding mechanism' },
  { fact: 'credential.type9.present', type: 'boolean', description: 'At least one type-9 (scrypt) credential exists' },
  { fact: 'firewall.policy.present', type: 'boolean', description: 'Firewall/security policy set present' },
  { fact: 'logging.local.enabled', type: 'boolean', description: 'Local logging (buffered/file) enabled' },
  { fact: 'logging.remote.enabled', type: 'boolean', description: 'Remote syslog configured' },
  { fact: 'logging.remote.servers', type: 'string', description: 'Remote syslog server address (one fact per configured server)' },
  { fact: 'management.acl.applied', type: 'boolean', description: 'An ACL is attached to a management surface' },
  { fact: 'management.acl.binding', type: 'string', description: 'Management ACL binding (acl/direction)' },
  { fact: 'management.acl.present', type: 'boolean', description: 'ACL restricting management plane access' },
  { fact: 'management.acl.terminal_action', type: 'string', description: 'Terminal behavior of the management-bound ACL' },
  { fact: 'management.console.authentication', type: 'string', description: 'Console line authentication method' },
  { fact: 'management.ftp.enabled', type: 'boolean', description: 'FTP management service enabled (insecure)' },
  { fact: 'management.http.acl', type: 'string', description: 'ACL applied to the HTTP management server' },
  { fact: 'management.http.authentication', type: 'string', description: 'HTTP management authentication method' },
  { fact: 'management.http.enabled', type: 'boolean', description: 'Plain-HTTP management enabled (insecure)' },
  { fact: 'management.https.acl', type: 'string', description: 'ACL applied to the HTTPS management server' },
  { fact: 'management.https.authentication', type: 'string', description: 'HTTPS management authentication method' },
  { fact: 'management.https.enabled', type: 'boolean', description: 'HTTPS management enabled' },
  { fact: 'management.session_timeout', type: 'integer', description: 'Management session idle timeout (minutes)' },
  { fact: 'management.ssh.acl.present', type: 'boolean', description: 'ACL restricting SSH management access' },
  { fact: 'management.ssh.enabled', type: 'boolean', description: 'SSH management service enabled' },
  { fact: 'management.ssh.timeout', type: 'integer', description: 'SSH idle timeout (minutes)' },
  { fact: 'management.ssh.version', type: 'string', description: "SSH protocol version (e.g. '2')" },
  { fact: 'management.telnet.enabled', type: 'boolean', description: 'Telnet management service enabled (insecure)' },
  { fact: 'management.vty.acl', type: 'string', description: 'ACL applied to VTY lines (ipv4)' },
  { fact: 'management.vty.acl.ipv6', type: 'string', description: 'ACL applied to VTY lines (ipv6)' },
  { fact: 'management.vty.authentication', type: 'string', description: 'VTY authentication method' },
  { fact: 'management.vty.transport', type: 'string', description: 'Permitted VTY transport protocols' },
  { fact: 'network.interface.present', type: 'boolean', description: 'At least one interface configured (derived compat fact)' },
  { fact: 'network.route.present', type: 'boolean', description: 'At least one route (static or learned) configured' },
  { fact: 'ntp.servers', type: 'string', description: 'NTP server address (one fact per configured server)' },
  { fact: 'snmp.communities_restricted', type: 'boolean', description: 'SNMP community bounded by a source ACL (one fact per community)' },
  { fact: 'snmp.community.acl', type: 'string', description: 'ACL restricting an SNMP community' },
  { fact: 'snmp.v1.v2c.enabled', type: 'boolean', description: 'SNMP v1/v2c communities in use (insecure)' },
  { fact: 'snmp.v3.enabled', type: 'boolean', description: 'SNMPv3 enabled' },
  { fact: 'snmp.version', type: 'string', description: 'SNMP version in use for a configured SNMP principal (one fact per principal)' },
  { fact: 'vendor_extension', type: 'string', description: 'Unmapped vendor-specific feature (status UNKNOWN)' },
];

export const FRAMEWORKS_DATA = [
  {
    profile_id: 'cis-network-baseline',
    title: 'CIS Network Device Benchmark',
    version: '1.1.0',
    description: 'Center for Internet Security hardening guidelines for enterprise firewalls, switches, and routers.',
    control_count: 68,
  },
  {
    profile_id: 'nist-sp-800-53-r5',
    title: 'NIST SP 800-53 Rev 5',
    version: '5.0',
    description: 'Security and Privacy Controls for Federal Information Systems and Organizations.',
    control_count: 112,
  },
  {
    profile_id: 'disa-network-stig',
    title: 'DoD DISA Network Infrastructure STIG',
    version: 'v10r2',
    description: 'United States Department of Defense Security Technical Implementation Guide for Network Assets.',
    control_count: 84,
  },
  {
    profile_id: 'iso-iec-27001-2022',
    title: 'ISO/IEC 27001:2022 Annex A',
    version: '2022',
    description: 'International standard for managing information security, Clause 8.20 Network Security.',
    control_count: 54,
  },
];

export function getSavedUsers(): UserAccount[] {
  try {
    const s = localStorage.getItem('inv4r.users');
    if (s) return JSON.parse(s);
  } catch {}
  localStorage.setItem('inv4r.users', JSON.stringify(DEFAULT_USERS));
  return DEFAULT_USERS;
}

export function saveUsers(users: UserAccount[]) {
  localStorage.setItem('inv4r.users', JSON.stringify(users));
}

// A fresh install (or a reset environment) starts with ZERO nodes. The backend
// owns the node inventory; nothing is seeded into the browser anymore.
export function getSavedNodes(): IngestedNode[] {
  try {
    const s = localStorage.getItem('inv4r.nodes');
    if (s) return JSON.parse(s);
  } catch {}
  return [];
}

export function saveNodes(nodes: IngestedNode[]) {
  localStorage.setItem('inv4r.nodes', JSON.stringify(nodes));
}

export function getSavedVerifications(): VerificationItem[] {
  try {
    const s = localStorage.getItem('inv4r.verifications');
    if (s) return JSON.parse(s);
  } catch {}
  return [];
}

export function saveVerifications(v: VerificationItem[]) {
  localStorage.setItem('inv4r.verifications', JSON.stringify(v));
}

export function getSavedMappings(): MappingPack[] {
  try {
    const s = localStorage.getItem('inv4r.mappings');
    if (s) return JSON.parse(s);
  } catch {}
  localStorage.setItem('inv4r.mappings', JSON.stringify(DEFAULT_MAPPINGS));
  return DEFAULT_MAPPINGS;
}

export function saveMappings(m: MappingPack[]) {
  localStorage.setItem('inv4r.mappings', JSON.stringify(m));
}

export function getSavedAiSettings() {
  try {
    const s = localStorage.getItem('inv4r.ai_settings');
    if (s) return JSON.parse(s);
  } catch {}
  const def = { mode: 'learned', air_gapped: true };
  localStorage.setItem('inv4r.ai_settings', JSON.stringify(def));
  return def;
}

export function saveAiSettings(settings: { mode: string; air_gapped: boolean }) {
  localStorage.setItem('inv4r.ai_settings', JSON.stringify(settings));
}

export function getSavedAccessRequests(): AccessRequest[] {
  try {
    const s = localStorage.getItem('inv4r.accessRequests');
    if (s) return JSON.parse(s);
  } catch {}
  localStorage.setItem('inv4r.accessRequests', JSON.stringify(DEFAULT_ACCESS_REQUESTS));
  return DEFAULT_ACCESS_REQUESTS;
}

export function saveAccessRequests(reqs: AccessRequest[]) {
  localStorage.setItem('inv4r.accessRequests', JSON.stringify(reqs));
}
