from __future__ import annotations
import hashlib, os, re, tarfile, tempfile
from pathlib import Path
from .models import Finding

SENSITIVE=re.compile(r'(?i)(password|passwd|secret|community|token|pwd|(?:auth|priv)?key|hash)(\s*[:= ]\s*)(\S+)')
def redact(s:str)->str:
    s=SENSITIVE.sub(lambda m:m.group(1)+m.group(2)+'[REDACTED]',s)
    s=re.sub(r'(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)', '[IP_REDACTED]', s)
    return s[:1800]

def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if not value:
        return default
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValueError(f'{name} must be an integer') from exc
    if parsed <= 0:
        raise ValueError(f'{name} must be greater than zero')
    return parsed


def safe_extract(tar: tarfile.TarFile, dest: Path, max_files: int | None = None,
                 max_bytes: int | None = None):
    # Check Point support/backup archives can legitimately expand to several GB.
    # Limits remain configurable so deployments can match available disk capacity.
    max_files = max_files or _env_int('CHECKPOINT_AUDIT_MAX_FILES', 200_000)
    max_bytes = max_bytes or _env_int('CHECKPOINT_AUDIT_MAX_EXPANDED_BYTES', 10 * 1024**3)

    members = tar.getmembers()
    file_members = [m for m in members if m.isfile()]
    if len(file_members) > max_files:
        raise ValueError(
            f'Archive contains {len(file_members):,} files; safety limit is {max_files:,}. '
            'Increase CHECKPOINT_AUDIT_MAX_FILES only for a trusted archive.'
        )

    total = sum(max(0, m.size) for m in file_members)
    if total > max_bytes:
        actual_gib = total / 1024**3
        limit_gib = max_bytes / 1024**3
        raise ValueError(
            f'Expanded archive is {actual_gib:.2f} GiB; safety limit is {limit_gib:.2f} GiB. '
            'For a trusted Check Point archive, increase '
            'CHECKPOINT_AUDIT_MAX_EXPANDED_BYTES.'
        )

    base = dest.resolve()
    for m in members:
        target = (dest / m.name).resolve()
        if base not in target.parents and target != base:
            raise ValueError(f'Unsafe archive path detected: {m.name}')
        # Links are skipped to prevent extraction outside the temporary directory.
        if m.issym() or m.islnk():
            continue
        tar.extract(m, dest, filter='data')

def read_text(path:Path,limit=5_000_000):
    try: return path.read_bytes()[:limit].decode('utf-8','replace')
    except Exception: return ''

def parse_initial(text:str):
    facts={}
    for line in text.splitlines():
        if not line or line.startswith('#') or ' ' not in line: continue
        k,v=line.split(' ',1); facts[k.strip()]=v.strip()
    return facts

def find_file(root:Path, suffix:str):
    for p in root.rglob('*'):
        if p.is_file() and str(p).replace('\\','/').endswith(suffix): return p
    return None

def ev(facts,key,source):
    v=facts.get(key)
    return (v, redact(f'{key} {v}') if v is not None else '', source)

def finding(fid,title,cat,status,severity,conf,expected,observed,impact,remediation,evidence,source):
    return Finding(fid,title,cat,status,severity,conf,expected,observed,impact,remediation,evidence,source)

def scan_archive(archive_path:str):
    ap=Path(archive_path); sha=hashlib.sha256(ap.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix='cp_audit_') as td:
        root=Path(td)
        with tarfile.open(ap,'r:*') as t: safe_extract(t,root)
        initial=find_file(root,'config/db/initial') or find_file(root,'config/db/initial_db')
        text=read_text(initial) if initial else ''
        facts=parse_initial(text)
        results=[]
        def exact(fid,title,cat,key,good_values,severity,expected,impact,remediation):
            v,e,s=ev(facts,key,str(initial.relative_to(root)) if initial else 'Not supplied')
            if v is None:
                results.append(finding(fid,title,cat,'Not Assessed','Informational',0,expected,'No authoritative active setting found',impact,remediation,'Required key not present',s))
            else:
                ok=v.lower() in [x.lower() for x in good_values]
                results.append(finding(fid,title,cat,'Compliant' if ok else 'Non-Compliant', 'Informational' if ok else severity,98,expected,v,impact,remediation,e,s))
        exact('CP-GAIA-001','Telnet service disabled','Management Plane','netaccess:telnet',['off','false','0'],'High','Disabled','Clear-text administrative access can expose privileged credentials.','Disable Telnet and use SSH/HTTPS from approved management networks.')
        exact('CP-GAIA-002','IPv6 disabled when not required','Network Hardening','ipv6',['f','false','off','0'],'Medium','Disabled unless formally required','Unused IPv6 can create an unmonitored attack path.','Disable IPv6 when unused, or document and secure the IPv6 design.')
        exact('CP-GAIA-003','Bootloader password configured','Platform Hardening','grub2pwd:PWD',[], 'High','A protected GRUB password hash','Physical or console access may permit boot parameter alteration.','Configure and protect the GRUB bootloader password.')
        # override presence-based checks
        for r in results:
            if r.id=='CP-GAIA-003' and facts.get('grub2pwd:PWD'):
                r.status='Compliant'; r.severity='Informational'; r.confidence=99; r.observed='Configured hash present'; r.evidence='grub2pwd:PWD [REDACTED]'
        exact('CP-GAIA-004','Expert mode password configured','Administrative Access','expertpwd:PWD',[], 'High','Expert mode protected by password','Unprotected expert mode enables unrestricted shell access.','Set a strong expert-mode password and restrict expert access.')
        for r in results:
            if r.id=='CP-GAIA-004' and facts.get('expertpwd:PWD'):
                r.status='Compliant'; r.severity='Informational'; r.confidence=99; r.observed='Configured hash present'; r.evidence='expertpwd:PWD [REDACTED]'
        # timeout
        v,e,s=ev(facts,'inactto:default',str(initial.relative_to(root)) if initial else 'Not supplied')
        if v and v.isdigit():
            n=int(v); ok=1<=n<=15
            results.append(finding('CP-GAIA-005','Administrative inactivity timeout','Administrative Access','Compliant' if ok else 'Non-Compliant','Informational' if ok else 'Medium',98,'1–15 minutes',f'{n} minutes','Long-lived idle sessions increase session hijacking risk.','Set the administrative inactivity timeout to 15 minutes or less.',e,s))
        else: results.append(finding('CP-GAIA-005','Administrative inactivity timeout','Administrative Access','Not Assessed','Informational',0,'1–15 minutes','No authoritative setting found','Long-lived idle sessions increase session hijacking risk.','Set the administrative inactivity timeout to 15 minutes or less.','Missing inactto:default',s))
        exact('CP-GAIA-006','Centralized RADIUS authentication enabled','Authentication','aaa:auth_order:radius:state',['on','true','1'],'Medium','Enabled where centralized AAA is required','Local-only authentication weakens centralized control and revocation.','Enable approved RADIUS/TACACS+ and retain controlled break-glass access.')
        # TACACS+ is an alternative to RADIUS, not universally mandatory. Avoid a false failure.
        v,e,s=ev(facts,'aaa:auth_order:tacacs:state',str(initial.relative_to(root)) if initial else 'Not supplied')
        radius_on=facts.get('aaa:auth_order:radius:state','').lower() in ('on','true','1')
        if v is None:
            results.append(finding('CP-GAIA-007','Centralized TACACS+ authentication','Authentication','Not Assessed','Informational',0,'Enabled only when required by the approved AAA design','No authoritative setting found','Absence of centralized command accounting can reduce accountability.','Enable TACACS+ when it is the organization-approved AAA method.','Required key not present',s))
        elif v.lower() in ('on','true','1'):
            results.append(finding('CP-GAIA-007','Centralized TACACS+ authentication','Authentication','Compliant','Informational',98,'Enabled when required by the approved AAA design','Enabled','Centralized AAA improves accountability.','Maintain redundant TACACS+ services and controlled break-glass access.',e,s))
        elif radius_on:
            results.append(finding('CP-GAIA-007','Centralized TACACS+ authentication','Authentication','Not Applicable','Informational',94,'TACACS+ or an approved alternative centralized AAA method','TACACS+ disabled; RADIUS is enabled','TACACS+ is not mandatory when an approved centralized alternative is in use.','Confirm RADIUS is the formally approved AAA method.',e+'\naaa:auth_order:radius:state on',s))
        else:
            results.append(finding('CP-GAIA-007','Centralized TACACS+ authentication','Authentication','Manual Review Required','Low',60,'Enabled when required by the approved AAA design','Disabled and no active RADIUS evidence','Local-only authentication may weaken centralized control.','Confirm the approved AAA architecture and enable centralized AAA if required.',e,s))
        exact('CP-GAIA-008','Scheduled configuration backup enabled','Resilience','backup-scheduled:Config_Backup',['t','true','on','1'],'High','Enabled','Missing backups can prolong outage and configuration recovery.','Configure protected recurring backups and test restoration.')
        # backup transport
        v,e,s=ev(facts,'backup-scheduled:Config_Backup:type',str(initial.relative_to(root)) if initial else 'Not supplied')
        if v:
            bad=v.lower() in ('ftp','tftp')
            results.append(finding('CP-GAIA-009','Secure backup transfer protocol','Resilience','Non-Compliant' if bad else 'Compliant','High' if bad else 'Informational',98,'SCP/SFTP or other encrypted transport',v,'FTP/TFTP can expose backup credentials and sensitive configurations.','Use SCP/SFTP or another authenticated encrypted backup channel.',e,s))
        else: results.append(finding('CP-GAIA-009','Secure backup transfer protocol','Resilience','Not Assessed','Informational',0,'Encrypted transport','No setting found','Unencrypted backup transfer can expose sensitive configuration.','Use SCP/SFTP or another encrypted backup channel.','Missing backup transport setting',s))
        exact('CP-GAIA-010','Management interface explicitly defined','Management Plane','management:interface',[], 'Medium','Dedicated management interface','Unclear management-plane separation can expose administrative services.','Use and restrict a dedicated management interface.')
        for r in results:
            if r.id=='CP-GAIA-010' and facts.get('management:interface'):
                r.status='Compliant'; r.severity='Informational'; r.confidence=96
        # SNMP file
        snmp=find_file(root,'var/lib/net-snmp/snmpd.conf'); st=read_text(snmp) if snmp else ''
        if not snmp:
            results.append(finding('CP-GAIA-011','Secure SNMP configuration','Monitoring','Not Assessed','Informational',0,'SNMPv3 or disabled','No SNMP evidence supplied','Weak SNMP communities can disclose or alter system information.','Use SNMPv3 with authentication and privacy, or disable SNMP.','No snmpd.conf', 'Not supplied'))
        else:
            weak=bool(re.search(r'(?im)^\s*(rocommunity|rwcommunity)\s+',st)); v3=bool(re.search(r'(?im)^\s*(rouser|rwuser|createUser)\s+',st)) or 'usmUser' in st
            status='Non-Compliant' if weak else ('Compliant' if v3 else 'Manual Review Required')
            sev='High' if weak else ('Informational' if v3 else 'Low'); conf=95 if weak or v3 else 55
            evidence='\n'.join([redact(x) for x in st.splitlines() if re.search(r'(?i)(community|user|group|access)',x)][:20]) or 'Configuration present; no decisive directive parsed'
            results.append(finding('CP-GAIA-011','Secure SNMP configuration','Monitoring',status,sev,conf,'SNMPv3 or disabled','Weak community directive detected' if weak else ('SNMPv3 evidence detected' if v3 else 'Configuration ambiguous'),'Weak SNMP can disclose or modify operational data.','Remove SNMPv1/v2c communities and use SNMPv3 authPriv.',evidence,str(snmp.relative_to(root))))
        # hotfix evidence is inventory, not currency judgment
        hf=find_file(root,'tmp/installed_hotfixes.txt'); hft=read_text(hf) if hf else ''
        results.append(finding('CP-PATCH-001','Installed hotfix inventory available','Patch Management','Compliant' if hft.strip() else 'Not Assessed','Informational',95 if hft.strip() else 0,'Installed hotfix inventory present','Inventory found' if hft.strip() else 'No inventory found','Missing patch evidence prevents reliable exposure assessment.','Export installed hotfix inventory and compare with an approved current baseline.',redact('\n'.join(hft.splitlines()[:30])) if hft else 'Not supplied',str(hf.relative_to(root)) if hf else 'Not supplied'))
        # Availability/update authorization setting
        v,e,s=ev(facts,'AllowSendingDataToCheckPointDefault',str(initial.relative_to(root)) if initial else 'Not supplied')
        # NTP broad evidence
        ntp_keys=[(k,v) for k,v in facts.items() if k.lower().startswith('ntp')]
        if ntp_keys:
            evidence='\n'.join(redact(f'{k} {v}') for k,v in ntp_keys[:30])
            enabled=any(v.lower() in ('t','true','on','1') for k,v in ntp_keys if k.lower() in ('ntp','ntp:enabled','ntp:active')) or any('server' in k.lower() for k,v in ntp_keys)
            results.append(finding('CP-GAIA-012','Network time synchronization configured','Time Security','Compliant' if enabled else 'Manual Review Required','Informational' if enabled else 'Medium',90 if enabled else 55,'Approved NTP servers configured','NTP-related configuration detected','Incorrect time impairs logs, authentication, and incident correlation.','Configure redundant authenticated or trusted NTP sources.',evidence,str(initial.relative_to(root))))
        else: results.append(finding('CP-GAIA-012','Network time synchronization configured','Time Security','Not Assessed','Informational',0,'Approved NTP servers configured','No authoritative NTP evidence','Incorrect time impairs logs and incident correlation.','Supply show configuration/show ntp output.','No NTP keys found',str(initial.relative_to(root)) if initial else 'Not supplied'))
        # Extended high-confidence Gaia checks. These use explicit active values only.
        src=str(initial.relative_to(root)) if initial else 'Not supplied'
        def numeric_rule(fid,title,cat,key,minimum=None,maximum=None,severity='Medium',expected='',impact='',remediation=''):
            v,e,s=ev(facts,key,src)
            try: n=int(v) if v is not None else None
            except (TypeError,ValueError): n=None
            if n is None:
                results.append(finding(fid,title,cat,'Not Assessed','Informational',0,expected,'No authoritative numeric setting found',impact,remediation,'Required key not present',s)); return
            ok=(minimum is None or n>=minimum) and (maximum is None or n<=maximum)
            results.append(finding(fid,title,cat,'Compliant' if ok else 'Non-Compliant','Informational' if ok else severity,98,expected,str(n),impact,remediation,e,s))

        numeric_rule('CP-AUTH-001','Minimum password length','Authentication','pwcontrol:minlen',minimum=8,severity='High',expected='At least 8 characters; apply a stronger organizational standard where required',impact='Short passwords are more vulnerable to guessing and cracking attacks.',remediation='Set the Gaia minimum password length to at least 12 characters.')
        numeric_rule('CP-AUTH-002','Password history enforcement','Authentication','pwcontrol:history_len',minimum=10,severity='Medium',expected='At least 10 previous passwords remembered',impact='Insufficient password history permits rapid reuse of compromised passwords.',remediation='Enable password history and remember at least 10 previous passwords.')
        numeric_rule('CP-AUTH-003','Maximum password age','Authentication','pwcontrol:expiry',minimum=1,maximum=90,severity='Medium',expected='Between 1 and 90 days where password expiry is required',impact='Long-lived passwords increase exposure after credential compromise.',remediation='Set password expiry to 90 days or less, consistent with organizational policy.')
        numeric_rule('CP-AUTH-004','Failed-login lockout threshold','Authentication','pwcontrol:tally:max',minimum=1,maximum=5,severity='High',expected='Lockout after 5 or fewer failed attempts',impact='A high or disabled threshold permits sustained password guessing.',remediation='Enable account lockout after no more than five failed attempts.')
        numeric_rule('CP-AUTH-005','Failed-login observation window','Authentication','pwcontrol:tally:time',minimum=300,maximum=900,severity='Medium',expected='300–900 seconds',impact='An ineffective lockout window can weaken brute-force protection.',remediation='Configure an approved failed-login observation window, typically 5–15 minutes.')
        exact('CP-AUTH-006','Account lockout enforcement enabled','Authentication','pwcontrol:tally:do',['t','true','on','1'],'High','Enabled','Without lockout enforcement, repeated password guessing may continue unchecked.','Enable Gaia password tally and account lockout enforcement.')
        exact('CP-AUTH-007','Password history enabled','Authentication','pwcontrol:history',['t','true','on','1'],'Medium','Enabled','Disabled history permits repeated reuse of old credentials.','Enable password history enforcement.')
        exact('CP-AUTH-008','Palindromic passwords rejected','Authentication','pwcontrol:ckpalind',['t','true','on','1'],'Low','Enabled','Predictable password patterns reduce password strength.','Enable palindrome checking as part of password-quality controls.')

        exact('CP-SSH-001','Direct SSH root login disabled','SSH Hardening','ssh:config:permitrootlogin',['no','off','false','0'],'High','Disabled','Direct root login removes individual accountability and increases privileged-access risk.','Set PermitRootLogin to no and use named administrative accounts with controlled elevation.')
        v,e,s=ev(facts,'ssh:config:passwordauthentication',src)
        if v is None:
            results.append(finding('CP-SSH-002','SSH password authentication restricted','SSH Hardening','Not Assessed','Informational',0,'Disabled where public-key or centralized authentication is operational','No authoritative setting found','Password-based SSH access increases exposure to credential attacks.','Prefer public-key or centralized authentication and retain controlled recovery access.','Required key not present',s))
        else:
            enabled=v.lower() in ('yes','on','true','1')
            status='Manual Review Required' if enabled else 'Compliant'
            results.append(finding('CP-SSH-002','SSH password authentication restricted','SSH Hardening',status,'Medium' if enabled else 'Informational',72 if enabled else 98,'Disabled where approved key-based or centralized authentication is operational','Enabled' if enabled else 'Disabled','Password-based SSH access increases exposure to credential attacks.','Validate operational dependencies, then disable SSH password authentication where feasible.',e,s))
        numeric_rule('CP-SSH-003','SSH login grace time','SSH Hardening','ssh:config:logingracetime',minimum=1,maximum=60,severity='Medium',expected='60 seconds or less',impact='A long authentication grace period consumes resources and supports slow brute-force attempts.',remediation='Set SSH LoginGraceTime to 60 seconds or less.')
        v,e,s=ev(facts,'ssh:config:clientaliveinterval',src)
        if v is None:
            results.append(finding('CP-SSH-004','SSH idle-session keepalive','SSH Hardening','Not Assessed','Informational',0,'A non-zero interval aligned to session policy','No authoritative setting found','Uncontrolled SSH idle sessions can remain open indefinitely.','Configure SSH ClientAliveInterval and ClientAliveCountMax to terminate inactive sessions.','Required key not present',s))
        else:
            try: n=int(v)
            except ValueError: n=-1
            ok=1<=n<=900
            results.append(finding('CP-SSH-004','SSH idle-session keepalive','SSH Hardening','Compliant' if ok else 'Non-Compliant','Informational' if ok else 'Medium',98,'1–900 seconds',str(n),'Uncontrolled SSH idle sessions can remain open indefinitely.','Configure a non-zero SSH ClientAliveInterval consistent with the administrative timeout.',e,s))
        weak_ciphers=[k.split(':enabled:',1)[1] for k,v in facts.items() if k.startswith('ssh:cipher:enabled:') and v.lower() in ('t','true','on','1') and any(x in k.lower() for x in ('cbc','3des','arcfour'))]
        results.append(finding('CP-SSH-005','Weak SSH ciphers disabled','SSH Hardening','Non-Compliant' if weak_ciphers else 'Compliant','High' if weak_ciphers else 'Informational',98,'No CBC, 3DES, or RC4 ciphers enabled',', '.join(weak_ciphers) if weak_ciphers else 'No weak enabled cipher detected','Legacy SSH ciphers can provide weaker confidentiality and increase downgrade exposure.','Disable CBC, 3DES, RC4, and other organization-prohibited SSH ciphers.',redact('\n'.join(f'ssh:cipher:enabled:{x} t' for x in weak_ciphers)) if weak_ciphers else 'Enabled cipher set contains no matched legacy cipher',src))
        weak_macs=[k.split(':enabled:',1)[1] for k,v in facts.items() if k.startswith('ssh:mac:enabled:') and v.lower() in ('t','true','on','1') and any(x in k.lower() for x in ('hmac-sha1','umac-64','md5'))]
        results.append(finding('CP-SSH-006','Weak SSH MAC algorithms disabled','SSH Hardening','Non-Compliant' if weak_macs else 'Compliant','Medium' if weak_macs else 'Informational',98,'No SHA-1, MD5, or 64-bit UMAC algorithms enabled',', '.join(weak_macs) if weak_macs else 'No weak enabled MAC detected','Legacy MAC algorithms weaken SSH integrity protection.','Disable SHA-1, MD5, and 64-bit UMAC algorithms when compatibility permits.',redact('\n'.join(f'ssh:mac:enabled:{x} t' for x in weak_macs)) if weak_macs else 'Enabled MAC set contains no matched legacy algorithm',src))
        weak_kex=[k.split(':enabled:',1)[1] for k,v in facts.items() if k.startswith('ssh:kex:enabled:') and v.lower() in ('t','true','on','1') and any(x in k.lower() for x in ('group1-sha1','group14-sha1','exchange-sha1'))]
        results.append(finding('CP-SSH-007','Weak SSH key-exchange algorithms disabled','SSH Hardening','Non-Compliant' if weak_kex else 'Compliant','Medium' if weak_kex else 'Informational',98,'No SHA-1-based or group1 KEX enabled',', '.join(weak_kex) if weak_kex else 'No weak enabled KEX detected','Legacy key-exchange algorithms can reduce session security.','Disable group1 and SHA-1-based SSH key-exchange algorithms.',redact('\n'.join(f'ssh:kex:enabled:{x} t' for x in weak_kex)) if weak_kex else 'Enabled KEX set contains no matched legacy algorithm',src))

        exact('CP-WEB-001','SSLv3 disabled for Gaia Portal','Web Management','httpd:ssl3_enabled',['0','off','false','no'],'High','Disabled','SSLv3 is obsolete and vulnerable to cryptographic attacks.','Keep SSLv3 disabled and permit only approved TLS versions.')
        numeric_rule('CP-WEB-002','Gaia Portal session timeout','Web Management','web:session-timeout',minimum=1,maximum=15,severity='Medium',expected='15 minutes or less',impact='Long-lived web administration sessions increase hijacking risk.',remediation='Set the Gaia Portal session timeout to 15 minutes or less.')
        v,e,s=ev(facts,'httpd:port',src)
        if v is None:
            results.append(finding('CP-WEB-003','Plain HTTP management exposure','Web Management','Not Assessed','Informational',0,'HTTP disabled or redirected without exposing authentication','No authoritative setting found','Plain HTTP can expose or downgrade management traffic.','Disable HTTP management or enforce secure redirection and network restrictions.','Required key not present',s))
        else:
            results.append(finding('CP-WEB-003','Plain HTTP management exposure','Web Management','Manual Review Required','Medium',60,'HTTP disabled or securely redirected and restricted',f'HTTP listener configured on port {v}','The presence of a configured port does not prove whether authentication is exposed or only redirected.','Verify runtime behavior and disable plain HTTP access when not required.',e,s))

        remote_syslog=[k for k,v in facts.items() if k.startswith('syslog:action:remote:') and ':selector' in k and v]
        results.append(finding('CP-LOG-001','Remote syslog forwarding configured','Logging and Monitoring','Compliant' if remote_syslog else 'Not Assessed','Informational',97 if remote_syslog else 0,'At least one approved remote syslog destination','Configured' if remote_syslog else 'No authoritative remote destination found','Without centralized logs, incidents may be harder to detect and investigate.','Forward relevant Gaia logs to redundant protected log collectors.',redact('\n'.join(f'{k} {facts[k]}' for k in remote_syslog[:10])) if remote_syslog else 'No remote syslog selector found',src))
        exact('CP-LOG-002','Gaia audit logs sent to management','Logging and Monitoring','syslog:sendaudittomgmt',['t','true','on','1'],'High','Enabled','Missing administrative audit forwarding reduces accountability and investigation capability.','Enable forwarding of Gaia audit events to the management server.')

        exact('CP-SNMP-002','SNMP restricted to version 3','Monitoring','snmp:version',['v3-only','v3'],'High','SNMPv3-only','SNMPv1/v2c rely on community strings and provide weak security.','Configure SNMPv3-only with authentication and privacy.')
        snmp_users=[k for k,v in facts.items() if k.startswith('snmp:v3:user:') and k.endswith(':seclvl')]
        weak_snmp=[f'{k} {facts[k]}' for k in snmp_users if 'authpriv' not in facts[k].lower()]
        if snmp_users:
            results.append(finding('CP-SNMP-003','SNMPv3 users require authentication and privacy','Monitoring','Non-Compliant' if weak_snmp else 'Compliant','High' if weak_snmp else 'Informational',98,'All SNMPv3 users use authPriv','Weak users detected' if weak_snmp else f'{len(snmp_users)} users use authPriv','SNMP users without privacy may expose monitoring data and credentials.','Require authPriv for every SNMPv3 user and remove obsolete accounts.',redact('\n'.join(weak_snmp if weak_snmp else [f'{k} {facts[k]}' for k in snmp_users])),src))
        else:
            results.append(finding('CP-SNMP-003','SNMPv3 users require authentication and privacy','Monitoring','Not Assessed','Informational',0,'All SNMPv3 users use authPriv','No SNMPv3 user security levels found','SNMP users without privacy may expose monitoring data.','Provide active SNMP configuration evidence.','No user security-level keys found',src))

        ntp_versions=[(k,v) for k,v in facts.items() if k.startswith('ntp:server:') and k.endswith(':version')]
        legacy_ntp=[f'{k} {v}' for k,v in ntp_versions if v.isdigit() and int(v)<4]
        if ntp_versions:
            results.append(finding('CP-TIME-002','NTP servers use current protocol version','Time Security','Non-Compliant' if legacy_ntp else 'Compliant','Medium' if legacy_ntp else 'Informational',98,'NTP version 4 where supported','Legacy version configured' if legacy_ntp else 'All parsed servers use version 4','Older NTP versions may lack current protocol protections and interoperability improvements.','Use NTP version 4 for configured time sources where supported.',redact('\n'.join(legacy_ntp if legacy_ntp else [f'{k} {v}' for k,v in ntp_versions])),src))
        else:
            results.append(finding('CP-TIME-002','NTP servers use current protocol version','Time Security','Not Assessed','Informational',0,'NTP version 4 where supported','No NTP version evidence','Legacy time protocols may weaken time synchronization.','Provide show ntp or active configuration output.','No NTP version keys found',src))

        v,e,s=ev(facts,'backup-scheduled:Config_Backup:max_backups',src)
        if v is not None and v.isdigit():
            n=int(v); ok=n>=3
            status='Compliant' if ok else ('Manual Review Required' if n==0 else 'Non-Compliant')
            sev='Informational' if ok else ('Low' if n==0 else 'Medium')
            conf=98 if n!=0 else 65
            results.append(finding('CP-BACKUP-003','Configuration backup retention','Resilience',status,sev,conf,'At least 3 retained backups or documented unlimited retention',str(n),'No or insufficient retention can leave no clean recovery point after corruption or compromise.','Retain multiple protected backup generations according to recovery requirements.',e,s))
        else:
            results.append(finding('CP-BACKUP-003','Configuration backup retention','Resilience','Not Assessed','Informational',0,'At least 3 retained backups','No authoritative retention value','Insufficient retention can leave no clean recovery point.','Configure and document backup retention.','Required key not present',s))

        tz=facts.get('timezone')
        results.append(finding('CP-SYS-001','System timezone explicitly configured','System Configuration','Compliant' if tz else 'Not Assessed','Informational',98 if tz else 0,'Approved organizational timezone',tz or 'No timezone setting found','Incorrect timezone configuration complicates event correlation and reporting.','Configure the approved timezone consistently across security infrastructure.',redact(f'timezone {tz}') if tz else 'Required key not present',src))
        # Policy checks cannot be inferred from gateway backup alone
        for fid,title,cat in [
          ('CP-POL-001','Overly permissive Any/Any access rules','Firewall Policy'),('CP-POL-002','Accept rules have logging enabled','Firewall Policy'),('CP-POL-003','Cleanup rule present and logged','Firewall Policy'),('CP-POL-004','Disabled, expired and unused rules reviewed','Firewall Policy'),('CP-NAT-001','Overly broad NAT rules','NAT Policy'),('CP-TP-001','Threat Prevention profiles assigned','Threat Prevention'),('CP-ADM-001','Administrator roles follow least privilege','Management Server')]:
            results.append(finding(fid,title,cat,'Not Assessed','Informational',0,'Management API/rulebase evidence required','Gateway backup does not provide authoritative management policy data','Incorrectly inferring policy state from gateway files creates false positives.','Provide mgmt_cli JSON exports or SmartConsole policy exports.','Evidence deliberately not inferred','Management export required'))
        meta={'archive':ap.name,'sha256':sha,'version':'R82.10' if 'R82.10' in '\n'.join(str(p) for p in root.rglob('*')) else 'Unknown','hostname':facts.get('machine:hostname','Unknown'),'role':'Centrally Managed' if facts.get('centrallyManaged','').lower() in ('t','true','1') else 'Unknown','file_count':sum(1 for p in root.rglob('*') if p.is_file())}
        return meta,results
