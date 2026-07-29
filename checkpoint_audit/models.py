from dataclasses import dataclass, asdict
@dataclass
class Finding:
    id:str; title:str; category:str; status:str; severity:str; confidence:int
    expected:str; observed:str; impact:str; remediation:str; evidence:str; source:str
    cis_reference:str="CIS-aligned technical check"
    def dict(self): return asdict(self)
