from dataclasses import dataclass
from enum import Enum
from logging import Logger
from threading import Lock
from typing import Optional

from networking.frames import IPFrame
from networking.types import IPaddr, IPProtocol

class FirewallAction(Enum):
    ACCEPT = "ACCEPT"
    DROP = "DROP"
    
    
@dataclass
class FirewallRule:
    src_ip: Optional[IPaddr]
    protocol: Optional[IPProtocol]
    action: FirewallAction 
    
    def matches(self, ip_frame: IPFrame) -> bool:
        if self.src_ip is not None and ip_frame.source != self.src_ip:
            return False
        if self.protocol is not None and ip_frame.protocol != self.protocol:
            return False
        return True
    
    def __str__(self) -> str:
        src = f"0x{self.src_ip:02x}" if self.src_ip is not None else "*"
        proto = self.protocol.name if self.protocol is not None else "*"
        return f"src={src}, proto={proto} -> {self.action.value}"
    
    
class Firewall:
    def __init__(self, logger: Logger, default_policy: FirewallAction = FirewallAction.ACCEPT):
        self.rules: list[FirewallRule] = []
        self.default_policy = FirewallAction = default_policy
        self.logger = logger
        self.lock = Lock()

    def check(self, ip_frame: IPFrame) -> bool:
        if ip_frame.protocol == IPProtocol.ARP:
            return True
        
        with self.lock:
            for i, rule in enumerate(self.rules):
                if rule.matches(ip_frame):
                    self.logger.info(
                        f"Firewall rule {i} matched: ({rule})"
                        f"for packet from 0x{ip_frame.source:02x} -> {rule.action.value}"
                    )
                    return rule.action == FirewallAction.ACCEPT
        
        self.logger.info(
            f"No firewall rule matched for packet from 0x{ip_frame.source:02x}, "
            f"applying default policy: {self.default_policy.value}"
        )
        return self.default_policy == FirewallAction.ACCEPT
    
    def add_rule(self, rule: FirewallRule) -> int:
        with self.lock:
            self.rules.append(rule)
            index = len(self.rules) - 1
        self.logger.info(f"Added firewall rule #{index}: {rule}")
        return index
    
    def remove_rule(self, index: int) -> bool:
        with self.lock:
            if 0 <= index < len(self.rules):
                removed_rule = self.rules.pop(index)
                self.logger.info(f"Removed firewall rule #{index}: {removed_rule}")
                return True
            else:
                self.logger.warning(f"Attempted to remove non-existent firewall rule #{index}")
                return False
    
    def list_rules(self) -> list[str]:
        with self.lock:
            lines = [f"#{i}: {rule}" for i, rule in enumerate(self.rules)]
        lines.append(f"Default policy: {self.default_policy.value}")
        return lines
    
    def set_default_policy(self, policy: FirewallAction):
        self.default_policy = policy
        self.logger.info(f"Set default firewall policy to: {policy.value}")
        
        