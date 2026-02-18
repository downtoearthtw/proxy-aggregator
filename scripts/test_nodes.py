#!/usr/bin/env python3
"""
節點測試器 - 測試連通性和中國可用性
"""

import json
import asyncio
import aiohttp
import socket
import ssl
import time
from pathlib import Path
from dataclasses import dataclass
from typing import Optional
import ipaddress


@dataclass
class TestResult:
    """測試結果"""
    node_id: str
    tcp_ok: bool = False
    tls_ok: bool = False
    latency_ms: int = 9999
    ip_info: dict = None
    ip_score: int = 0  # 0-100, 越高越好
    china_friendly: bool = False
    error: str = ""


class IPChecker:
    """IP 純淨度檢測"""
    
    # 已知被封鎖/不乾淨的 ASN
    BLOCKED_ASNS = {
        # 可根據經驗添加
    }
    
    # 已知乾淨的 CDN/雲端 ASN
    TRUSTED_ASNS = {
        13335,   # Cloudflare
        20940,   # Akamai
        16509,   # Amazon
        15169,   # Google
        8075,    # Microsoft
    }
    
    def __init__(self):
        self.cache = {}
    
    async def check_ip(self, session: aiohttp.ClientSession, ip: str) -> dict:
        """檢查 IP 資訊"""
        if ip in self.cache:
            return self.cache[ip]
        
        info = {
            "ip": ip,
            "country": "",
            "asn": 0,
            "org": "",
            "is_datacenter": False,
            "is_vpn": False,
            "trust_score": 50
        }
        
        try:
            # 使用 ip-api.com (免費，有速率限制)
            async with session.get(
                f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,isp,org,as,hosting",
                timeout=aiohttp.ClientTimeout(total=5)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("status") == "success":
                        info["country"] = data.get("countryCode", "")
                        info["org"] = data.get("org", "")
                        info["is_datacenter"] = data.get("hosting", False)
                        
                        # 提取 ASN
                        as_str = data.get("as", "")
                        if as_str:
                            try:
                                info["asn"] = int(as_str.split()[0].replace("AS", ""))
                            except:
                                pass
                        
                        # 計算信任分數
                        score = 50
                        
                        # 數據中心 IP 減分
                        if info["is_datacenter"]:
                            score -= 20
                        
                        # 可信 ASN 加分
                        if info["asn"] in self.TRUSTED_ASNS:
                            score += 30
                        
                        # 被封鎖 ASN 減分
                        if info["asn"] in self.BLOCKED_ASNS:
                            score -= 50
                        
                        # 中國 IP 不適合 (用於翻牆)
                        if info["country"] == "CN":
                            score -= 40
                        
                        info["trust_score"] = max(0, min(100, score))
        
        except Exception as e:
            info["error"] = str(e)
        
        self.cache[ip] = info
        return info


class NodeTester:
    """節點測試器"""
    
    def __init__(self, settings_path: str = "config/settings.json"):
        with open(settings_path, 'r') as f:
            self.settings = json.load(f)
        
        self.test_config = self.settings.get("testing", {})
        self.timeout = self.test_config.get("timeout_seconds", 10)
        self.max_concurrent = self.test_config.get("max_concurrent", 50)
        
        self.ip_checker = IPChecker()
        self.results: dict[str, TestResult] = {}
    
    async def resolve_host(self, host: str) -> Optional[str]:
        """解析主機名到 IP"""
        try:
            # 如果已經是 IP，直接返回
            ipaddress.ip_address(host)
            return host
        except ValueError:
            pass
        
        try:
            loop = asyncio.get_event_loop()
            result = await loop.getaddrinfo(host, None, family=socket.AF_INET)
            if result:
                return result[0][4][0]
        except Exception:
            pass
        
        return None
    
    async def test_tcp(self, host: str, port: int) -> tuple[bool, int]:
        """TCP 連接測試，返回 (成功, 延遲ms)"""
        try:
            start = time.time()
            
            # 創建連接
            loop = asyncio.get_event_loop()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )
            
            latency = int((time.time() - start) * 1000)
            writer.close()
            await writer.wait_closed()
            
            return True, latency
            
        except Exception:
            return False, 9999
    
    async def test_tls(self, host: str, port: int, sni: str = "") -> bool:
        """TLS 握手測試"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host, port,
                    ssl=context,
                    server_hostname=sni or host
                ),
                timeout=self.timeout
            )
            
            writer.close()
            await writer.wait_closed()
            return True
            
        except Exception:
            return False
    
    async def test_node(self, session: aiohttp.ClientSession, node: dict) -> TestResult:
        """測試單個節點"""
        result = TestResult(node_id=node.get("unique_id", ""))
        
        try:
            host = node.get("address", "")
            port = node.get("port", 443)
            
            if not host or not port:
                result.error = "Invalid host/port"
                return result
            
            # 解析 IP
            ip = await self.resolve_host(host)
            if not ip:
                result.error = "DNS resolution failed"
                return result
            
            # TCP 測試
            tcp_ok, latency = await self.test_tcp(ip, port)
            result.tcp_ok = tcp_ok
            result.latency_ms = latency
            
            if not tcp_ok:
                result.error = "TCP connection failed"
                return result
            
            # TLS 測試 (如果節點使用 TLS)
            if node.get("tls", False):
                sni = node.get("sni", "") or host
                result.tls_ok = await self.test_tls(ip, port, sni)
            else:
                result.tls_ok = True
            
            # IP 純淨度檢測
            ip_info = await self.ip_checker.check_ip(session, ip)
            result.ip_info = ip_info
            result.ip_score = ip_info.get("trust_score", 50)
            
            # 判斷中國友好度
            # 低延遲 + 乾淨 IP + 非中國 = 好節點
            result.china_friendly = (
                result.tcp_ok and
                result.latency_ms < 500 and
                result.ip_score >= 30 and
                ip_info.get("country", "") != "CN"
            )
            
        except Exception as e:
            result.error = str(e)
        
        return result
    
    async def test_all(self, nodes: list[dict]) -> list[dict]:
        """測試所有節點"""
        print(f"🦐 開始測試 {len(nodes)} 個節點...\n")
        
        # 限制並發
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def limited_test(session, node):
            async with semaphore:
                return await self.test_node(session, node)
        
        async with aiohttp.ClientSession() as session:
            tasks = [limited_test(session, node) for node in nodes]
            results = await asyncio.gather(*tasks)
        
        # 統計結果
        passed = 0
        tested_nodes = []
        
        for node, result in zip(nodes, results):
            node["test_result"] = {
                "tcp_ok": result.tcp_ok,
                "tls_ok": result.tls_ok,
                "latency_ms": result.latency_ms,
                "ip_score": result.ip_score,
                "china_friendly": result.china_friendly,
                "ip_country": result.ip_info.get("country", "") if result.ip_info else "",
                "error": result.error
            }
            
            if result.china_friendly:
                passed += 1
                tested_nodes.append(node)
        
        print(f"\n測試完成:")
        print(f"  ✓ 通過: {passed}")
        print(f"  ✗ 失敗: {len(nodes) - passed}")
        
        # 按延遲排序
        tested_nodes.sort(key=lambda x: x["test_result"]["latency_ms"])
        
        return tested_nodes
    
    def save_results(self, nodes: list[dict], output_path: str = "output/tested_nodes.json"):
        """保存測試結果"""
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        
        data = {
            "count": len(nodes),
            "updated": __import__('datetime').datetime.utcnow().isoformat() + "Z",
            "nodes": nodes
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        
        print(f"✓ 測試結果已保存到 {output_path}")


async def main():
    # 載入原始節點
    with open("output/raw_nodes.json", 'r') as f:
        data = json.load(f)
    
    nodes = data.get("nodes", [])
    
    # 測試節點
    tester = NodeTester()
    passed_nodes = await tester.test_all(nodes)
    
    # 保存結果
    tester.save_results(passed_nodes)


if __name__ == "__main__":
    asyncio.run(main())
