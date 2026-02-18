#!/usr/bin/env python3
"""
節點聚合器 - 從多個來源收集代理節點
"""

import json
import base64
import re
import asyncio
import aiohttp
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote
from dataclasses import dataclass, asdict
from typing import Optional
import yaml
import hashlib


@dataclass
class ProxyNode:
    """代理節點資料結構"""
    protocol: str  # vmess, vless, trojan, ss, ssr
    address: str
    port: int
    uuid_or_password: str
    name: str = ""
    network: str = "tcp"
    tls: bool = False
    sni: str = ""
    path: str = ""
    host: str = ""
    source: str = ""
    priority: int = 99
    
    @property
    def unique_id(self) -> str:
        """生成唯一 ID 用於去重"""
        key = f"{self.protocol}:{self.address}:{self.port}:{self.uuid_or_password}"
        return hashlib.md5(key.encode()).hexdigest()[:12]


class NodeParser:
    """節點解析器"""
    
    @staticmethod
    def parse_vmess(uri: str) -> Optional[ProxyNode]:
        """解析 vmess:// 連結"""
        try:
            encoded = uri.replace("vmess://", "")
            # 補齊 base64 padding
            padding = 4 - len(encoded) % 4
            if padding != 4:
                encoded += "=" * padding
            decoded = base64.b64decode(encoded).decode('utf-8')
            config = json.loads(decoded)
            
            return ProxyNode(
                protocol="vmess",
                address=config.get("add", ""),
                port=int(config.get("port", 443)),
                uuid_or_password=config.get("id", ""),
                name=config.get("ps", ""),
                network=config.get("net", "tcp"),
                tls=config.get("tls", "") == "tls",
                sni=config.get("sni", ""),
                path=config.get("path", ""),
                host=config.get("host", "")
            )
        except Exception as e:
            return None
    
    @staticmethod
    def parse_vless(uri: str) -> Optional[ProxyNode]:
        """解析 vless:// 連結"""
        try:
            parsed = urlparse(uri)
            params = parse_qs(parsed.query)
            
            # 提取 fragment 作為名稱
            name = unquote(parsed.fragment) if parsed.fragment else ""
            
            return ProxyNode(
                protocol="vless",
                address=parsed.hostname or "",
                port=parsed.port or 443,
                uuid_or_password=parsed.username or "",
                name=name,
                network=params.get("type", ["tcp"])[0],
                tls=params.get("security", ["none"])[0] in ["tls", "reality"],
                sni=params.get("sni", [""])[0],
                path=params.get("path", [""])[0],
                host=params.get("host", [""])[0]
            )
        except Exception:
            return None
    
    @staticmethod
    def parse_trojan(uri: str) -> Optional[ProxyNode]:
        """解析 trojan:// 連結"""
        try:
            parsed = urlparse(uri)
            params = parse_qs(parsed.query)
            name = unquote(parsed.fragment) if parsed.fragment else ""
            
            return ProxyNode(
                protocol="trojan",
                address=parsed.hostname or "",
                port=parsed.port or 443,
                uuid_or_password=parsed.username or "",
                name=name,
                network=params.get("type", ["tcp"])[0],
                tls=True,
                sni=params.get("sni", [""])[0],
                path=params.get("path", [""])[0],
                host=params.get("host", [""])[0]
            )
        except Exception:
            return None
    
    @staticmethod
    def parse_ss(uri: str) -> Optional[ProxyNode]:
        """解析 ss:// 連結 (Shadowsocks)"""
        try:
            uri = uri.replace("ss://", "")
            
            # 分離 fragment (名稱)
            if "#" in uri:
                uri, name = uri.rsplit("#", 1)
                name = unquote(name)
            else:
                name = ""
            
            # SIP002 格式: base64(method:password)@host:port
            if "@" in uri:
                user_info, server_info = uri.rsplit("@", 1)
                # 補齊 padding
                padding = 4 - len(user_info) % 4
                if padding != 4:
                    user_info += "=" * padding
                try:
                    decoded = base64.b64decode(user_info).decode('utf-8')
                    method, password = decoded.split(":", 1)
                except:
                    method, password = user_info, ""
                
                if ":" in server_info:
                    host, port = server_info.rsplit(":", 1)
                else:
                    host, port = server_info, "443"
            else:
                # 舊格式: base64(method:password@host:port)
                padding = 4 - len(uri) % 4
                if padding != 4:
                    uri += "=" * padding
                decoded = base64.b64decode(uri).decode('utf-8')
                method_pass, server = decoded.rsplit("@", 1)
                method, password = method_pass.split(":", 1)
                host, port = server.rsplit(":", 1)
            
            return ProxyNode(
                protocol="ss",
                address=host,
                port=int(port),
                uuid_or_password=f"{method}:{password}",
                name=name
            )
        except Exception:
            return None
    
    @staticmethod
    def parse_ssr(uri: str) -> Optional[ProxyNode]:
        """解析 ssr:// 連結 (ShadowsocksR)"""
        try:
            encoded = uri.replace("ssr://", "")
            padding = 4 - len(encoded) % 4
            if padding != 4:
                encoded += "=" * padding
            decoded = base64.b64decode(encoded).decode('utf-8')
            
            # 格式: host:port:protocol:method:obfs:password_base64/?params
            main_part = decoded.split("/?")[0]
            parts = main_part.split(":")
            
            if len(parts) >= 6:
                host = parts[0]
                port = int(parts[1])
                password_encoded = parts[5]
                padding = 4 - len(password_encoded) % 4
                if padding != 4:
                    password_encoded += "=" * padding
                password = base64.b64decode(password_encoded).decode('utf-8')
                
                return ProxyNode(
                    protocol="ssr",
                    address=host,
                    port=port,
                    uuid_or_password=password,
                    name=""
                )
        except Exception:
            return None
        return None
    
    @classmethod
    def parse_line(cls, line: str) -> Optional[ProxyNode]:
        """解析單行節點連結"""
        line = line.strip()
        if not line:
            return None
        
        if line.startswith("vmess://"):
            return cls.parse_vmess(line)
        elif line.startswith("vless://"):
            return cls.parse_vless(line)
        elif line.startswith("trojan://"):
            return cls.parse_trojan(line)
        elif line.startswith("ss://"):
            return cls.parse_ss(line)
        elif line.startswith("ssr://"):
            return cls.parse_ssr(line)
        
        return None


class ClashParser:
    """Clash 配置解析器"""
    
    @staticmethod
    def parse(content: str) -> list[ProxyNode]:
        """解析 Clash YAML 配置"""
        nodes = []
        try:
            config = yaml.safe_load(content)
            proxies = config.get("proxies", [])
            
            for proxy in proxies:
                ptype = proxy.get("type", "").lower()
                
                if ptype == "vmess":
                    node = ProxyNode(
                        protocol="vmess",
                        address=proxy.get("server", ""),
                        port=int(proxy.get("port", 443)),
                        uuid_or_password=proxy.get("uuid", ""),
                        name=proxy.get("name", ""),
                        network=proxy.get("network", "tcp"),
                        tls=proxy.get("tls", False),
                        sni=proxy.get("servername", ""),
                        path=proxy.get("ws-opts", {}).get("path", ""),
                        host=proxy.get("ws-opts", {}).get("headers", {}).get("Host", "")
                    )
                    nodes.append(node)
                    
                elif ptype == "vless":
                    node = ProxyNode(
                        protocol="vless",
                        address=proxy.get("server", ""),
                        port=int(proxy.get("port", 443)),
                        uuid_or_password=proxy.get("uuid", ""),
                        name=proxy.get("name", ""),
                        network=proxy.get("network", "tcp"),
                        tls=proxy.get("tls", False),
                        sni=proxy.get("servername", "")
                    )
                    nodes.append(node)
                    
                elif ptype == "trojan":
                    node = ProxyNode(
                        protocol="trojan",
                        address=proxy.get("server", ""),
                        port=int(proxy.get("port", 443)),
                        uuid_or_password=proxy.get("password", ""),
                        name=proxy.get("name", ""),
                        tls=True,
                        sni=proxy.get("sni", "")
                    )
                    nodes.append(node)
                    
                elif ptype == "ss":
                    node = ProxyNode(
                        protocol="ss",
                        address=proxy.get("server", ""),
                        port=int(proxy.get("port", 443)),
                        uuid_or_password=f"{proxy.get('cipher', '')}:{proxy.get('password', '')}",
                        name=proxy.get("name", "")
                    )
                    nodes.append(node)
                    
        except Exception as e:
            print(f"Clash parse error: {e}")
        
        return nodes


class NodeAggregator:
    """節點聚合器"""
    
    def __init__(self, config_path: str = "config/sources.json"):
        with open(config_path, 'r') as f:
            self.config = json.load(f)
        self.nodes: dict[str, ProxyNode] = {}  # unique_id -> node
    
    async def fetch_source(self, session: aiohttp.ClientSession, source: dict) -> list[ProxyNode]:
        """獲取單個來源的節點"""
        nodes = []
        try:
            async with session.get(source["url"], timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status != 200:
                    print(f"Failed to fetch {source['name']}: HTTP {resp.status}")
                    return nodes
                
                content = await resp.text()
                source_type = source.get("type", "mixed")
                
                if source_type == "clash":
                    nodes = ClashParser.parse(content)
                elif source_type == "base64":
                    # 整個內容是 base64 編碼的多行節點
                    try:
                        padding = 4 - len(content.strip()) % 4
                        if padding != 4:
                            content = content.strip() + "=" * padding
                        decoded = base64.b64decode(content).decode('utf-8')
                        for line in decoded.split('\n'):
                            node = NodeParser.parse_line(line)
                            if node:
                                nodes.append(node)
                    except:
                        # 可能不是 base64，嘗試直接解析
                        for line in content.split('\n'):
                            node = NodeParser.parse_line(line)
                            if node:
                                nodes.append(node)
                else:  # mixed
                    for line in content.split('\n'):
                        node = NodeParser.parse_line(line)
                        if node:
                            nodes.append(node)
                
                # 設定來源資訊
                for node in nodes:
                    node.source = source["name"]
                    node.priority = source.get("priority", 99)
                
                print(f"✓ {source['name']}: {len(nodes)} nodes")
                
        except Exception as e:
            print(f"✗ {source['name']}: {e}")
        
        return nodes
    
    async def aggregate(self) -> list[ProxyNode]:
        """聚合所有來源"""
        print("🦐 開始聚合節點...\n")
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            for source in self.config["sources"]:
                if source.get("enabled", True):
                    tasks.append(self.fetch_source(session, source))
            
            results = await asyncio.gather(*tasks)
            
            # 合併並去重
            for source_nodes in results:
                for node in source_nodes:
                    if node.address and node.port:
                        uid = node.unique_id
                        # 保留優先級較高（數字較小）的節點
                        if uid not in self.nodes or node.priority < self.nodes[uid].priority:
                            self.nodes[uid] = node
        
        # 轉換為列表並排序
        all_nodes = list(self.nodes.values())
        all_nodes.sort(key=lambda x: (x.priority, x.address))
        
        print(f"\n總計: {len(all_nodes)} 個唯一節點")
        return all_nodes
    
    def save_nodes(self, nodes: list[ProxyNode], output_path: str = "output/raw_nodes.json"):
        """保存節點到文件"""
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        
        data = {
            "count": len(nodes),
            "updated": __import__('datetime').datetime.utcnow().isoformat() + "Z",
            "nodes": [asdict(node) for node in nodes]
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        
        print(f"✓ 已保存到 {output_path}")


async def main():
    aggregator = NodeAggregator()
    nodes = await aggregator.aggregate()
    aggregator.save_nodes(nodes)


if __name__ == "__main__":
    asyncio.run(main())
