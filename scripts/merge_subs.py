#!/usr/bin/env python3
"""
訂閱合併器 - 合併 BPB Panel 和聚合節點，輸出多種格式
"""

import json
import base64
import yaml
import asyncio
import aiohttp
from pathlib import Path
from datetime import datetime
from typing import Optional
from urllib.parse import quote


class SubscriptionMerger:
    """訂閱合併器"""
    
    def __init__(self, settings_path: str = "config/settings.json", sources_path: str = "config/sources.json"):
        with open(settings_path, 'r') as f:
            self.settings = json.load(f)
        with open(sources_path, 'r') as f:
            self.sources = json.load(f)
        
        self.output_config = self.settings.get("output", {})
        self.max_nodes = self.output_config.get("max_nodes", 200)
    
    async def fetch_bpb_subscription(self) -> list[dict]:
        """獲取 BPB Panel 訂閱"""
        bpb_config = self.sources.get("bpb_panel", {})
        if not bpb_config.get("enabled") or not bpb_config.get("subscription_url"):
            print("ℹ BPB Panel 訂閱未配置")
            return []
        
        url = bpb_config["subscription_url"]
        nodes = []
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        # BPB Panel 可能返回不同格式，這裡嘗試解析
                        try:
                            # 嘗試 JSON (sing-box 格式)
                            data = json.loads(content)
                            print(f"✓ BPB Panel: 已獲取 sing-box 配置")
                            return [{"type": "singbox_config", "data": data, "source": "bpb", "priority": 0}]
                        except:
                            pass
                        
                        # 嘗試解析為普通節點列表
                        from aggregate import NodeParser
                        lines = content.strip().split('\n')
                        for line in lines:
                            node = NodeParser.parse_line(line)
                            if node:
                                node.source = "bpb"
                                node.priority = 0
                                nodes.append(node.__dict__)
                        
                        print(f"✓ BPB Panel: {len(nodes)} 個節點")
        except Exception as e:
            print(f"✗ BPB Panel 獲取失敗: {e}")
        
        return nodes
    
    def node_to_singbox_outbound(self, node: dict, tag: str) -> Optional[dict]:
        """將節點轉換為 sing-box outbound"""
        protocol = node.get("protocol", "")
        
        if protocol == "vmess":
            return {
                "type": "vmess",
                "tag": tag,
                "server": node.get("address"),
                "server_port": node.get("port"),
                "uuid": node.get("uuid_or_password"),
                "security": "auto",
                "alter_id": 0,
                "transport": self._get_transport(node),
                "tls": self._get_tls(node) if node.get("tls") else None
            }
        
        elif protocol == "vless":
            outbound = {
                "type": "vless",
                "tag": tag,
                "server": node.get("address"),
                "server_port": node.get("port"),
                "uuid": node.get("uuid_or_password"),
                "transport": self._get_transport(node),
            }
            if node.get("tls"):
                outbound["tls"] = self._get_tls(node)
            return outbound
        
        elif protocol == "trojan":
            return {
                "type": "trojan",
                "tag": tag,
                "server": node.get("address"),
                "server_port": node.get("port"),
                "password": node.get("uuid_or_password"),
                "tls": self._get_tls(node),
                "transport": self._get_transport(node) if node.get("network") != "tcp" else None
            }
        
        elif protocol == "ss":
            method_pass = node.get("uuid_or_password", "").split(":", 1)
            return {
                "type": "shadowsocks",
                "tag": tag,
                "server": node.get("address"),
                "server_port": node.get("port"),
                "method": method_pass[0] if method_pass else "aes-256-gcm",
                "password": method_pass[1] if len(method_pass) > 1 else ""
            }
        
        return None
    
    def _get_transport(self, node: dict) -> Optional[dict]:
        """獲取傳輸層配置"""
        network = node.get("network", "tcp")
        
        if network == "ws":
            return {
                "type": "ws",
                "path": node.get("path", "/"),
                "headers": {"Host": node.get("host", "")} if node.get("host") else None
            }
        elif network == "grpc":
            return {
                "type": "grpc",
                "service_name": node.get("path", "")
            }
        
        return None
    
    def _get_tls(self, node: dict) -> dict:
        """獲取 TLS 配置"""
        return {
            "enabled": True,
            "server_name": node.get("sni") or node.get("host") or node.get("address"),
            "insecure": True
        }
    
    def node_to_clash_proxy(self, node: dict) -> Optional[dict]:
        """將節點轉換為 Clash proxy"""
        protocol = node.get("protocol", "")
        name = node.get("name") or f"{node.get('address')}:{node.get('port')}"
        
        if protocol == "vmess":
            proxy = {
                "name": name,
                "type": "vmess",
                "server": node.get("address"),
                "port": node.get("port"),
                "uuid": node.get("uuid_or_password"),
                "alterId": 0,
                "cipher": "auto",
            }
            
            network = node.get("network", "tcp")
            if network == "ws":
                proxy["network"] = "ws"
                proxy["ws-opts"] = {
                    "path": node.get("path", "/"),
                    "headers": {"Host": node.get("host", "")} if node.get("host") else {}
                }
            
            if node.get("tls"):
                proxy["tls"] = True
                proxy["servername"] = node.get("sni") or node.get("host") or ""
                proxy["skip-cert-verify"] = True
            
            return proxy
        
        elif protocol == "vless":
            proxy = {
                "name": name,
                "type": "vless",
                "server": node.get("address"),
                "port": node.get("port"),
                "uuid": node.get("uuid_or_password"),
            }
            
            network = node.get("network", "tcp")
            if network == "ws":
                proxy["network"] = "ws"
                proxy["ws-opts"] = {
                    "path": node.get("path", "/"),
                    "headers": {"Host": node.get("host", "")} if node.get("host") else {}
                }
            
            if node.get("tls"):
                proxy["tls"] = True
                proxy["servername"] = node.get("sni") or ""
                proxy["skip-cert-verify"] = True
            
            return proxy
        
        elif protocol == "trojan":
            return {
                "name": name,
                "type": "trojan",
                "server": node.get("address"),
                "port": node.get("port"),
                "password": node.get("uuid_or_password"),
                "sni": node.get("sni") or "",
                "skip-cert-verify": True
            }
        
        elif protocol == "ss":
            method_pass = node.get("uuid_or_password", "").split(":", 1)
            return {
                "name": name,
                "type": "ss",
                "server": node.get("address"),
                "port": node.get("port"),
                "cipher": method_pass[0] if method_pass else "aes-256-gcm",
                "password": method_pass[1] if len(method_pass) > 1 else ""
            }
        
        return None
    
    def node_to_uri(self, node: dict) -> Optional[str]:
        """將節點轉換為 URI"""
        protocol = node.get("protocol", "")
        
        if protocol == "vmess":
            config = {
                "v": "2",
                "ps": node.get("name", ""),
                "add": node.get("address"),
                "port": str(node.get("port")),
                "id": node.get("uuid_or_password"),
                "aid": "0",
                "net": node.get("network", "tcp"),
                "type": "none",
                "host": node.get("host", ""),
                "path": node.get("path", ""),
                "tls": "tls" if node.get("tls") else "",
                "sni": node.get("sni", "")
            }
            encoded = base64.b64encode(json.dumps(config).encode()).decode()
            return f"vmess://{encoded}"
        
        elif protocol == "vless":
            params = []
            if node.get("network") and node["network"] != "tcp":
                params.append(f"type={node['network']}")
            if node.get("tls"):
                params.append("security=tls")
            if node.get("sni"):
                params.append(f"sni={node['sni']}")
            if node.get("path"):
                params.append(f"path={quote(node['path'])}")
            if node.get("host"):
                params.append(f"host={node['host']}")
            
            param_str = "&".join(params) if params else ""
            name = quote(node.get("name", ""))
            
            return f"vless://{node['uuid_or_password']}@{node['address']}:{node['port']}?{param_str}#{name}"
        
        elif protocol == "trojan":
            params = []
            if node.get("sni"):
                params.append(f"sni={node['sni']}")
            
            param_str = "&".join(params) if params else ""
            name = quote(node.get("name", ""))
            
            return f"trojan://{node['uuid_or_password']}@{node['address']}:{node['port']}?{param_str}#{name}"
        
        elif protocol == "ss":
            method_pass = node.get("uuid_or_password", "")
            encoded = base64.b64encode(method_pass.encode()).decode()
            name = quote(node.get("name", ""))
            
            return f"ss://{encoded}@{node['address']}:{node['port']}#{name}"
        
        return None
    
    def generate_singbox_config(self, nodes: list[dict]) -> dict:
        """生成 sing-box 配置"""
        outbounds = []
        proxy_tags = []
        
        for i, node in enumerate(nodes[:self.max_nodes]):
            source = node.get("source", "aggregated")
            prefix = "⭐" if source == "bpb" else "🌐"
            node_name = node.get('name') or "{}:{}".format(node.get("address"), node.get("port"))
            tag = "{} {}".format(prefix, node_name)[:50]
            tag = "{}-{}".format(tag, i)  # 確保唯一
            
            outbound = self.node_to_singbox_outbound(node, tag)
            if outbound:
                # 清理 None 值
                outbound = {k: v for k, v in outbound.items() if v is not None}
                outbounds.append(outbound)
                proxy_tags.append(tag)
        
        # 基礎配置
        config = {
            "log": {"level": "info"},
            "dns": {
                "servers": [
                    {"tag": "google", "address": "8.8.8.8"},
                    {"tag": "local", "address": "223.5.5.5", "detour": "direct"}
                ],
                "rules": [
                    {"outbound": "any", "server": "local"},
                    {"clash_mode": "direct", "server": "local"},
                    {"clash_mode": "global", "server": "google"}
                ]
            },
            "inbounds": [
                {
                    "type": "mixed",
                    "tag": "mixed-in",
                    "listen": "127.0.0.1",
                    "listen_port": 7890
                }
            ],
            "outbounds": [
                {
                    "type": "selector",
                    "tag": "proxy",
                    "outbounds": ["auto"] + proxy_tags,
                    "default": "auto"
                },
                {
                    "type": "urltest",
                    "tag": "auto",
                    "outbounds": proxy_tags,
                    "url": "https://www.gstatic.com/generate_204",
                    "interval": "5m"
                },
                *outbounds,
                {"type": "direct", "tag": "direct"},
                {"type": "block", "tag": "block"},
                {"type": "dns", "tag": "dns-out"}
            ],
            "route": {
                "rules": [
                    {"protocol": "dns", "outbound": "dns-out"},
                    {"clash_mode": "direct", "outbound": "direct"},
                    {"clash_mode": "global", "outbound": "proxy"},
                    {"geoip": ["cn", "private"], "outbound": "direct"},
                    {"geosite": "cn", "outbound": "direct"}
                ],
                "final": "proxy"
            },
            "experimental": {
                "clash_api": {
                    "external_controller": "127.0.0.1:9090",
                    "secret": ""
                }
            }
        }
        
        return config
    
    def generate_clash_config(self, nodes: list[dict]) -> dict:
        """生成 Clash 配置"""
        proxies = []
        proxy_names = []
        
        for i, node in enumerate(nodes[:self.max_nodes]):
            proxy = self.node_to_clash_proxy(node)
            if proxy:
                # 確保名稱唯一
                base_name = proxy["name"]
                proxy["name"] = f"{base_name}-{i}"
                proxies.append(proxy)
                proxy_names.append(proxy["name"])
        
        config = {
            "mixed-port": 7890,
            "allow-lan": False,
            "mode": "rule",
            "log-level": "info",
            "external-controller": "127.0.0.1:9090",
            "dns": {
                "enable": True,
                "enhanced-mode": "fake-ip",
                "nameserver": ["8.8.8.8", "1.1.1.1"],
                "fallback": ["https://dns.google/dns-query"]
            },
            "proxies": proxies,
            "proxy-groups": [
                {
                    "name": "🚀 Proxy",
                    "type": "select",
                    "proxies": ["⚡ Auto"] + proxy_names + ["DIRECT"]
                },
                {
                    "name": "⚡ Auto",
                    "type": "url-test",
                    "proxies": proxy_names,
                    "url": "https://www.gstatic.com/generate_204",
                    "interval": 300
                }
            ],
            "rules": [
                "GEOIP,CN,DIRECT",
                "MATCH,🚀 Proxy"
            ]
        }
        
        return config
    
    def generate_base64(self, nodes: list[dict]) -> str:
        """生成 Base64 訂閱"""
        uris = []
        
        for node in nodes[:self.max_nodes]:
            uri = self.node_to_uri(node)
            if uri:
                uris.append(uri)
        
        content = "\n".join(uris)
        return base64.b64encode(content.encode()).decode()
    
    async def merge_and_generate(self):
        """合併並生成所有格式"""
        print("🦐 開始合併訂閱...\n")
        
        # 載入測試通過的節點
        nodes = []
        try:
            with open("output/tested_nodes.json", 'r') as f:
                data = json.load(f)
                nodes = data.get("nodes", [])
        except FileNotFoundError:
            print("⚠ 未找到測試後的節點，使用原始節點")
            try:
                with open("output/raw_nodes.json", 'r') as f:
                    data = json.load(f)
                    nodes = data.get("nodes", [])
            except:
                pass
        
        # 獲取 BPB Panel 訂閱
        bpb_nodes = await self.fetch_bpb_subscription()
        
        # 合併節點（BPB 優先）
        all_nodes = bpb_nodes + nodes
        
        # 按優先級和延遲排序
        all_nodes.sort(key=lambda x: (
            x.get("priority", 99),
            x.get("test_result", {}).get("latency_ms", 9999)
        ))
        
        print(f"\n合併後共 {len(all_nodes)} 個節點")
        
        # 生成各種格式
        output_dir = Path("output")
        output_dir.mkdir(exist_ok=True)
        
        formats = self.output_config.get("formats", ["singbox", "clash", "base64"])
        
        if "singbox" in formats:
            singbox_config = self.generate_singbox_config(all_nodes)
            with open(output_dir / "singbox.json", 'w') as f:
                json.dump(singbox_config, f, ensure_ascii=False, indent=2)
            print("✓ 已生成 singbox.json")
        
        if "clash" in formats:
            clash_config = self.generate_clash_config(all_nodes)
            with open(output_dir / "clash.yaml", 'w') as f:
                yaml.dump(clash_config, f, allow_unicode=True, default_flow_style=False)
            print("✓ 已生成 clash.yaml")
        
        if "base64" in formats:
            base64_content = self.generate_base64(all_nodes)
            with open(output_dir / "base64.txt", 'w') as f:
                f.write(base64_content)
            print("✓ 已生成 base64.txt")
        
        # 生成索引文件
        index = {
            "name": "Proxy Aggregator Subscription",
            "updated": datetime.utcnow().isoformat() + "Z",
            "node_count": len(all_nodes),
            "subscriptions": {
                "singbox": "singbox.json",
                "clash": "clash.yaml",
                "base64": "base64.txt"
            }
        }
        
        with open(output_dir / "index.json", 'w') as f:
            json.dump(index, f, ensure_ascii=False, indent=2)
        
        print("\n✅ 訂閱生成完成！")


async def main():
    merger = SubscriptionMerger()
    await merger.merge_and_generate()


if __name__ == "__main__":
    asyncio.run(main())
