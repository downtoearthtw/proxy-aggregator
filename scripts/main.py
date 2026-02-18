#!/usr/bin/env python3
"""
主程序 - 執行完整的聚合流程
"""

import asyncio
import sys
import os

# 添加當前目錄到路徑
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


async def main():
    print("=" * 60)
    print("🦐 Proxy Aggregator - 代理節點聚合器")
    print("=" * 60)
    print()
    
    # Step 1: 聚合節點
    print("📥 Step 1/3: 聚合節點")
    print("-" * 40)
    from aggregate import NodeAggregator
    aggregator = NodeAggregator()
    nodes = await aggregator.aggregate()
    aggregator.save_nodes(nodes)
    print()
    
    # Step 2: 測試節點
    print("🔬 Step 2/3: 測試節點")
    print("-" * 40)
    from test_nodes import NodeTester
    tester = NodeTester()
    passed_nodes = await tester.test_all([n.__dict__ if hasattr(n, '__dict__') else n for n in nodes])
    tester.save_results(passed_nodes)
    print()
    
    # Step 3: 生成訂閱
    print("📤 Step 3/3: 生成訂閱")
    print("-" * 40)
    from merge_subs import SubscriptionMerger
    merger = SubscriptionMerger()
    await merger.merge_and_generate()
    print()
    
    print("=" * 60)
    print("✅ 全部完成！")
    print("=" * 60)
    print()
    print("📂 輸出檔案位於 output/ 目錄:")
    print("   - singbox.json  (Sing-box / Karing)")
    print("   - clash.yaml    (Clash / Mihomo)")
    print("   - base64.txt    (通用 Base64)")
    print()


if __name__ == "__main__":
    asyncio.run(main())
