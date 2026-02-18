# 🦐 Proxy Aggregator

自動聚合代理節點 + BPB Panel 同步 + 中國連通測試 + 多格式訂閱輸出

## ✨ 功能

- ✅ 自動同步 BPB Panel 上游更新
- ✅ 聚合多個公開節點來源
- ✅ 中國連通性測試（TCP + TLS + 延遲）
- ✅ IP 純淨度檢測（避免被封鎖的 IP）
- ✅ 輸出 Sing-box / Clash / V2ray 訂閱格式
- ✅ 每日自動更新（GitHub Actions）
- ✅ GitHub Pages 托管訂閱

---

## 🚀 快速部署

### 步驟 1：部署 BPB Panel（10 分鐘）

1. 前往 [BPB Wizard Releases](https://github.com/bia-pain-bache/BPB-Wizard/releases/latest)
2. 下載對應系統的版本並執行
3. 登入 Cloudflare 帳號（Downtoearth.tw@gmail.com）
4. 按提示完成部署
5. 記下你的 **Panel URL** 和 **訂閱連結**

### 步驟 2：Fork 本倉庫

1. 點擊本頁面右上角的 **Fork** 按鈕
2. 創建到你的 GitHub 帳號下

### 步驟 3：配置 Secrets

在你 Fork 的倉庫中：
1. 進入 **Settings** → **Secrets and variables** → **Actions**
2. 添加以下 Secret（可選）：
   - `CF_DEPLOY_HOOK`: Cloudflare Pages Deploy Hook URL（用於自動重建）

### 步驟 4：配置 BPB 訂閱

編輯 `config/sources.json`，填入你的 BPB Panel 訂閱 URL：

```json
{
  "bpb_panel": {
    "enabled": true,
    "subscription_url": "https://你的worker.你的域名.workers.dev/你的路徑/sub",
    "priority": 0
  }
}
```

### 步驟 5：啟用 GitHub Pages

1. 進入 **Settings** → **Pages**
2. Source 選擇 **Deploy from a branch**
3. Branch 選擇 **gh-pages** / **root**
4. 點擊 **Save**

### 步驟 6：手動觸發首次運行

1. 進入 **Actions** → **Aggregate Nodes**
2. 點擊 **Run workflow**
3. 等待完成（約 5-10 分鐘）

---

## 📱 使用訂閱

部署完成後，你的訂閱連結為：

| 格式 | URL | 適用客戶端 |
|------|-----|-----------|
| **Sing-box** | `https://你的用戶名.github.io/proxy-aggregator/singbox.json` | Karing, Sing-box |
| **Clash** | `https://你的用戶名.github.io/proxy-aggregator/clash.yaml` | Clash, Mihomo, Stash |
| **Base64** | `https://你的用戶名.github.io/proxy-aggregator/base64.txt` | V2rayN, V2rayNG |

---

## 📂 項目結構

```
proxy-aggregator/
├── .github/workflows/
│   ├── sync-bpb.yml        # 同步 BPB Panel 上游
│   └── aggregate.yml       # 每日節點聚合
├── scripts/
│   ├── main.py             # 主程序
│   ├── aggregate.py        # 節點收集
│   ├── test_nodes.py       # 連通測試
│   └── merge_subs.py       # 訂閱合併
├── config/
│   ├── sources.json        # 節點來源配置
│   └── settings.json       # 全局設定
├── output/                  # 生成的訂閱文件
│   ├── singbox.json
│   ├── clash.yaml
│   └── base64.txt
├── requirements.txt
└── README.md
```

---

## ⚙️ 配置說明

### sources.json - 節點來源

```json
{
  "sources": [
    {
      "name": "來源名稱",
      "url": "訂閱 URL",
      "type": "base64|clash|mixed",
      "enabled": true,
      "priority": 1  // 數字越小優先級越高
    }
  ],
  "bpb_panel": {
    "enabled": true,
    "subscription_url": "你的 BPB 訂閱 URL",
    "priority": 0  // BPB 最高優先級
  }
}
```

### settings.json - 測試設定

```json
{
  "testing": {
    "timeout_seconds": 10,      // 連接超時
    "max_concurrent": 50,       // 並發測試數
    "ip_purity": {
      "enabled": true,          // 啟用 IP 純淨度檢測
      "min_trust_score": 30     // 最低信任分數 (0-100)
    }
  },
  "output": {
    "max_nodes": 200            // 最大輸出節點數
  }
}
```

---

## 🔄 自動更新機制

| 任務 | 時間 | 說明 |
|------|------|------|
| BPB Panel 同步 | 每天 UTC 0:00 | 檢查上游更新 |
| 節點聚合 | 每天 UTC 6:00 (台灣 14:00) | 收集 + 測試 + 生成 |

你也可以隨時在 **Actions** 頁面手動觸發。

---

## 🔧 本地運行

```bash
# 安裝依賴
pip install -r requirements.txt

# 運行完整流程
cd scripts
python main.py
```

---

## ⚠️ 注意事項

1. **隱私**: BPB Panel 訂閱 URL 包含你的私人配置，請勿公開分享
2. **頻率**: 免費 GitHub Actions 每月有使用限制，每日一次是安全的
3. **節點來源**: 公開節點的穩定性和安全性無法保證，BPB Panel 節點優先使用
4. **IP 純淨度**: 測試使用 ip-api.com，有速率限制，大量節點時可能部分跳過

---

## 📜 License

MIT

---

Made with 🦐 by Proxy Aggregator
