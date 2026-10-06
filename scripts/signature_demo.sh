#!/usr/bin/env bash
# 字节特征定位接口的端到端演示（需先 docker compose up 启动服务）。
# 输出与 README 第 4.7 节一致的真实请求/响应。
set -eu
BASE="${BASE:-http://localhost:8000}"
SID="sig-demo"

b64() { printf '%s' "$1" | base64 | tr -d '\n'; }

post() { curl -s -w '\n[HTTP %{http_code}]\n' -X POST "$BASE$1" \
  -H 'Content-Type: application/json' -d "$2"; }

# 清理旧会话（忽略不存在）
curl -s -X POST "$BASE/sessions" -H 'Content-Type: application/json' \
  -d "{\"session_id\":\"$SID\"}" >/dev/null

# ISN=7000：capture=10 上报 [1,8)="ABCDEFGH"；更晚捕获的 capture=20 覆盖
# 偏移 1 的 "A"（内容相同，earliest 归 cap=10；latest 归 cap=20），
# 扫描线把流切成两个相邻 run：[1,2) 与 [2,9)。
post "/sessions/$SID/directions/c2s/packets" "{\"packets\":[
  {\"capture\":1,\"seq\":7000,\"syn\":true},
  {\"capture\":10,\"seq\":7001,\"payload\":\"$(b64 ABCDEFGH)\"},
  {\"capture\":20,\"seq\":7001,\"payload\":\"$(b64 A)\"}]}"

post "/sessions/$SID/directions/c2s/revisions" '{"expected_revision":0}'

# 模式 "AB" 横跨两个相邻 run：A 在 [1,2)，B 在 [2,9)
echo '--- 跨 run 命中 AB（category=both）---'
post "/sessions/$SID/directions/c2s/signature-search" "{
  \"session_id\":\"$SID\",\"direction\":\"c2s\",\"revision\":1,
  \"pattern_base64\":\"$(b64 AB)\",\"offset\":1,\"limit\":100}"

# 更晚到达但 capture 更小（=5）的报文覆盖偏移 1..8，发布修订 2
post "/sessions/$SID/directions/c2s/packets" "{\"packets\":[
  {\"capture\":5,\"seq\":7001,\"payload\":\"$(b64 ZZZZZZZZ)\"}]}"
post "/sessions/$SID/directions/c2s/revisions" '{"expected_revision":1}'

echo '--- 修订 1 命中不变（仍 both）---'
post "/sessions/$SID/directions/c2s/signature-search" "{
  \"session_id\":\"$SID\",\"direction\":\"c2s\",\"revision\":1,
  \"pattern_base64\":\"$(b64 AB)\"}"

echo '--- 修订 2：AB 只存在于 latest 流（earliest 已被 cap=5 翻转）---'
post "/sessions/$SID/directions/c2s/signature-search" "{
  \"session_id\":\"$SID\",\"direction\":\"c2s\",\"revision\":2,
  \"pattern_base64\":\"$(b64 AB)\"}"
