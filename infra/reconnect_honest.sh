#!/bin/bash
# Reconnecte la victime (node2) aux nœuds honnêtes après un run Eclipse.
rpc() { curl -s -X POST -H "Content-Type: application/json" --data "$2" "http://127.0.0.1:$1"; }
get_enode() {
  rpc "$1" '{"jsonrpc":"2.0","method":"admin_nodeInfo","params":[],"id":1}' \
    | jq -r .result.enode 2>/dev/null | sed 's/@[^:]*:/@127.0.0.1:/; s/?.*//'
}
for port in 8545 8547 8548 8549; do
  E=$(get_enode "$port")
  [[ "$E" == enode://* ]] && rpc 8546 "{\"jsonrpc\":\"2.0\",\"method\":\"admin_addPeer\",\"params\":[\"$E\"],\"id\":1}" > /dev/null
done
sleep 3
echo "Pairs de la victime après reconnexion :"
rpc 8546 '{"jsonrpc":"2.0","method":"net_peerCount","params":[],"id":1}'
