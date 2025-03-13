# letta-py-proxy

Proxy for Letta server and support for streaming. Currently, Letta supports streaming for Anthropic, Deepseek, and OpenAI models.

Pair-programmed with CoPilot to learn about proxying streams.

# Install

```
git clone https://github.com/thedunston/letta-py-proxy
cd letta-py-proxy
pip install -r requirements.txt
```

then run:

```
python pproxy.py -h
```

The default is to listen on all interfaces on port 8284 and forward to `http://localhost:8283/v1`.

# Usage

Point your letta application to the proxy server. For example, the default would be ```http://localhost:8284```.
