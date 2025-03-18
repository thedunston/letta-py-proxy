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

## Authorization

Add the flag ```--require-tokens``` to use Authorization Headers with `pproxy.py`. ```example: Authorization efd02f2aad505d20fe1635f0a1fd6872```

Tokens can be generated and managed with `manage_tokens.py`.

```
python3 manage_tokens.py -h
usage: manage_tokens.py [-h] [--create-token CREATE_TOKEN] [--list-tokens] [--delete-token DELETE_TOKEN]
                        [--add-proxy-server ADD_PROXY_SERVER] [--list-proxy-servers]
                        [--delete-proxy-server DELETE_PROXY_SERVER]

Token Management Script

options:
  -h, --help            show this help message and exit
  --create-token CREATE_TOKEN, -ct CREATE_TOKEN
                        Create a new token with the specified name
  --list-tokens, -lt    List all tokens in the database
  --delete-token DELETE_TOKEN, -dt DELETE_TOKEN
                        Delete a token by name
  --add-proxy-server ADD_PROXY_SERVER, -ap ADD_PROXY_SERVER
                        Add a proxy server to the database
  --list-proxy-servers, -lp
                        List all proxy servers in the database
  --delete-proxy-server DELETE_PROXY_SERVER, -dp DELET
```
Create a token for duane

```
python manage_tokens.py -ct duane
Token with name 'duane' deleted successfully.
```

You'll need to add the `letta-py-proxy` URL so it can refresh tokens loaded in-memory when a token is deleted for changes to take effect immediately.

```
Token with name 'duane' deleted successfully.
1. http://localhost:8284
Enter the number of the proxy server to delete: 1
*** Tokens reloaded successfully ***```
