#!/usr/bin/env python3
"""
ZAP Python Client Example

This example demonstrates connecting to a ZAP gateway and using
the MCP operations: tools, resources, and prompts.

Run with: python examples/python/main.py
"""

import asyncio
from zap_proto import Client, Gateway


async def main():
    """Main example demonstrating ZAP client usage."""
    print("ZAP Chat Client Example (Python)")
    print("=================================\n")

    # Connect to the ZAP gateway
    client = await Client.connect("zap://localhost:9999")
    print("Connected to ZAP gateway\n")

    # Initialize the connection
    server_info = await client.init()
    print(f"Server: {server_info.name} v{server_info.version}")
    print(f"Protocol: {server_info.protocol_version}\n")

    # List available tools
    print("Available Tools:")
    print("----------------")
    tools = await client.list_tools()
    for tool in tools:
        print(f"  {tool.name} - {tool.description}")
    print()

    # Call a tool
    print("Calling 'search' tool...")
    result = await client.call_tool("search", {
        "query": "python programming",
        "limit": 5
    })

    if result.is_error:
        print(f"Tool error: {result.error}")
    else:
        print("Search results:")
        for content in result.content:
            print(f"  - {content.text}")
    print()

    # List resources
    print("Available Resources:")
    print("--------------------")
    resources = await client.list_resources()
    for resource in resources:
        print(f"  {resource.uri} - {resource.name}")
    print()

    # Read a resource
    print("Reading config resource...")
    content = await client.read_resource("file:///etc/zap/config.json")
    print(f"Config: {content.text}\n")

    # List prompts
    print("Available Prompts:")
    print("------------------")
    prompts = await client.list_prompts()
    for prompt in prompts:
        desc = prompt.description or ""
        print(f"  {prompt.name} - {desc}")
    print()

    # Get a prompt
    print("Getting 'code-review' prompt...")
    messages = await client.get_prompt("code-review", {
        "language": "python",
        "file": "main.py"
    })

    print("Prompt messages:")
    for msg in messages:
        preview = msg.content[:50] if len(msg.content) > 50 else msg.content
        print(f"  [{msg.role}] {preview}...")

    print("\nDone!")


async def gateway_example():
    """Example: Running a ZAP gateway."""
    print("Starting ZAP Gateway...")

    gateway = Gateway(host="0.0.0.0", port=9999)

    # Add MCP servers
    gateway.add_server(
        "filesystem",
        "stdio://npx @modelcontextprotocol/server-filesystem /data"
    )
    gateway.add_server(
        "database",
        "http://localhost:8080/mcp"
    )
    gateway.add_server(
        "search",
        "ws://localhost:9000/ws"
    )

    print("Gateway configured with 3 MCP servers")
    print("Starting on port 9999...")

    await gateway.start()


async def pq_crypto_example():
    """Example: Using post-quantum cryptography."""
    from hanzo_zap.crypto import MLKem, MLDsa

    print("Post-Quantum Cryptography Example")
    print("==================================\n")

    # ML-KEM key encapsulation
    print("ML-KEM-768 Key Encapsulation:")
    pk, sk = MLKem.generate_keypair()
    print(f"  Public key: {len(pk)} bytes")
    print(f"  Secret key: {len(sk)} bytes")

    ciphertext, shared_secret = MLKem.encapsulate(pk)
    print(f"  Ciphertext: {len(ciphertext)} bytes")
    print(f"  Shared secret: {len(shared_secret)} bytes")

    decrypted = MLKem.decapsulate(ciphertext, sk)
    assert shared_secret == decrypted
    print("  Decapsulation: SUCCESS\n")

    # ML-DSA digital signatures
    print("ML-DSA-65 Digital Signatures:")
    pk, sk = MLDsa.generate_keypair()
    print(f"  Public key: {len(pk)} bytes")
    print(f"  Secret key: {len(sk)} bytes")

    message = b"Hello, ZAP!"
    signature = MLDsa.sign(message, sk)
    print(f"  Signature: {len(signature)} bytes")

    is_valid = MLDsa.verify(message, signature, pk)
    print(f"  Verification: {'SUCCESS' if is_valid else 'FAILED'}")


async def identity_example():
    """Example: Using decentralized identity."""
    from hanzo_zap.identity import NodeIdentity, Did

    print("Decentralized Identity Example")
    print("==============================\n")

    # Generate a new identity
    identity = NodeIdentity.generate()
    print(f"Generated DID: {identity.did}")
    print(f"Public key: {identity.public_key[:32].hex()}...")

    # Sign a message
    message = b"Hello from ZAP!"
    signature = identity.sign(message)
    print(f"Signature: {signature[:32].hex()}...")

    # Verify the signature
    is_valid = identity.verify(message, signature)
    print(f"Verification: {'SUCCESS' if is_valid else 'FAILED'}")


async def consensus_example():
    """Example: Agent consensus."""
    from hanzo_zap.consensus import AgentConsensus

    print("Agent Consensus Example")
    print("=======================\n")

    # Create consensus with 67% threshold
    consensus = AgentConsensus(threshold=0.67)
    print("Created consensus with 67% threshold")

    # Simulate agent responses
    agents = [
        ("did:key:agent1", "The answer is 42"),
        ("did:key:agent2", "The answer is 42"),
        ("did:key:agent3", "The answer is 41"),
    ]

    print("\nSubmitting agent responses:")
    for did, response in agents:
        await consensus.submit_response(did, response)
        print(f"  {did}: '{response}'")

    # Check for consensus
    result = await consensus.finalize()
    print(f"\nConsensus reached: {result.reached}")
    if result.reached:
        print(f"Final answer: {result.response}")
        print(f"Agreement: {result.agreement * 100:.1f}%")


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        example = sys.argv[1]
        if example == "gateway":
            asyncio.run(gateway_example())
        elif example == "crypto":
            asyncio.run(pq_crypto_example())
        elif example == "identity":
            asyncio.run(identity_example())
        elif example == "consensus":
            asyncio.run(consensus_example())
        else:
            print(f"Unknown example: {example}")
            print("Available: gateway, crypto, identity, consensus")
    else:
        asyncio.run(main())
