import time

from agent_soc_manager.tools.chatops.security import (
    generate_signed_payload,
    verify_signed_payload,
)


def test_security():
    payload = {"session_id": "test_session", "action": "block"}
    print(f"Original payload: {payload}")

    # Test signing
    token = generate_signed_payload(payload, ttl=10)
    print(f"Generated token: {token}")

    # Test verification
    verified = verify_signed_payload(token)
    print(f"Verified payload: {verified}")

    assert verified["session_id"] == "test_session"
    assert "exp" in verified

    # Test expiration
    print("Testing expiration (waiting 2 seconds)...")
    token_short = generate_signed_payload(payload, ttl=1)
    time.sleep(2)
    try:
        verify_signed_payload(token_short)
        print("FAILED: Token should have expired")
    except ValueError as e:
        print(f"SUCCESS: Caught expected error: {e}")

    # Test tampering
    print("Testing tampering...")
    payload_part, sig_part = token.split(".")
    tampered_token = payload_part + ".fake_signature"
    try:
        verify_signed_payload(tampered_token)
        print("FAILED: Tampered token should be rejected")
    except ValueError as e:
        print(f"SUCCESS: Caught expected error: {e}")


if __name__ == "__main__":
    test_security()
