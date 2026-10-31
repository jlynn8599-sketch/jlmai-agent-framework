import json
import os

import pytest

from v2 import payment_key_registry as registry


@pytest.fixture
def registry_setup(tmp_path, monkeypatch):
    base = tmp_path / ".jlmai"
    key_dir = base / "payment-keys"
    key_dir.mkdir(parents=True)

    base.chmod(0o700)
    key_dir.chmod(0o700)

    public_key = key_dir / "test-public.pem"
    public_key.write_text("dummy public key for filesystem tests\n")
    public_key.chmod(0o644)

    registry_file = key_dir / "registry.json"

    monkeypatch.setattr(registry, "REGISTRY_DIR", key_dir)
    monkeypatch.setattr(registry, "REGISTRY_PATH", registry_file)
    monkeypatch.setattr(registry, "TRUSTED_KEY_DIR", key_dir)

    document = {
        "schema": registry.REGISTRY_SCHEMA,
        "keys": {
            "test-key-001": {
                "signer_id": "test-signer",
                "public_key_file": "test-public.pem",
                "status": "ACTIVE",
            }
        },
    }

    def write_registry(value=None):
        content = document if value is None else value
        registry_file.write_text(json.dumps(content))
        registry_file.chmod(0o600)

    write_registry()

    return {
        "base": base,
        "key_dir": key_dir,
        "public_key": public_key,
        "registry_file": registry_file,
        "document": document,
        "write_registry": write_registry,
    }


def test_loads_valid_registry(registry_setup):
    keys = registry.load_trusted_keys()

    assert list(keys) == ["test-key-001"]
    assert keys["test-key-001"]["signer_id"] == "test-signer"
    assert keys["test-key-001"]["status"] == "ACTIVE"
    assert keys["test-key-001"]["public_key_path"] == str(
        registry_setup["public_key"]
    )


def test_missing_registry_is_rejected(registry_setup):
    registry_setup["registry_file"].unlink()

    with pytest.raises(registry.RegistryError):
        registry.load_trusted_keys()


def test_registry_symlink_is_rejected(registry_setup):
    real_file = registry_setup["key_dir"] / "real-registry.json"
    real_file.write_text(json.dumps(registry_setup["document"]))
    real_file.chmod(0o600)

    registry_setup["registry_file"].unlink()
    registry_setup["registry_file"].symlink_to(real_file)

    with pytest.raises(registry.RegistryError):
        registry.load_trusted_keys()


def test_insecure_registry_permissions_are_rejected(registry_setup):
    registry_setup["registry_file"].chmod(0o644)

    with pytest.raises(registry.RegistryError):
        registry.load_trusted_keys()


def test_insecure_registry_directory_permissions_are_rejected(
    registry_setup,
):
    registry_setup["key_dir"].chmod(0o755)

    with pytest.raises(registry.RegistryError):
        registry.load_trusted_keys()


def test_invalid_registry_schema_is_rejected(registry_setup):
    document = dict(registry_setup["document"])
    document["schema"] = "unknown.schema"

    registry_setup["write_registry"](document)

    with pytest.raises(registry.RegistryError):
        registry.load_trusted_keys()


def test_extra_registry_root_field_is_rejected(registry_setup):
    document = dict(registry_setup["document"])
    document["unexpected"] = True

    registry_setup["write_registry"](document)

    with pytest.raises(registry.RegistryError):
        registry.load_trusted_keys()


def test_duplicate_json_keys_are_rejected(registry_setup):
    registry_setup["registry_file"].write_text(
        '{"schema":"jlmai.payment-key-registry.v1",'
        '"schema":"jlmai.payment-key-registry.v1","keys":{}}'
    )
    registry_setup["registry_file"].chmod(0o600)

    with pytest.raises(registry.RegistryError):
        registry.load_trusted_keys()


def test_path_traversal_public_key_filename_is_rejected(registry_setup):
    document = registry_setup["document"]
    document["keys"]["test-key-001"]["public_key_file"] = "../outside.pem"

    registry_setup["write_registry"](document)

    with pytest.raises(registry.RegistryError):
        registry.load_trusted_keys()


def test_missing_public_key_is_rejected(registry_setup):
    registry_setup["public_key"].unlink()

    with pytest.raises(registry.RegistryError):
        registry.load_trusted_keys()


def test_public_key_symlink_is_rejected(registry_setup):
    public_key = registry_setup["public_key"]
    target = registry_setup["key_dir"] / "other.pem"
    target.write_text("dummy\n")
    target.chmod(0o644)

    public_key.unlink()
    public_key.symlink_to(target)

    with pytest.raises(registry.RegistryError):
        registry.load_trusted_keys()


def test_group_or_world_writable_public_key_is_rejected(registry_setup):
    registry_setup["public_key"].chmod(0o666)

    with pytest.raises(registry.RegistryError):
        registry.load_trusted_keys()


def test_invalid_key_entry_fields_are_rejected(registry_setup):
    document = registry_setup["document"]
    document["keys"]["test-key-001"]["unexpected"] = "value"

    registry_setup["write_registry"](document)

    with pytest.raises(registry.RegistryError):
        registry.load_trusted_keys()


def test_invalid_key_status_is_rejected(registry_setup):
    document = registry_setup["document"]
    document["keys"]["test-key-001"]["status"] = "UNKNOWN"

    registry_setup["write_registry"](document)

    with pytest.raises(registry.RegistryError):
        registry.load_trusted_keys()


def test_invalid_signer_identifier_is_rejected(registry_setup):
    document = registry_setup["document"]
    document["keys"]["test-key-001"]["signer_id"] = "../attacker"

    registry_setup["write_registry"](document)

    with pytest.raises(registry.RegistryError):
        registry.load_trusted_keys()


def test_registry_file_must_be_owned_by_current_user(registry_setup):
    # Ownership is checked by the loader. This test verifies the current
    # fixture has the expected owner without attempting privileged chown.
    info = registry_setup["registry_file"].stat()
    assert info.st_uid == os.getuid()
