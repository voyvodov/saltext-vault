"""
Manage the Vault PKI secret engine.
.. important::
    This module requires the general :ref:`Vault setup <vault-setup>`.
"""

import logging
from datetime import datetime
from datetime import timezone
from cryptography.hazmat.primitives import hashes, serialization

import saltext.vault.utils.vault as vault
from salt.exceptions import CommandExecutionError
from salt.exceptions import SaltInvocationError
import salt.utils.x509 as x509util


# import debugpy

# # Allow other computers to attach to debugpy at this IP address and port.
# debugpy.listen(('0.0.0.0', 5678))

# # Pause the program until a remote debugger is attached
# debugpy.wait_for_client()

log = logging.getLogger(__name__)

def list_roles(mount='pki'):
    """
    List configured PKI roles.


    CLI Example:
    
    .. code-block:: bash

            salt '*' vault_pki.list_roles
    
    mount
        The mount path the DB backend is mounted to. Defaults to ``pki``.
    """
    endpoint = f"{mount}/roles"
    try:
        return vault.query("LIST", endpoint, __opts__, __context__)["data"]["keys"]
    except vault.VaultNotFoundError:
        return []
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err

def read_role(name, mount='pki'):
    """
    Get configuration of specific PKI role.


    CLI Example:
    
    .. code-block:: bash

            salt '*' vault_pki.read_role
    
    name
        The name of the role.

    mount
        The mount path the DB backend is mounted to. Defaults to ``pki``.
    """
    
    endpoint = f"{mount}/roles/{name}"
    try:
        res = vault.query("GET", endpoint, __opts__, __context__)
        if isinstance(res , dict):
            return res["data"]
        return False
    except vault.VaultNotFoundError:
        return None
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err
    
def write_role(
    name,
    mount="pki",
    issuer=None,
    ttl=None,
    max_ttl=None,
    allow_localhost=None,
    allowed_domains=None,
    server_flag=None,
    client_flag=None,
    key_usage=None,
    no_store=None,
    require_cn=None,
    cn_validations=None,
    **kwargs
):
    args = locals()
    endpoint = f"{mount}/roles/{name}"
    
    method = "POST"
    headers = {}

    
    if read_role(name, mount=mount) is not None:
        method = "PATCH"
        headers = {
            "Content-Type": "application/merge-patch+json"
        }

    payload = {k: v for k, v in kwargs.items() if not k.startswith("_")}

    for k,v in args.items():
        if k not in ["name", "mount", "kwargs"]:
            if v is not None:
                payload[k] = v


    for m in [method, "POST"]:
        try:
            vault.query(m, endpoint, __opts__, __context__, payload=payload, add_headers=headers)
            return True
        except vault.VaultUnsupportedOperationError:
            continue  
        except vault.VaultException as err:
            raise CommandExecutionError(f"{err.__class__}: {err}") from err

def delete_role(
    name,
    mount="pki"
):
    endpoint = f"{mount}/roles/{name}"

    try:
        vault.query("DELETE", endpoint, __opts__, __context__)
        return True
    except vault.VaultNotFoundError:
        return False
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err

def list_issuers(mount='pki'):
    endpoint = f"{mount}/issuers"

    try:
        return vault.query("LIST", endpoint, __opts__, __context__)['data']['key_info']
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err

def read_issuer(name, mount='pki'):
    endpoint = f"{mount}/issuer/{name}"

    try:
        return vault.query("GET", endpoint, __opts__, __context__)['data']
    except vault.VaultNotFoundError:
        return None
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err

def read_issuer_certificate(name, mount='pki'):
    certificate = read_issuer(name, mount)

    return certificate["certificate"]


def issue_certificate(
        role_name,
        common_name,
        mount="pki",
        issuer=None,
        alt_names=None,
        ttl=None,
        format="pem",
        exclude_cn_from_sans=False,
        **kwargs
):
    endpoint = f"{mount}/issue/{role_name}"
    if issuer is not None:
        endpoint = f"{mount}/issuer/{issuer}/issue/{role_name}"

    payload = {k: v for k, v in kwargs.items() if not k.startswith("_")}
    payload["common_name"] = common_name
    
    if ttl is not None:
        payload["ttl"] = ttl

    payload["format"] = format
    payload["exclude_cn_from_sans"] = exclude_cn_from_sans

    if alt_names is not None:
        dns_sans, ip_sans, uri_sans, other_sans = _split_sans(alt_names)
        payload["alt_names"] = dns_sans
        payload["ip_sans"] = ip_sans
        payload["uri_sans"] = uri_sans
        payload["other_sans"] = other_sans

    try:
        return vault.query("POST", endpoint, __opts__, __context__, payload=payload)['data']
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err

def sign_certificate(
        role_name,
        common_name,
        mount="pki",
        csr=None,
        private_key=None,
        private_key_passphrase=None,
        digest="sha256",
        issuer=None,
        alt_names=None,
        ttl=None,
        format="pem",
        exclude_cn_from_sans=False,
        **kwargs
):
    if csr is None and private_key is None:
        raise CommandExecutionError("either csr or private_key must be passed.")

    if csr is not None and private_key is not None:
        raise CommandExecutionError("only one of csr or private_key must be passed, not both")

    csr_args, extra_args = _split_csr_kwargs(kwargs)

    endpoint = f"{mount}/sign/{role_name}"
    if issuer is not None:
        endpoint = f"{mount}/issuer/{issuer}/sign/{role_name}"

    payload = {k: v for k, v in extra_args.items() if not k.startswith("_")}

    payload["common_name"] = common_name

    if ttl is not None:
        payload["ttl"] = ttl

    payload["format"] = format
    payload["exclude_cn_from_sans"] = exclude_cn_from_sans

    if alt_names is not None:
        dns_sans, ip_sans, uri_sans, other_sans = _split_sans(alt_names)
        payload["alt_names"] = dns_sans
        payload["ip_sans"] = ip_sans
        payload["uri_sans"] = uri_sans
        payload["other_sans"] = other_sans

    # In case private_key is passed we're going to build
    # CSR in place.
    if private_key is not None:
        if isinstance(alt_names, dict):
            alt_names = [ f"{k}:{v}" for k, v in alt_names.items() ]
        
        if alt_names:
            csr_args["subjectAltName"] = alt_names

        csr = _build_csr(
            private_key=private_key,
            private_key_passphrase=private_key_passphrase,
            digest=digest,
            **csr_args
        )

    payload["csr"] = csr
    

    try:
        return vault.query("POST", endpoint, __opts__, __context__, payload=payload)["data"]
    except vault.VaultException as err:
        raise CommandExecutionError(f"{err.__class__}: {err}") from err

def _split_sans(sans):
    dns_sans = []
    ip_sans = []
    uri_sans = []
    other_sans = []

    if isinstance(sans, list):
        sans = { item.split(":", 1) for item in sans }
    
    for k,v in sans.items():
        if k.upper() == "DNS" or k.upper() == "EMAIL":
            dns_sans.append(v)
        elif k.upper() == "IP":
            ip_sans.append(v)
        elif k.upper() == "URI":
            uri_sans.append(v)
        else:
            other_sans.append(f"{k};UTF8:{v}")
    
    return dns_sans, ip_sans, uri_sans, other_sans


def _build_csr(
        private_key,
        private_key_passphrase=None,
        digest="sha256", 
        **kwargs):
    if digest.lower() not in [
        "sha1",
        "sha224",
        "sha256",
        "sha384",
        "sha512",
        "sha512_224",
        "sha512_256",
        "sha3_224",
        "sha3_256",
        "sha3_384",
        "sha3_512",
    ]:
        raise CommandExecutionError(
            f"Invalid value '{digest}' for digest. Valid: sha1, sha224, sha256, "
            "sha384, sha512, sha512_224, sha512_256, sha3_224, sha3_256, sha3_384, "
            "sha3_512"
        )

    builder, key = x509util.build_csr(
        private_key=private_key, 
        private_key_passphrase=private_key_passphrase, 
        **kwargs
    )
    algorithm = None
    if x509util.get_key_type(key) not in [
        x509util.KEY_TYPE.ED25519,
        x509util.KEY_TYPE.ED448,
    ]:
        algorithm = x509util.get_hashing_algorithm(digest)
    
    csr = builder.sign(key, algorithm=algorithm)
    csr = x509util.load_csr(csr)
    csr_encoding = getattr(serialization.Encoding, "PEM")
    csr_bytes = csr.public_bytes(csr_encoding)
    csr = csr_bytes.decode()

    return csr

def _split_csr_kwargs(kwargs):
    valid_csr_args = [
        "C",
        "ST",
        "L",
        "STREET",
        "O",
        "OU",
        "CN",
        "MAIL",
        "SN",
        "GN",
        "UID",
        "basicConstraints",
        "keyUsage",
        "subjectKeyIdentifier",
        "authorityKeyIdentifier",
        "certificatePolicies",
        "policyConstraints",
        "nameConstraints",
    ]
    csr_args = {}
    extra_args = {}
    for k, v in kwargs.items():
        if k in valid_csr_args:
            csr_args[k] = v
        else:
            extra_args[k] = v
    return csr_args, extra_args


