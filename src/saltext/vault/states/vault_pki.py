import os
import logging
import copy
from datetime import datetime, timedelta
from cryptography import x509 as cx509

from salt.exceptions import CommandExecutionError, SaltInvocationError
from salt.state import STATE_INTERNAL_KEYWORDS as _STATE_INTERNAL_KEYWORDS
from salt.utils import context as saltcontext
from saltext.vault.modules import vault_pki

import salt.utils.x509 as x509util

log = logging.getLogger(__name__)

def certificate_managed(
    name,
    common_name,
    role_name,
    days_remaining=None,
    issuer='default',
    encoding="pem",
    append_certs=None,
    private_key=None,
    private_key_passphrase=None,
    mount_point="pki",
    days_valid=None,
    new=False,
    **kwargs,
):
    if days_valid is None:
        days_valid = 30

    if days_remaining is None:
        days_remaining = 7

    ret = {
        "name": name,
        "changes": {},
        "result": True,
        "comment": "The certificate is in the correct state",
    }

    current = current_encoding = None
    changes = {}
    verb = "create"
    file_args, cert_args = _split_file_kwargs(_filter_state_internal_kwargs(kwargs))
    append_certs = append_certs or []
    if not isinstance(append_certs, list):
        append_certs = [append_certs]

    try:
        # check file.managed changes early to avoid using unnecessary resources
        file_managed_test = _file_managed(name, test=True, replace=False, **file_args)
        if file_managed_test["result"] is False:
            ret["result"] = False
            ret[
                "comment"
            ] = "Problem while testing file.managed changes, see its output"
            _add_sub_state_run(ret, file_managed_test)
            return ret

        if "is not present and is not set for creation" in file_managed_test["comment"]:
            _add_sub_state_run(ret, file_managed_test)
            return ret

        real_name = os.path.realpath(name)
        replace = False

        if new:
            replace = True

        if __salt__["file.file_exists"](real_name):
            try:
                (
                    current,
                    current_encoding,
                    current_chain,
                    current_extra,
                ) = x509util.load_cert(
                    real_name, passphrase=None, get_encoding=True
                )
            except SaltInvocationError as err:
                if any(
                    (
                        "Could not deserialize binary data" in str(err),
                        "Could not load PEM-encoded" in str(err),
                    )
                ):
                    replace = True
                else:
                    raise
            else:
                if encoding != current_encoding:
                    changes["encoding"] = encoding

                cn = current.subject.get_attributes_for_oid(
                           x509util.NAME_ATTRS_OID['CN']
                        )[0].value.strip()
                if cn != common_name:
                    changes["common_name"] = True

                if (
                    current.not_valid_after
                    < datetime.utcnow()
                    + timedelta(days=days_remaining)
                ):
                    changes["expiration"] = True

                issuer_cert = vault_pki.read_issuer_certificate(issuer, mount_point=mount_point)
                ca = x509util.load_cert(issuer_cert)
                privKey = x509util.load_privkey(private_key, private_key_passphrase)

                changes.update(
                    _compare_cert(
                        current,
                        ca,
                        privKey
                    )
                )

        else:
            changes["created"] = name

        if replace:
            changes["replaced"] = name

        if (
            not changes
            and file_managed_test["result"]
            and not file_managed_test["changes"]
        ):
            _add_sub_state_run(ret, file_managed_test)
            return ret

        ret["changes"] = changes
        if current and changes:
            verb = "recreate"

        if __opts__["test"]:
            ret["result"] = None if changes else True
            ret["comment"] = (
                f"The certificate would have been {verb}d"
                if changes
                else ret["comment"]
            )
            _add_sub_state_run(ret, file_managed_test)
            return ret

        if changes:
            if not set(changes) - {
                "additional_certs",
            }:
                cert = __salt__["x509.encode_certificate"](
                        current, encoding=encoding, append_certs=append_certs
                    )
            else:
                cert = vault_pki.issue_certificate(
                    common_name=common_name,
                    role_name=role_name,
                    private_key=private_key,
                    private_key_passphrase=private_key_passphrase,
                    days_valid=days_valid,
                    issuer=issuer,
                    mount_point=mount_point,
                    **cert_args
                )

            ret["comment"] = f"The certificate has been {verb}d"

        if not changes or encoding in ["pem", "pkcs7_pem"]:
            replace = bool(encoding in ["pem", "pkcs7_pem"] and changes)
            contents = cert['certificate'] if replace else None
            file_managed_ret = _file_managed(
                name, contents=contents, replace=replace, **file_args
            )
            _add_sub_state_run(ret, file_managed_ret)
            if not _check_file_ret(file_managed_ret, ret, current):
                return ret

    except (CommandExecutionError, SaltInvocationError) as err:
        ret["result"] = False
        ret["comment"] = str(err)
        ret["changes"] = {}

    return ret

def _filter_state_internal_kwargs(kwargs):
    # check_cmd is a valid argument to file.managed
    ignore = set(_STATE_INTERNAL_KEYWORDS) - {"check_cmd"}
    return {k: v for k, v in kwargs.items() if k not in ignore}

def _split_file_kwargs(kwargs):
    valid_file_args = [
        "user",
        "group",
        "mode",
        "attrs",
        "makedirs",
        "dir_mode",
        "backup",
        "create",
        "follow_symlinks",
        "check_cmd",
        "tmp_dir",
        "tmp_ext",
        "selinux",
        "encoding",
        "encoding_errors",
        "win_owner",
        "win_perms",
        "win_deny_perms",
        "win_inheritance",
        "win_perms_reset",
    ]
    file_args = {"show_changes": False}
    extra_args = {}
    for k, v in kwargs.items():
        if k in valid_file_args:
            file_args[k] = v
        else:
            extra_args[k] = v
    return file_args, extra_args

def _add_sub_state_run(ret, sub):
    sub["low"] = {
        "name": ret["name"],
        "state": "file",
        "__id__": __low__["__id__"],
        "fun": "managed",
    }
    if "sub_state_run" not in ret:
        ret["sub_state_run"] = []
    ret["sub_state_run"].append(sub)

def _file_managed(name, test=None, **kwargs):
    if test not in [None, True]:
        raise SaltInvocationError("test param can only be None or True")
    # work around https://github.com/saltstack/salt/issues/62590
    opts = copy.deepcopy(__opts__)
    opts['test'] = test or __opts__["test"]

    file_managed = __states__["file.managed"]
    with saltcontext.func_globals_inject(
        file_managed, __opts__=opts):
        with saltcontext.func_globals_inject(
                    __salt__["file.manage_file"], __opts__=opts
                ):
            return file_managed(name, **kwargs)

def _check_file_ret(fret, ret, current):
    if fret["result"] is False:
        ret["result"] = False
        ret[
            "comment"
        ] = f"Could not {'create' if not current else 'update'} file, see file.managed output"
        ret["changes"] = {}
        return False
    return True

def _compare_cert(current, signing_cert : cx509.Certificate, private_key):
    changes = {}


    if signing_cert and not x509util.verify_signature(
        current, signing_cert.public_key()
    ):
        changes["signing_private_key"] = True

    # Check correctly if issuer is the same
    if _getattr_safe(signing_cert, "issuer") != current.issuer:
        changes["issuer_name"] = _getattr_safe(signing_cert, "issuer").rfc4514_string()

    if not x509util.is_pair(
        current.public_key(), private_key
    ):
        changes["private_key"] = True

    return changes

def _getattr_safe(obj, attr):
    try:
        return getattr(obj, attr)
    except AttributeError as err:
        # Since we cannot get the certificate object without signing,
        # we need to compare attributes marked as internal. At least
        # convert possible exceptions into some description.
        raise CommandExecutionError(
            f"Could not get attribute {attr} from {obj.__class__.__name__}. "
            "Did the internal API of cryptography change?"
        ) from err